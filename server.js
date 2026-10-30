import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  ACTIVE_DB_PATH,
  initDatabase,
  getUserByLdap,
  getUserByIdentity,
  listAllUsers,
  getOrgChartForUser,
  listConnectors,
  toggleConnectorState,
  registerCustomToolConnector,
  ingestExternalData,
  listGoLinks,
  resolveGoLink,
  createOrUpdateGoLink,
  deleteGoLink,
  listAcronyms,
  createAcronym,
  actOnApproval,
  createQuickTicket,
  getOmniboxTypeahead,
  executeFederatedSearch,
  getDashboardWidgets,
  recordAuditLog,
  listAuditLogs,
} from './src/db.js';
import { generateMomaAiOverview, askMomaFollowUp } from './src/ai.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PUBLIC_DIR = path.resolve(__dirname, 'public');

// Initialize SQLite database (persistent WAL file or :memory: in test mode) and seed enterprise dataset
initDatabase();

/**
 * Multi-tiered secret resolution (Environment -> Local Secret File -> Cryptographic Random Ephemeral)
 * Never hardcodes secrets or static literal fallbacks.
 * TODO(security): In production on Google Cloud, fetch secrets directly from Cloud Secret Manager / KMS.
 */
function resolveSessionSecret() {
  if (process.env.SESSION_SECRET && process.env.SESSION_SECRET.trim().length >= 32) {
    return process.env.SESSION_SECRET.trim();
  }
  const secretFilePath = path.resolve(__dirname, '.session_secret');
  if (fs.existsSync(secretFilePath)) {
    const fileSecret = fs.readFileSync(secretFilePath, 'utf-8').trim();
    if (fileSecret.length >= 32) {
      return fileSecret;
    }
  }
  if (process.env.NODE_ENV === 'production') {
    throw new Error('SESSION_SECRET (>= 32 chars) is mandatory when NODE_ENV=production.');
  }
  console.warn('[SECURITY WARNING] Generating ephemeral session secret. Instance-isolated!');
  return crypto.randomBytes(32).toString('hex');
}

const SESSION_SECRET = resolveSessionSecret();
const SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutes finite session lifetime
const COOKIE_NAME = '__Secure-moma_sid';

// Server-side in-memory session store
const sessionStore = new Map();

// Rate limiter store
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 240;

function signSessionId(rawId) {
  const mac = crypto.createHmac('sha256', SESSION_SECRET).update(rawId).digest('hex');
  return `${rawId}.${mac}`;
}

function verifySignedSessionId(signedCookie) {
  if (typeof signedCookie !== 'string' || !signedCookie.includes('.')) {
    return null;
  }
  const [rawId, mac] = signedCookie.split('.');
  if (!rawId || !mac) return null;
  const expectedMac = crypto.createHmac('sha256', SESSION_SECRET).update(rawId).digest('hex');
  const a = Buffer.from(mac, 'hex');
  const b = Buffer.from(expectedMac, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return null;
  }
  return rawId;
}

function createSession(userLdap = 'jassouline') {
  const rawId = crypto.randomBytes(32).toString('hex');
  const csrfToken = crypto.randomBytes(24).toString('hex');
  const now = Date.now();
  const session = {
    id: rawId,
    userLdap,
    csrfToken,
    createdAt: now,
    expiresAt: now + SESSION_TTL_MS,
  };
  sessionStore.set(rawId, session);
  return session;
}

function invalidateUserSessions(userLdap) {
  for (const [sid, sess] of sessionStore.entries()) {
    if (sess.userLdap === userLdap) {
      sessionStore.delete(sid);
    }
  }
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader || typeof cookieHeader !== 'string') return cookies;
  const parts = cookieHeader.split(';');
  for (const part of parts) {
    const idx = part.indexOf('=');
    if (idx > 0) {
      const k = part.slice(0, idx).trim();
      const v = part.slice(idx + 1).trim();
      try {
        cookies[k] = decodeURIComponent(v);
      } catch {
        cookies[k] = v;
      }
    }
  }
  return cookies;
}

function formatSessionCookie(signedValue, maxAgeSeconds = 1800) {
  const isTls = process.env.NODE_ENV === 'production';
  const flags = [
    `${COOKIE_NAME}=${encodeURIComponent(signedValue)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (isTls) {
    flags.push('Secure');
  }
  return flags.join('; ');
}

function getOrCreateSession(req, res, defaultLdap = 'jassouline') {
  const cookies = parseCookies(req.headers.cookie);
  const signedSid = cookies[COOKIE_NAME];
  if (signedSid) {
    const rawId = verifySignedSessionId(signedSid);
    if (rawId && sessionStore.has(rawId)) {
      const sess = sessionStore.get(rawId);
      if (sess.expiresAt > Date.now()) {
        sess.expiresAt = Date.now() + SESSION_TTL_MS;
        return sess;
      }
      sessionStore.delete(rawId);
    }
  }
  const newSession = createSession(defaultLdap);
  res.setHeader('Set-Cookie', formatSessionCookie(signSessionId(newSession.id), 1800));
  return newSession;
}

function validateCsrfToken(req, session) {
  const headerToken = req.headers['x-csrf-token'];
  if (typeof headerToken !== 'string' || !session || !session.csrfToken) {
    return false;
  }
  const a = Buffer.from(headerToken, 'utf-8');
  const b = Buffer.from(session.csrfToken, 'utf-8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Constant-time verification of Machine-to-Machine Bearer token for /api/v1/ingest.
 * Fails closed when INGEST_API_TOKEN is not configured in environment.
 */
function verifyIngestBearerToken(req) {
  const configuredToken = String(process.env.INGEST_API_TOKEN || '').trim();
  if (configuredToken.length < 24) {
    return false;
  }
  const authHeader = String(req.headers.authorization || '').trim();
  if (!authHeader.toLowerCase().startsWith('bearer ')) {
    return false;
  }
  const providedToken = authHeader.slice(7).trim();
  if (!providedToken) {
    return false;
  }
  const digestA = crypto.createHash('sha256').update(providedToken, 'utf-8').digest();
  const digestB = crypto.createHash('sha256').update(configuredToken, 'utf-8').digest();
  return crypto.timingSafeEqual(digestA, digestB);
}

function checkRateLimit(req) {
  const clientIp = req.socket.remoteAddress || '127.0.0.1';
  const now = Date.now();
  const entry = rateLimitStore.get(clientIp);
  if (!entry || entry.resetAt <= now) {
    rateLimitStore.set(clientIp, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return true;
  }
  entry.count += 1;
  return entry.count <= RATE_LIMIT_MAX_REQUESTS;
}

function resolveAllowedOrigin(reqOrigin, port) {
  const allowList = new Set([
    `http://127.0.0.1:${port}`,
    `http://localhost:${port}`,
  ]);
  if (process.env.ALLOWED_ORIGINS) {
    for (const raw of process.env.ALLOWED_ORIGINS.split(',')) {
      const trimmed = raw.trim();
      if (trimmed && trimmed !== '*') {
        allowList.add(trimmed);
      }
    }
  }
  if (reqOrigin && allowList.has(reqOrigin)) {
    return reqOrigin;
  }
  return `http://127.0.0.1:${port}`;
}

function applySecurityHeaders(req, res, nonce, port) {
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join('; ');

  res.setHeader('Content-Security-Policy', csp);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Origin', resolveAllowedOrigin(req.headers.origin, port));
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token, Authorization');
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(body);
}

function readJsonBody(req, maxBytes = 32768) {
  return new Promise((resolve, reject) => {
    let totalBytes = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      totalBytes += chunk.length;
      if (totalBytes > maxBytes) {
        reject(new Error('Payload too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf-8');
        if (!raw.trim()) {
          resolve({});
          return;
        }
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error('Invalid JSON payload'));
      }
    });
    req.on('error', () => reject(new Error('Stream error')));
  });
}

const STATIC_ALLOWLIST = new Map([
  ['index.html', 'text/html; charset=utf-8'],
  ['styles.css', 'text/css; charset=utf-8'],
  ['app.js', 'application/javascript; charset=utf-8'],
]);

function serveStaticFile(res, requestedFile, nonce) {
  const safeBasename = path.basename(requestedFile);
  if (!STATIC_ALLOWLIST.has(safeBasename)) {
    sendJson(res, 404, { error: 'Ressource introuvable.' });
    return;
  }
  const resolvedPath = path.resolve(PUBLIC_DIR, safeBasename);
  if (!resolvedPath.startsWith(PUBLIC_DIR + path.sep)) {
    sendJson(res, 403, { error: 'Accès interdit.' });
    return;
  }
  if (!fs.existsSync(resolvedPath)) {
    sendJson(res, 404, { error: 'Fichier non trouvé.' });
    return;
  }

  const contentType = STATIC_ALLOWLIST.get(safeBasename);
  res.statusCode = 200;
  res.setHeader('Content-Type', contentType);

  if (safeBasename === 'index.html') {
    const html = fs.readFileSync(resolvedPath, 'utf-8').replaceAll('__CSP_NONCE__', nonce);
    res.end(html);
    return;
  }

  const content = fs.readFileSync(resolvedPath);
  res.end(content);
}

const PORT = Number(process.env.PORT) || 3000;
// Defaults strictly to loopback 127.0.0.1 (never 0.0.0.0 unless explicitly overridden inside an isolated container)
const HOST = process.env.HOST || '127.0.0.1';

export const server = http.createServer(async (req, res) => {
  const nonce = crypto.randomBytes(16).toString('base64');
  const activePort = server.address()?.port || PORT;
  applySecurityHeaders(req, res, nonce, activePort);

  // Strict HTTP method allow-list: only GET and POST are permitted
  if (req.method !== 'GET' && req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    sendJson(res, 405, { error: 'Méthode HTTP non autorisée. Seuls GET et POST sont permis.' });
    return;
  }

  if (!checkRateLimit(req)) {
    sendJson(res, 429, { error: 'Trop de requêtes. Veuillez patienter quelques secondes.' });
    return;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(req.url || '/', `http://127.0.0.1:${activePort}`);
  } catch {
    sendJson(res, 400, { error: 'Requête invalide.' });
    return;
  }

  const pathname = parsedUrl.pathname;
  const clientIp = req.socket.remoteAddress || '127.0.0.1';
  const authMode = String(process.env.AUTH_MODE || 'demo').trim().toLowerCase();

  // Lightweight container / load-balancer health probe
  if (req.method === 'GET' && pathname === '/api/healthz') {
    sendJson(res, 200, {
      status: 'ok',
      version: '1.1.0',
      authMode,
      dbMode: ACTIVE_DB_PATH === ':memory:' ? 'memory' : 'sqlite-wal',
    });
    return;
  }

  // External M2M Push Ingestion API (/api/v1/ingest) — supports Bearer INGEST_API_TOKEN or Admin Session + CSRF
  if (req.method === 'POST' && pathname === '/api/v1/ingest') {
    const isBearerAuth = verifyIngestBearerToken(req);
    let ingestActorLdap = 'api-connector';

    if (!isBearerAuth) {
      const session = getOrCreateSession(req, res);
      if (!validateCsrfToken(req, session)) {
        sendJson(res, 403, { error: 'Authentification Bearer INGEST_API_TOKEN ou jeton CSRF valide requis.' });
        return;
      }
      const sessionUser = getUserByLdap(session.userLdap, true);
      if (!sessionUser || sessionUser.role !== 'admin') {
        sendJson(res, 403, { error: 'Seul un administrateur ou un jeton connecteur peut pousser des données.' });
        return;
      }
      ingestActorLdap = sessionUser.ldap;
    }

    try {
      const body = await readJsonBody(req, 131072);
      const result = ingestExternalData(body, ingestActorLdap, clientIp);
      sendJson(res, 200, { ingested: result });
    } catch (err) {
      sendJson(res, 400, { error: err.message || 'Échec de l’ingestion des données externes.' });
    }
    return;
  }

  // Resolve enterprise user identity:
  // - In production IAP mode (`AUTH_MODE=iap`), read verified proxy identity header and fail closed if missing/unknown.
  // - In demo mode (`AUTH_MODE=demo`), use signed HttpOnly session persona.
  // TODO(security): Verify cryptographic JWT signature (`x-goog-iap-jwt-assertion`) against Google IAP public keys in production.
  let currentUser = null;
  let session = null;

  if (authMode === 'iap') {
    const iapIdentity =
      req.headers['x-goog-authenticated-user-email'] || req.headers['x-forwarded-user'] || '';
    currentUser = getUserByIdentity(String(iapIdentity), true);
    if (!currentUser && pathname.startsWith('/api/')) {
      sendJson(res, 401, {
        error: 'Authentification Zero-Trust IAP requise (en-tête X-Goog-Authenticated-User-Email manquant ou utilisateur non habilité).',
      });
      return;
    }
    session = getOrCreateSession(req, res, currentUser?.ldap || 'jassouline');
    if (currentUser) {
      session.userLdap = currentUser.ldap;
    }
  } else {
    session = getOrCreateSession(req, res);
    currentUser = getUserByLdap(session.userLdap, true) || getUserByLdap('jassouline', true);
  }

  // Enforce CSRF token validation on all cookie-authenticated state-changing (POST) requests
  if (req.method === 'POST') {
    if (!validateCsrfToken(req, session)) {
      sendJson(res, 403, { error: 'Jeton CSRF manquant ou invalide. Requête bloquée.' });
      return;
    }
  }

  try {
    // 1. Direct /go/:slug HTTP Resolver (Mimics http://go/<alias> inside Google)
    if (req.method === 'GET' && pathname.startsWith('/go/')) {
      const slug = pathname.slice(4);
      const resolved = resolveGoLink(slug);
      if (!resolved) {
        sendJson(res, 404, {
          error: `Le raccourci go/${slug} n'existe pas encore.`,
          suggestion: `Créez-le dans l'onglet go/links du portail WhatsMomat.`,
        });
        return;
      }
      if (parsedUrl.searchParams.get('format') === 'json') {
        sendJson(res, 200, { resolved });
        return;
      }

      let safeTargetUrl = null;
      try {
        const parsedTarget = new URL(resolved.target_url);
        if (parsedTarget.protocol === 'https:' || parsedTarget.protocol === 'http:') {
          safeTargetUrl = parsedTarget;
        }
      } catch {
        safeTargetUrl = null;
      }

      const isSimulatedCorpDomain =
        safeTargetUrl &&
        (safeTargetUrl.hostname.endsWith('.corp.internal') || safeTargetUrl.hostname.endsWith('.internal'));
      const shouldExternalRedirect =
        Boolean(safeTargetUrl) &&
        (process.env.GO_REDIRECT_MODE === '302' ||
          parsedUrl.searchParams.get('redirect') === '1' ||
          !isSimulatedCorpDomain);

      res.statusCode = 302;
      if (shouldExternalRedirect) {
        res.setHeader('Location', safeTargetUrl.toString());
      } else {
        res.setHeader('Location', `/?goResolved=${encodeURIComponent(resolved.slug)}`);
      }
      res.end();
      return;
    }

    // 2. Session & Auth Persona API
    if (req.method === 'GET' && pathname === '/api/session') {
      const personas = listAllUsers().map((u) => ({
        ldap: u.ldap,
        fullName: u.fullName,
        title: u.title,
        department: u.department,
        role: u.role,
        avatarColor: u.avatarColor,
      }));
      sendJson(res, 200, {
        csrfToken: session.csrfToken,
        currentUser,
        personas: authMode === 'iap' ? [] : personas,
        authMode,
        dbMode: ACTIVE_DB_PATH === ':memory:' ? 'memory' : 'sqlite-wal',
        geminiConfigured: Boolean(process.env.GEMINI_API_KEY),
      });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/auth/switch-persona') {
      if (authMode === 'iap') {
        sendJson(res, 403, {
          error: 'Le changement de persona de démonstration est désactivé lorsque AUTH_MODE=iap.',
        });
        return;
      }
      const body = await readJsonBody(req);
      const targetLdap = String(body.ldap || '').trim().toLowerCase();
      const targetUser = getUserByLdap(targetLdap, true);
      if (!targetUser) {
        sendJson(res, 404, { error: 'Profil collaborateur introuvable.' });
        return;
      }
      session.userLdap = targetUser.ldap;
      sendJson(res, 200, {
        message: `Session basculée sur @${targetUser.ldap} (${targetUser.department} / ${targetUser.role})`,
        currentUser: targetUser,
      });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/auth/logout') {
      sessionStore.delete(session.id);
      invalidateUserSessions(session.userLdap);
      res.setHeader('Set-Cookie', formatSessionCookie('', 0));
      sendJson(res, 200, { loggedOut: true });
      return;
    }

    // 3. Dashboard Widgets API
    if (req.method === 'GET' && pathname === '/api/dashboard') {
      const widgets = getDashboardWidgets(currentUser);
      sendJson(res, 200, {
        user: currentUser,
        ...widgets,
      });
      return;
    }

    // 4. Unified Federated Search + OneBox + AI Overview API
    if (req.method === 'GET' && pathname === '/api/search') {
      const q = parsedUrl.searchParams.get('q') || '';
      const facet = parsedUrl.searchParams.get('facet') || 'all';
      const results = executeFederatedSearch(q, currentUser, facet);
      const aiOverview = await generateMomaAiOverview(q, results, currentUser);
      sendJson(res, 200, {
        ...results,
        aiOverview,
      });
      return;
    }

    // 5. People Directory & Interactive Org Chart (Moma Teams) API
    if (req.method === 'GET' && pathname === '/api/people') {
      const q = parsedUrl.searchParams.get('q') || '';
      const dept = parsedUrl.searchParams.get('department') || '';
      const people = listAllUsers(q, dept);
      sendJson(res, 200, { people });
      return;
    }

    if (req.method === 'GET' && pathname.startsWith('/api/people/')) {
      const ldap = pathname.slice('/api/people/'.length);
      const revealPii = parsedUrl.searchParams.get('revealPii') === '1';
      const orgData = getOrgChartForUser(ldap, revealPii);
      if (!orgData) {
        sendJson(res, 404, { error: 'Collaborateur introuvable dans Moma Teams.' });
        return;
      }
      if (revealPii && currentUser) {
        recordAuditLog({
          actorLdap: currentUser.ldap,
          action: 'PII_REVEAL',
          targetType: 'person',
          targetKey: orgData.profile.ldap,
          metadata: { department: orgData.profile.department },
          clientIp,
        });
      }
      sendJson(res, 200, orgData);
      return;
    }

    // 6. Enterprise Connectors & Custom Client Tool Integration API
    if (req.method === 'GET' && pathname === '/api/connectors') {
      sendJson(res, 200, { connectors: listConnectors() });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/connectors/toggle') {
      const body = await readJsonBody(req);
      try {
        const updated = toggleConnectorState(body.connectorKey, currentUser);
        sendJson(res, 200, { connector: updated });
      } catch (err) {
        sendJson(res, 400, { error: err.message || 'Impossible de modifier ce connecteur.' });
      }
      return;
    }

    if (req.method === 'POST' && pathname === '/api/connectors/custom') {
      const body = await readJsonBody(req);
      try {
        const created = registerCustomToolConnector(body, currentUser);
        sendJson(res, 200, { connector: created });
      } catch (err) {
        sendJson(res, 400, { error: err.message || 'Impossible d’intégrer cet outil.' });
      }
      return;
    }

    // 7. go/links Registry & Creation API
    if (req.method === 'GET' && pathname === '/api/golinks') {
      const q = parsedUrl.searchParams.get('q') || '';
      const category = parsedUrl.searchParams.get('category') || '';
      const links = listGoLinks(q, category);
      sendJson(res, 200, { goLinks: links });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/golinks/resolve') {
      const body = await readJsonBody(req);
      const resolved = resolveGoLink(body.slug);
      if (!resolved) {
        sendJson(res, 404, { error: 'Raccourci go/ introuvable.' });
        return;
      }
      sendJson(res, 200, { resolved });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/golinks') {
      const body = await readJsonBody(req);
      try {
        const saved = createOrUpdateGoLink(body, currentUser);
        sendJson(res, 200, { goLink: saved });
      } catch (validationErr) {
        sendJson(res, 400, { error: validationErr.message || 'Données invalides.' });
      }
      return;
    }

    if (req.method === 'POST' && pathname === '/api/golinks/delete') {
      const body = await readJsonBody(req);
      try {
        const result = deleteGoLink(body.slug, currentUser);
        sendJson(res, 200, result);
      } catch (delErr) {
        sendJson(res, 403, { error: delErr.message || 'Suppression refusée.' });
      }
      return;
    }

    // 8. Predictive Instant Omnibox Typeahead API
    if (req.method === 'GET' && pathname === '/api/typeahead') {
      const q = parsedUrl.searchParams.get('q') || '';
      const payload = getOmniboxTypeahead(q, currentUser);
      sendJson(res, 200, payload);
      return;
    }

    // 9. Whatis Acronym Decoder & Collaborative Glossary API
    if (req.method === 'GET' && pathname === '/api/whatis') {
      const q = parsedUrl.searchParams.get('q') || '';
      const category = parsedUrl.searchParams.get('category') || '';
      const acronyms = listAcronyms(q, category);
      sendJson(res, 200, { acronyms });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/whatis') {
      const body = await readJsonBody(req);
      try {
        const created = createAcronym(body, currentUser);
        sendJson(res, 200, { acronym: created });
      } catch (err) {
        sendJson(res, 400, { error: err.message || 'Impossible d’enregistrer cet acronyme.' });
      }
      return;
    }

    // 10. Actionable Approvals Center & Direct Ticket Creation API
    if (req.method === 'POST' && pathname === '/api/approvals/act') {
      const body = await readJsonBody(req);
      try {
        const updated = actOnApproval(body.approvalKey, body.decision, currentUser);
        sendJson(res, 200, { approval: updated });
      } catch (err) {
        sendJson(res, err.statusCode || 400, { error: err.message || 'Action impossible sur cette demande.' });
      }
      return;
    }

    if (req.method === 'POST' && pathname === '/api/tickets/create') {
      const body = await readJsonBody(req);
      try {
        const created = createQuickTicket(body, currentUser);
        sendJson(res, 200, { ticket: created });
      } catch (err) {
        sendJson(res, 400, { error: err.message || 'Impossible de créer ce ticket IT.' });
      }
      return;
    }

    // 11. Multi-Turn Conversational "Ask Moma" Follow-Up API
    if (req.method === 'POST' && pathname === '/api/ai/chat') {
      const body = await readJsonBody(req);
      try {
        const queryContext = String(body.queryContext || '').trim();
        const searchResults = executeFederatedSearch(queryContext || body.question || '', currentUser, 'all');
        const reply = await askMomaFollowUp({
          question: body.question,
          previousInteractionId: body.previousInteractionId || null,
          queryContext,
          currentUser,
          searchResults,
        });
        sendJson(res, 200, { reply });
      } catch (err) {
        sendJson(res, 400, { error: err.message || 'Impossible de générer la réponse Ask Moma.' });
      }
      return;
    }

    // 12. Security Audit Logs API (Admin & SecOps only)
    if (req.method === 'GET' && pathname === '/api/audit-logs') {
      try {
        const limit = parsedUrl.searchParams.get('limit') || '50';
        const logs = listAuditLogs(currentUser, limit);
        sendJson(res, 200, { auditLogs: logs });
      } catch (err) {
        sendJson(res, err.statusCode || 403, { error: err.message || 'Accès interdit.' });
      }
      return;
    }

    // 13. Static Frontend Assets
    if (req.method === 'GET') {
      if (pathname === '/' || pathname === '/index.html') {
        serveStaticFile(res, 'index.html', nonce);
        return;
      }
      if (pathname === '/styles.css') {
        serveStaticFile(res, 'styles.css', nonce);
        return;
      }
      if (pathname === '/app.js') {
        serveStaticFile(res, 'app.js', nonce);
        return;
      }
    }

    sendJson(res, 404, { error: 'Route introuvable.' });
  } catch {
    sendJson(res, 500, { error: 'Une erreur interne est survenue sur le serveur WhatsMomat.' });
  }
});

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  server.listen(PORT, HOST, () => {
    console.log(
      `WhatsMomat v1.1 listening securely on http://${HOST}:${PORT} (DB: ${ACTIVE_DB_PATH === ':memory:' ? ':memory:' : path.basename(ACTIVE_DB_PATH)})`
    );
  });
}
