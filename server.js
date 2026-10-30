import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  ACTIVE_DB_PATH,
  initDatabase,
  createDbSession,
  getValidDbSession,
  updateDbSessionUser,
  deleteDbSession,
  deleteAllUserDbSessions,
  getUserByLdap,
  getUserByIdentity,
  listAllUsers,
  getOrgChartForUser,
  listScimUsers,
  provisionScimUser,
  listKudos,
  sendPeerKudo,
  listUserPinnedSlugs,
  toggleUserPin,
  getDocumentByCode,
  flagDocumentOutdated,
  getConnectorRaw,
  listConnectorsRawEnabled,
  listConnectors,
  toggleConnectorState,
  configureConnectorOutboundUrls,
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
import { generateTextEmbedding } from './src/embeddings.js';
import { fetchLiveOutboundOneBoxes, dispatchApprovalActionWebhook } from './src/outbound.js';

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

// Rate limiter store
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 320;

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

/**
 * Resolves a persistent SQLite session.
 * If a valid signed cookie was presented whose session has been revoked (e.g. logout or SCIM deactivation),
 * returns `{ session: null, revoked: true }` so API routes fail closed with 401.
 */
function resolveOrCreateSession(req, res, defaultLdap = 'jassouline', allowBootstrapIfRevoked = false) {
  const cookies = parseCookies(req.headers.cookie);
  const signedSid = cookies[COOKIE_NAME];
  if (signedSid) {
    const rawId = verifySignedSessionId(signedSid);
    if (rawId) {
      const existing = getValidDbSession(rawId, SESSION_TTL_MS);
      if (existing) {
        return { session: existing, revoked: false };
      }
      if (!allowBootstrapIfRevoked) {
        res.setHeader('Set-Cookie', formatSessionCookie('', 0));
        return { session: null, revoked: true };
      }
    }
  }
  const newSession = createDbSession(defaultLdap, SESSION_TTL_MS);
  res.setHeader('Set-Cookie', formatSessionCookie(signSessionId(newSession.id), 1800));
  return { session: newSession, revoked: false };
}

function getExistingSessionFromRequest(req) {
  const cookies = parseCookies(req.headers.cookie);
  const signedSid = cookies[COOKIE_NAME];
  if (!signedSid) return null;
  const rawId = verifySignedSessionId(signedSid);
  if (!rawId) return null;
  return getValidDbSession(rawId, SESSION_TTL_MS);
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
 * Constant-time verification of Machine-to-Machine Bearer tokens (Ingest & SCIM 2.0).
 * Fails closed when token is unconfigured or shorter than 24 characters.
 */
function verifyBearerSecret(req, configuredSecret) {
  const cleanSecret = String(configuredSecret || '').trim();
  if (cleanSecret.length < 24) {
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
  const digestB = crypto.createHash('sha256').update(cleanSecret, 'utf-8').digest();
  return crypto.timingSafeEqual(digestA, digestB);
}

function verifyIngestBearerToken(req) {
  return verifyBearerSecret(req, process.env.INGEST_API_TOKEN);
}

function verifyScimBearerToken(req) {
  return verifyBearerSecret(req, process.env.SCIM_API_TOKEN || process.env.INGEST_API_TOKEN);
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

function escapeXml(str) {
  return String(str || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
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

function sendJson(res, statusCode, payload, contentType = 'application/json; charset=utf-8') {
  const body = JSON.stringify(payload);
  res.statusCode = statusCode;
  res.setHeader('Content-Type', contentType);
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
      version: '1.2.0',
      authMode,
      dbMode: ACTIVE_DB_PATH === ':memory:' ? 'memory' : 'sqlite-wal',
    });
    return;
  }

  // OpenSearch Browser Descriptor (/opensearch.xml) — enables Chrome/Edge/Firefox Tab-to-Search ("moma <Tab>")
  if (req.method === 'GET' && pathname === '/opensearch.xml') {
    const safeOrigin = resolveAllowedOrigin(req.headers.origin, activePort);
    const xml = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/">',
      '  <ShortName>WhatsMomat</ShortName>',
      '  <Description>Recherche fédérée intranet WhatsMomat (Moma, OneBox, Teams, go/links, Whatis)</Description>',
      '  <InputEncoding>UTF-8</InputEncoding>',
      `  <Url type="text/html" method="get" template="${escapeXml(safeOrigin)}/?q={searchTerms}" />`,
      `  <Url type="application/x-suggestions+json" method="get" template="${escapeXml(safeOrigin)}/api/opensearch-suggest?q={searchTerms}" />`,
      '</OpenSearchDescription>',
    ].join('\n');
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/opensearchdescription+xml; charset=utf-8');
    res.end(xml);
    return;
  }

  // External M2M Push Ingestion API (/api/v1/ingest) — supports Bearer INGEST_API_TOKEN or Admin Session + CSRF
  if (req.method === 'POST' && pathname === '/api/v1/ingest') {
    const isBearerAuth = verifyIngestBearerToken(req);
    let ingestActorLdap = 'api-connector';

    if (!isBearerAuth) {
      const session = getExistingSessionFromRequest(req);
      if (!session || !validateCsrfToken(req, session)) {
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

  // SCIM 2.0 Directory Provisioning & Deactivation API (/api/v1/scim/v2/Users)
  if (pathname === '/api/v1/scim/v2/Users') {
    const isScimBearer = verifyScimBearerToken(req);
    let scimActorLdap = 'scim-idp';

    if (!isScimBearer) {
      const session = getExistingSessionFromRequest(req);
      if (!session) {
        sendJson(
          res,
          401,
          {
            schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
            detail: 'Authentification Bearer SCIM_API_TOKEN requise.',
            status: '401',
          },
          'application/scim+json; charset=utf-8'
        );
        return;
      }
      if (req.method === 'POST' && !validateCsrfToken(req, session)) {
        sendJson(res, 403, { error: 'Jeton Bearer SCIM_API_TOKEN ou CSRF valide requis.' });
        return;
      }
      const sessionUser = getUserByLdap(session.userLdap, true);
      if (!sessionUser || sessionUser.role !== 'admin') {
        sendJson(res, 403, { error: 'Accès SCIM 2.0 réservé au fournisseur d’identité (IdP) ou à un administrateur.' });
        return;
      }
      scimActorLdap = sessionUser.ldap;
    }

    if (req.method === 'GET') {
      sendJson(res, 200, listScimUsers(), 'application/scim+json; charset=utf-8');
      return;
    }
    if (req.method === 'POST') {
      try {
        const body = await readJsonBody(req, 65536);
        const { created, resource } = provisionScimUser(body, scimActorLdap, clientIp);
        sendJson(res, created ? 201 : 200, resource, 'application/scim+json; charset=utf-8');
      } catch (err) {
        sendJson(
          res,
          400,
          {
            schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
            detail: err.message || 'Requête SCIM 2.0 invalide.',
            status: '400',
          },
          'application/scim+json; charset=utf-8'
        );
      }
      return;
    }
  }

  // Resolve enterprise user identity:
  // - In production IAP mode (`AUTH_MODE=iap`), read verified proxy identity header and fail closed if missing/unknown.
  // - In demo mode (`AUTH_MODE=demo`), use signed HttpOnly SQLite-persisted session persona.
  // TODO(security): Verify cryptographic JWT signature (`x-goog-iap-jwt-assertion`) against Google IAP public keys in production.
  let currentUser = null;
  let session = null;
  const allowSessionBootstrap = pathname === '/api/session' || !pathname.startsWith('/api/');

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
    const resolvedSess = resolveOrCreateSession(req, res, currentUser?.ldap || 'jassouline', true);
    session = resolvedSess.session;
    if (currentUser && session && session.userLdap !== currentUser.ldap) {
      updateDbSessionUser(session.id, currentUser.ldap);
      session.userLdap = currentUser.ldap;
    }
  } else {
    const resolvedSess = resolveOrCreateSession(req, res, 'jassouline', allowSessionBootstrap);
    if (resolvedSess.revoked && pathname.startsWith('/api/')) {
      sendJson(res, 401, { error: 'Session expirée ou révoquée (déconnexion ou désactivation SCIM).' });
      return;
    }
    session = resolvedSess.session;
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
        sendJson(res, 404, { error: 'Profil collaborateur introuvable ou compte désactivé.' });
        return;
      }
      updateDbSessionUser(session.id, targetUser.ldap);
      session.userLdap = targetUser.ldap;
      sendJson(res, 200, {
        message: `Session basculée sur @${targetUser.ldap} (${targetUser.department} / ${targetUser.role})`,
        currentUser: targetUser,
      });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/auth/logout') {
      deleteDbSession(session.id);
      deleteAllUserDbSessions(session.userLdap);
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

    // 4. Unified Hybrid Federated Search (BM25 + Vector RRF) + Live Outbound OneBox + AI Overview API
    if (req.method === 'GET' && pathname === '/api/search') {
      const q = parsedUrl.searchParams.get('q') || '';
      const facet = parsedUrl.searchParams.get('facet') || 'all';
      const queryEmbeddingObj =
        process.env.GEMINI_API_KEY && q.trim().length >= 2 ? await generateTextEmbedding(q) : null;
      const results = executeFederatedSearch(q, currentUser, facet, queryEmbeddingObj);

      // Query SSRF-hardened live outbound OneBox endpoints in parallel with 1.5s circuit breaker
      const liveCards = await fetchLiveOutboundOneBoxes(q, currentUser, listConnectorsRawEnabled());
      if (liveCards.length > 0) {
        results.oneBoxCards = [...liveCards, ...results.oneBoxCards];
      }

      const aiOverview = await generateMomaAiOverview(q, results, currentUser);
      sendJson(res, 200, {
        ...results,
        aiOverview,
      });
      return;
    }

    // OpenSearch Address-Bar Autocomplete Suggestions API
    if (req.method === 'GET' && pathname === '/api/opensearch-suggest') {
      const q = parsedUrl.searchParams.get('q') || '';
      const safeOrigin = resolveAllowedOrigin(req.headers.origin, activePort);
      const { suggestions } = getOmniboxTypeahead(q, currentUser);
      const completions = suggestions.map((s) => s.queryValue || s.label || '');
      const descriptions = suggestions.map((s) => `${s.badge || s.kind} — ${s.sublabel || s.label || ''}`);
      const urls = suggestions.map((s) =>
        s.kind === 'golink'
          ? `${safeOrigin}/go/${encodeURIComponent(String(s.queryValue || '').replace(/^go\//, ''))}`
          : `${safeOrigin}/?q=${encodeURIComponent(s.queryValue || '')}`
      );
      sendJson(res, 200, [q, completions, descriptions, urls], 'application/x-suggestions+json; charset=utf-8');
      return;
    }

    // 5. People Directory, Org Chart & Peer Kudos (Moma Teams) API
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

    if (req.method === 'GET' && pathname === '/api/kudos') {
      const targetLdap = parsedUrl.searchParams.get('ldap') || '';
      const limit = parsedUrl.searchParams.get('limit') || '15';
      sendJson(res, 200, { kudos: listKudos(targetLdap, limit) });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/kudos') {
      const body = await readJsonBody(req);
      try {
        const kudo = sendPeerKudo(body, currentUser);
        sendJson(res, 201, { kudo });
      } catch (err) {
        sendJson(res, 400, { error: err.message || 'Impossible d’envoyer ce Peer Kudo.' });
      }
      return;
    }

    // 6. Full Document Reader & Freshness Flagging (ACL-enforced)
    if (req.method === 'GET' && pathname.startsWith('/api/documents/')) {
      const docCode = decodeURIComponent(pathname.slice('/api/documents/'.length));
      try {
        const doc = getDocumentByCode(docCode, currentUser);
        sendJson(res, 200, { document: doc });
      } catch (err) {
        sendJson(res, err.statusCode || 400, { error: err.message || 'Accès au document refusé.' });
      }
      return;
    }

    if (req.method === 'POST' && pathname === '/api/documents/flag-outdated') {
      const body = await readJsonBody(req);
      try {
        const updatedDoc = flagDocumentOutdated(body, currentUser);
        sendJson(res, 200, { document: updatedDoc });
      } catch (err) {
        sendJson(res, err.statusCode || 400, { error: err.message || 'Impossible de mettre à jour le statut du document.' });
      }
      return;
    }

    // 7. Enterprise Connectors, Outbound Federation & Custom Client Tool Integration API
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

    if (req.method === 'POST' && pathname === '/api/connectors/endpoints') {
      const body = await readJsonBody(req);
      try {
        const updated = configureConnectorOutboundUrls(body, currentUser);
        sendJson(res, 200, { connector: updated });
      } catch (err) {
        sendJson(res, err.statusCode || 400, { error: err.message || 'URL sortante refusée.' });
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

    // 8. go/links Registry, Creation & User Pins API
    if (req.method === 'GET' && pathname === '/api/golinks') {
      const q = parsedUrl.searchParams.get('q') || '';
      const category = parsedUrl.searchParams.get('category') || '';
      const pinnedSlugs = listUserPinnedSlugs(currentUser?.ldap);
      const pinnedSet = new Set(pinnedSlugs);
      const links = listGoLinks(q, category).map((g) => ({
        ...g,
        isPinned: pinnedSet.has(g.slug),
      }));
      sendJson(res, 200, { goLinks: links, pinnedSlugs });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/pins/toggle') {
      const body = await readJsonBody(req);
      try {
        const pinResult = toggleUserPin(body.slug, currentUser);
        sendJson(res, 200, pinResult);
      } catch (err) {
        sendJson(res, 400, { error: err.message || 'Impossible d’épingler ce raccourci.' });
      }
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

    // 9. Predictive Instant Omnibox Typeahead API
    if (req.method === 'GET' && pathname === '/api/typeahead') {
      const q = parsedUrl.searchParams.get('q') || '';
      const payload = getOmniboxTypeahead(q, currentUser);
      sendJson(res, 200, payload);
      return;
    }

    // 10. Whatis Acronym Decoder & Collaborative Glossary API
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

    // 11. Actionable Approvals Center (+ Signed Outbound Webhook) & Direct Ticket Creation API
    if (req.method === 'POST' && pathname === '/api/approvals/act') {
      const body = await readJsonBody(req);
      try {
        const updated = actOnApproval(body.approvalKey, body.decision, currentUser);
        const connector = getConnectorRaw(updated.connector_key);
        let webhookDelivery = { configured: false, delivered: false };
        if (connector?.approval_webhook_url) {
          webhookDelivery = await dispatchApprovalActionWebhook(
            connector.approval_webhook_url,
            updated,
            currentUser,
            SESSION_SECRET
          );
          recordAuditLog({
            actorLdap: currentUser.ldap,
            action: 'APPROVAL_WEBHOOK_DISPATCH',
            targetType: 'approval',
            targetKey: updated.approval_key,
            metadata: webhookDelivery,
            clientIp,
          });
        }
        sendJson(res, 200, { approval: updated, webhookDelivery });
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

    // 12. Multi-Turn Conversational "Ask Moma" Follow-Up API
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

    // 13. Security Audit Logs API (Admin & SecOps only)
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

    // 14. Static Frontend Assets
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
      `WhatsMomat v1.2 listening securely on http://${HOST}:${PORT} (DB: ${ACTIVE_DB_PATH === ':memory:' ? ':memory:' : path.basename(ACTIVE_DB_PATH)})`
    );
  });
}
