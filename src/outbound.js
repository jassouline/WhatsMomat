import crypto from 'node:crypto';
import dns from 'node:dns';
import net from 'node:net';

const CIRCUIT_BREAKER_TIMEOUT_MS = 1500;
const MAX_OUTBOUND_RESPONSE_BYTES = 16384;

const BLOCKED_HOSTNAMES = new Set([
  'metadata.google.internal',
  'metadata',
  'instance-data',
  '0.0.0.0',
  '[::]',
  '[::1]',
]);

/**
 * Checks whether an IPv4 or IPv6 literal belongs to private, loopback, link-local,
 * CGNAT, or cloud metadata address space (CWE-918 SSRF protection).
 */
export function isPrivateOrReservedIp(ipAddress, allowLoopbackForTest = false) {
  const cleanIp = String(ipAddress || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!cleanIp) return true;

  if (allowLoopbackForTest && cleanIp === '127.0.0.1') {
    return false;
  }

  // Handle IPv4-mapped IPv6 addresses (e.g. ::ffff:169.254.169.254)
  if (cleanIp.startsWith('::ffff:')) {
    return isPrivateOrReservedIp(cleanIp.slice(7), allowLoopbackForTest);
  }

  const version = net.isIP(cleanIp);
  if (version === 4) {
    const parts = cleanIp.split('.').map((n) => Number(n));
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
      return true;
    }
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true; // Cloud Metadata (169.254.169.254) & link-local
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a === 198 && (b === 18 || b === 19)) return true;
    if (a >= 224) return true; // Multicast & reserved
    return false;
  }

  if (version === 6) {
    if (cleanIp === '::' || cleanIp === '::1') return true;
    if (cleanIp.startsWith('fc') || cleanIp.startsWith('fd')) return true; // Unique local
    if (cleanIp.startsWith('fe8') || cleanIp.startsWith('fe9') || cleanIp.startsWith('fea') || cleanIp.startsWith('feb')) {
      return true; // Link-local fe80::/10
    }
    return false;
  }

  return true;
}

/**
 * Validates an outbound connector or webhook URL synchronously for structural safety
 * (used when saving a connector in the database).
 */
export function validateOutboundUrlSyntax(rawUrl) {
  const trimmed = String(rawUrl || '').trim();
  if (!trimmed) return null;

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error('URL sortante invalide.');
  }

  if (parsed.username || parsed.password) {
    throw new Error('Les identifiants intégrés dans une URL sortante sont interdits.');
  }

  const hostname = parsed.hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.has(hostname)) {
    throw new Error('Hôte interdit par la politique anti-SSRF (métadonnées cloud / adresse réservée).');
  }

  const allowLoopback =
    process.env.ALLOW_LOOPBACK_WEBHOOKS === '1' && process.env.NODE_ENV !== 'production';

  if (parsed.protocol !== 'https:') {
    if (!(allowLoopback && parsed.protocol === 'http:' && hostname === '127.0.0.1')) {
      throw new Error('Seul le protocole HTTPS est autorisé pour les endpoints sortants.');
    }
  }

  if (net.isIP(hostname.replace(/^\[|\]$/g, ''))) {
    if (isPrivateOrReservedIp(hostname, allowLoopback)) {
      throw new Error('Adresse IP interne, privée ou métadonnées cloud bloquée (protection SSRF).');
    }
  }

  return parsed.toString();
}

/**
 * Resolves DNS and verifies that all target IPs are public (or 127.0.0.1 in explicit test mode)
 * before making an outbound HTTP request.
 */
async function assertSafeOutboundTarget(rawUrl) {
  const normalizedUrl = validateOutboundUrlSyntax(rawUrl);
  if (!normalizedUrl) {
    throw new Error('Empty outbound URL');
  }
  const parsed = new URL(normalizedUrl);
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');

  // Simulated demo domains (*.corp.internal) are non-routable placeholders
  if (hostname.endsWith('.corp.internal') || hostname.endsWith('.internal')) {
    throw new Error('Simulated internal domain');
  }

  const allowLoopback =
    process.env.ALLOW_LOOPBACK_WEBHOOKS === '1' && process.env.NODE_ENV !== 'production';

  // Optional strict allow-list of outbound hostnames when configured in production
  if (process.env.OUTBOUND_ALLOWED_HOSTS) {
    const allowedHosts = new Set(
      process.env.OUTBOUND_ALLOWED_HOSTS.split(',')
        .map((h) => h.trim().toLowerCase())
        .filter(Boolean)
    );
    if (allowedHosts.size > 0 && !allowedHosts.has(hostname)) {
      throw new Error(`Hostname ${hostname} is not in OUTBOUND_ALLOWED_HOSTS.`);
    }
  }

  if (net.isIP(hostname)) {
    if (isPrivateOrReservedIp(hostname, allowLoopback)) {
      throw new Error('Blocked private/metadata IP');
    }
    return parsed;
  }

  const records = await dns.promises.lookup(hostname, { all: true });
  if (!records || records.length === 0) {
    throw new Error('Unresolvable hostname');
  }
  for (const rec of records) {
    if (isPrivateOrReservedIp(rec.address, allowLoopback)) {
      throw new Error('DNS resolved to a private or reserved IP (SSRF blocked)');
    }
  }
  return parsed;
}

async function readBoundedJson(response) {
  const reader = response.body?.getReader?.();
  if (!reader) {
    return response.json();
  }
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_OUTBOUND_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error('Outbound response exceeded 16 KB safety cap');
    }
    chunks.push(value);
  }
  const raw = Buffer.concat(chunks.map((u) => Buffer.from(u))).toString('utf-8');
  return JSON.parse(raw);
}

/**
 * Queries live outbound OneBox endpoints for connectors matching the user's query
 * within a strict 1.5s circuit breaker and SSRF guard.
 */
export async function fetchLiveOutboundOneBoxes(rawQuery, currentUser, candidateConnectors) {
  const cleanQuery = String(rawQuery || '').trim();
  if (!cleanQuery || !Array.isArray(candidateConnectors) || candidateConnectors.length === 0) {
    return [];
  }

  const qLower = cleanQuery.toLowerCase();
  const matching = candidateConnectors.filter((c) => {
    if (!c.enabled || !c.live_endpoint_url) return false;
    const triggers = String(c.onebox_trigger || '')
      .split(',')
      .map((t) => t.trim().toLowerCase())
      .filter(Boolean);
    return (
      qLower.includes(c.connector_key.toLowerCase()) ||
      triggers.some((trig) => qLower.includes(trig) || trig.includes(qLower))
    );
  });

  if (matching.length === 0) return [];

  const liveCards = await Promise.all(
    matching.slice(0, 2).map(async (conn) => {
      try {
        const target = await assertSafeOutboundTarget(conn.live_endpoint_url);
        target.searchParams.set('q', cleanQuery.slice(0, 120));
        target.searchParams.set('principal', currentUser?.ldap || 'anonymous');

        const res = await fetch(target.toString(), {
          method: 'GET',
          headers: {
            Accept: 'application/json',
            'X-WhatsMomat-Principal': String(currentUser?.ldap || ''),
          },
          redirect: 'error',
          signal: AbortSignal.timeout(CIRCUIT_BREAKER_TIMEOUT_MS),
        });
        if (!res.ok) return null;

        const data = await readBoundedJson(res);
        if (!data || typeof data !== 'object') return null;

        const safeFields = Array.isArray(data.fields)
          ? data.fields
              .slice(0, 6)
              .map((f) => ({
                label: String(f?.label || 'Indicateur').slice(0, 64),
                value: String(f?.value || '').slice(0, 160),
              }))
              .filter((f) => f.value)
          : [];
        if (safeFields.length === 0) return null;

        return {
          id: `live-${conn.connector_key}`,
          connectorKey: conn.connector_key,
          connectorName: conn.name,
          vendor: conn.vendor,
          cardTitle: String(data.cardTitle || data.title || `OneBox Live — ${conn.name}`).slice(0, 120),
          cardSubtitle: String(
            data.cardSubtitle || data.subtitle || `Réponse temps réel de ${conn.vendor} (<1.5s Circuit Breaker)`
          ).slice(0, 160),
          badgeText: String(data.badgeText || `${conn.vendor} Live API`).slice(0, 48),
          fields: safeFields,
          actionLabel: String(data.actionLabel || `Ouvrir go/${conn.connector_key}`).slice(0, 64),
          actionGoLink: String(data.actionGoLink || `go/${conn.connector_key}`).slice(0, 64),
          isLiveOutbound: true,
        };
      } catch {
        // Fail open on supplemental live widget: circuit breaker swallows slow/unreachable external tool
        return null;
      }
    })
  );

  return liveCards.filter(Boolean);
}

/**
 * Dispatches a signed HMAC-SHA256 webhook notification when an approval is decided in "My Moma".
 */
export async function dispatchApprovalActionWebhook(webhookUrl, approval, actorUser, signingSecret) {
  if (!webhookUrl) {
    return { configured: false, delivered: false };
  }
  try {
    const target = await assertSafeOutboundTarget(webhookUrl);
    const payload = JSON.stringify({
      event: 'moma.approval.decided',
      approvalKey: approval.approval_key,
      connectorKey: approval.connector_key,
      decision: approval.status,
      actorLdap: actorUser.ldap,
      requesterLdap: approval.requester_ldap,
      decidedAt: new Date().toISOString(),
    });
    if (!signingSecret) {
      throw new Error('Missing HMAC signing key for outbound webhook.');
    }
    const signature = crypto
      .createHmac('sha256', String(signingSecret))
      .update(payload)
      .digest('hex');

    const res = await fetch(target.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-WhatsMomat-Event': 'moma.approval.decided',
        'X-WhatsMomat-Signature': `sha256=${signature}`,
      },
      body: payload,
      redirect: 'error',
      signal: AbortSignal.timeout(CIRCUIT_BREAKER_TIMEOUT_MS),
    });

    return {
      configured: true,
      delivered: res.ok,
      statusCode: res.status,
    };
  } catch (err) {
    return {
      configured: true,
      delivered: false,
      reason: err.message || 'Outbound delivery failed',
    };
  }
}
