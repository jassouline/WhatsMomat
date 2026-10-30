import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { server } from '../server.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function runVerificationSuite() {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  console.log(`[VERIFY] WhatsMomat v1.2 test server bound to ${baseUrl}`);

  try {
    // 0. Healthcheck Probe
    const healthRes = await fetch(`${baseUrl}/api/healthz`);
    assert.equal(healthRes.status, 200);
    const healthData = await healthRes.json();
    assert.equal(healthData.status, 'ok');
    assert.equal(healthData.version, '1.2.0');

    // 1. Verify Security Headers, CORS Allow-List & Session Cookie Creation
    const homeRes = await fetch(`${baseUrl}/`, {
      headers: { Origin: `http://localhost:${address.port}` },
    });
    assert.equal(homeRes.status, 200, 'Home page should return 200');
    const csp = homeRes.headers.get('content-security-policy') || '';
    assert.ok(csp.includes("script-src 'self' 'nonce-"), 'CSP must enforce per-request script nonce');
    assert.ok(csp.includes("style-src 'self'"), 'CSP must enforce strict style-src self');
    assert.ok(!csp.includes('unsafe-inline'), 'CSP must not allow unsafe-inline');
    assert.equal(homeRes.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(homeRes.headers.get('x-frame-options'), 'DENY');
    assert.equal(
      homeRes.headers.get('access-control-allow-origin'),
      `http://localhost:${address.port}`,
      'CORS allow-list must support localhost on active port without wildcard'
    );

    const rawSetCookie = homeRes.headers.get('set-cookie') || '';
    assert.ok(rawSetCookie.includes('__Secure-moma_sid='), 'Cookie must use __Secure- prefix');
    assert.ok(rawSetCookie.includes('HttpOnly'), 'Cookie must be HttpOnly');
    assert.ok(rawSetCookie.includes('SameSite=Strict'), 'Cookie must be SameSite=Strict');
    const sessionCookie = rawSetCookie.split(';')[0];

    // 2. Verify HTTP Method Allow-List (Reject DELETE / PUT with 405)
    const deleteRes = await fetch(`${baseUrl}/api/golinks`, {
      method: 'DELETE',
      headers: { Cookie: sessionCookie },
    });
    assert.equal(deleteRes.status, 405, 'Disallowed HTTP method DELETE must return 405');

    // 3. Fetch Session & CSRF Token
    const sessRes = await fetch(`${baseUrl}/api/session`, {
      headers: { Cookie: sessionCookie },
    });
    assert.equal(sessRes.status, 200);
    const sessData = await sessRes.json();
    assert.ok(sessData.csrfToken, 'Session must provide a Synchronizer CSRF token');
    assert.equal(sessData.currentUser.ldap, 'jassouline');
    assert.equal(sessData.authMode, 'demo');

    // 4. Verify CSRF Protection blocks POST without X-CSRF-Token
    const csrfFailRes = await fetch(`${baseUrl}/api/golinks`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        slug: 'unauth-test',
        targetUrl: 'https://corp.internal/test',
        title: 'Test Title',
        description: 'Test Description',
      }),
    });
    assert.equal(csrfFailRes.status, 403, 'POST without X-CSRF-Token must be blocked with 403');

    // 5. Verify Federated Search (FTS5 BM25), Moma OneBox & Connector Toggling
    const searchSapRes = await fetch(
      `${baseUrl}/api/search?q=${encodeURIComponent('commande sap achat')}`,
      { headers: { Cookie: sessionCookie } }
    );
    const searchSapData = await searchSapRes.json();
    assert.ok(searchSapData.oneBoxCards.length >= 1, 'Search for SAP must trigger SAP Live OneBox card');
    assert.equal(searchSapData.oneBoxCards[0].connectorKey, 'sap-erp');

    // Verify disabling a connector removes its documents and OneBox cards from search
    const toggleSapRes = await fetch(`${baseUrl}/api/connectors/toggle`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': sessData.csrfToken,
      },
      body: JSON.stringify({ connectorKey: 'sap-erp' }),
    });
    assert.equal(toggleSapRes.status, 200);
    const toggleSapData = await toggleSapRes.json();
    assert.equal(toggleSapData.connector.enabled, false, 'SAP connector should now be disabled');

    const searchSapDisabledRes = await fetch(
      `${baseUrl}/api/search?q=${encodeURIComponent('commande sap achat')}`,
      { headers: { Cookie: sessionCookie } }
    );
    const searchSapDisabledData = await searchSapDisabledRes.json();
    assert.equal(searchSapDisabledData.oneBoxCards.length, 0, 'Disabled connector must not trigger OneBox');
    assert.ok(searchSapDisabledData.disabledConnectorSkippedCount >= 1, 'Disabled connector docs must be skipped');

    // Re-enable SAP connector
    await fetch(`${baseUrl}/api/connectors/toggle`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': sessData.csrfToken,
      },
      body: JSON.stringify({ connectorKey: 'sap-erp' }),
    });

    // 6. Verify Registering a Custom Client Tool ("Intégrer ses propres outils")
    const registerCustomRes = await fetch(`${baseUrl}/api/connectors/custom`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': sessData.csrfToken,
      },
      body: JSON.stringify({
        name: 'Salesforce CRM Client',
        connectorKey: 'salesforce',
        vendor: 'Salesforce',
        protocol: 'REST API + Webhook + OAuth 2.0',
        baseUrl: 'https://salesforce.corp.internal',
        oneboxTrigger: 'salesforce, crm, opportunité',
        visibilityDept: 'ALL',
        oneboxMetricLabel: 'Pipeline Q4',
        oneboxMetricValue: '18.4 M€ • 42 comptes actifs',
        sampleTitle: 'Procédure Opportunités & Devis Salesforce CRM',
        sampleContent: 'Toutes les opportunités commerciales sont synchronisées depuis Salesforce CRM sur go/salesforce.',
      }),
    });
    assert.equal(registerCustomRes.status, 200, 'Custom tool registration must succeed');

    const searchCustomRes = await fetch(
      `${baseUrl}/api/search?q=${encodeURIComponent('salesforce opportunité')}`,
      { headers: { Cookie: sessionCookie } }
    );
    const searchCustomData = await searchCustomRes.json();
    assert.ok(
      searchCustomData.oneBoxCards.some((ob) => ob.connectorKey === 'salesforce'),
      'Newly integrated custom tool must immediately trigger a Moma OneBox card'
    );
    assert.ok(
      searchCustomData.documents.some((d) => d.connectorKey === 'salesforce'),
      'Newly integrated custom tool document must appear in FTS5 federated search'
    );
    assert.ok(
      searchCustomData.goLinks.some((g) => g.slug === 'salesforce'),
      'Newly integrated custom tool must auto-register go/salesforce'
    );

    // 6b. Verify External Push Ingestion API (/api/v1/ingest) via M2M Bearer Token
    const ephemeralIngestToken = crypto.randomBytes(24).toString('hex');
    process.env.INGEST_API_TOKEN = ephemeralIngestToken;

    const badIngestRes = await fetch(`${baseUrl}/api/v1/ingest`, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer invalid-token-attempt',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ connectorKey: 'salesforce', documents: [] }),
    });
    assert.equal(badIngestRes.status, 403, 'Invalid Bearer token on /api/v1/ingest must fail closed with 403');

    const validIngestRes = await fetch(`${baseUrl}/api/v1/ingest`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${ephemeralIngestToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        connectorKey: 'salesforce',
        documents: [
          {
            docCode: 'SF-DEAL-2026',
            title: 'Contrat Cadre Renouvellement Cloud Enterprise Globex',
            content: 'Opportunité stratégique Globex validée dans Salesforce CRM avec SLA Platinum.',
            tags: ['globex', 'salesforce', 'contrat'],
            visibilityDept: 'ALL',
          },
        ],
        tickets: [
          {
            ticketKey: 'CRM-901',
            title: 'Synchronisation OAuth2 Salesforce <-> WhatsMomat',
            status: 'Actif',
            priority: 'P2 - Normale',
            summary: 'Webhook temps réel opérationnel.',
          },
        ],
      }),
    });
    assert.equal(validIngestRes.status, 200, 'Authenticated M2M ingestion must return 200');
    const validIngestData = await validIngestRes.json();
    assert.equal(validIngestData.ingested.upsertedDocs, 1);
    assert.equal(validIngestData.ingested.upsertedTickets, 1);

    const searchIngestedRes = await fetch(
      `${baseUrl}/api/search?q=${encodeURIComponent('Globex Platinum')}`,
      { headers: { Cookie: sessionCookie } }
    );
    const searchIngestedData = await searchIngestedRes.json();
    assert.ok(
      searchIngestedData.documents.some((d) => d.docCode === 'SF-DEAL-2026'),
      'Externally ingested document must be immediately indexed in FTS5 and searchable'
    );
    delete process.env.INGEST_API_TOKEN;

    // 7. Verify Seeded go/menu & go/jira + Real 302 Redirect Mode on /go/:slug
    const goMenuJsonRes = await fetch(`${baseUrl}/go/menu?format=json`, {
      headers: { Cookie: sessionCookie },
    });
    assert.equal(goMenuJsonRes.status, 200, 'go/menu alias must exist');
    const goJiraJsonRes = await fetch(`${baseUrl}/go/jira?format=json`, {
      headers: { Cookie: sessionCookie },
    });
    assert.equal(goJiraJsonRes.status, 200, 'go/jira alias must exist');

    // Create a go/link targeting a real external URL and verify native HTTP 302 Location header
    const createExtGoRes = await fetch(`${baseUrl}/api/golinks`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': sessData.csrfToken,
      },
      body: JSON.stringify({
        slug: 'ext-docs',
        targetUrl: 'https://ai.google.dev/gemini-api/docs',
        title: 'Documentation Officielle Gemini API',
        category: 'Engineering & SRE',
        description: 'Portail développeur externe pour vérifier la redirection HTTP 302 native.',
      }),
    });
    assert.equal(createExtGoRes.status, 200);

    const realRedirectRes = await fetch(`${baseUrl}/go/ext-docs`, {
      headers: { Cookie: sessionCookie },
      redirect: 'manual',
    });
    assert.equal(realRedirectRes.status, 302);
    assert.equal(
      realRedirectRes.headers.get('location'),
      'https://ai.google.dev/gemini-api/docs',
      'Non-.corp.internal go/link must perform a native HTTP 302 external redirect'
    );

    // 8. Verify ACL Trimming on Restricted Documents
    const searchEngRes = await fetch(
      `${baseUrl}/api/search?q=${encodeURIComponent('confidentiel secops kms')}`,
      { headers: { Cookie: sessionCookie } }
    );
    const searchEngData = await searchEngRes.json();
    assert.equal(searchEngData.documents.length, 0, 'Engineering user must not see SecOps restricted doc');
    assert.ok(searchEngData.aclTrimmedCount >= 1, 'ACL Trimming count must reflect filtered restricted doc');

    // Switch persona to sophiel (Security Admin, role: security_admin)
    const switchRes = await fetch(`${baseUrl}/api/auth/switch-persona`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': sessData.csrfToken,
      },
      body: JSON.stringify({ ldap: 'sophiel' }),
    });
    assert.equal(switchRes.status, 200);

    const searchSecRes = await fetch(
      `${baseUrl}/api/search?q=${encodeURIComponent('confidentiel secops kms')}`,
      { headers: { Cookie: sessionCookie } }
    );
    const searchSecData = await searchSecRes.json();
    assert.equal(searchSecData.documents.length, 1, 'Security Admin must see SecOps restricted doc');
    assert.equal(searchSecData.documents[0].docCode, 'DOC-SEC-001');

    // 9. Verify Teams Org Chart, Default PII Masking, Explicit PII Reveal & Enriched Profile
    const orgMaskedRes = await fetch(`${baseUrl}/api/people/jassouline`, {
      headers: { Cookie: sessionCookie },
    });
    const orgMasked = await orgMaskedRes.json();
    assert.equal(orgMasked.profile.piiMasked, true, 'PII must be masked by default');
    assert.ok(orgMasked.profile.email.includes('***'), 'Email must be masked by default');
    assert.ok(orgMasked.profile.phone.startsWith('***-***-'), 'Phone must be masked by default');
    assert.ok(orgMasked.profile.deskLocation.includes('Desk 4B-14'), 'Enriched profile must include deskLocation');
    assert.equal(orgMasked.profile.presenceStatus, 'available', 'Enriched profile must include presenceStatus');
    assert.ok(Array.isArray(orgMasked.profile.groups) && orgMasked.profile.groups.length >= 2, 'Enriched profile must include IAM groups');
    assert.equal(orgMasked.managementChain[0].ldap, 'clairem');
    assert.equal(orgMasked.directReports.length, 3);

    // Reveal PII explicitly (triggers PII_REVEAL audit log)
    const orgRevealedRes = await fetch(`${baseUrl}/api/people/jassouline?revealPii=1`, {
      headers: { Cookie: sessionCookie },
    });
    const orgRevealed = await orgRevealedRes.json();
    assert.equal(orgRevealed.profile.piiMasked, false);
    assert.equal(orgRevealed.profile.email, 'jordan.assouline@corp.internal');

    // 10. Verify Predictive Omnibox Typeahead & Operator Parsing
    const typeaheadRes = await fetch(`${baseUrl}/api/typeahead?q=vpn`, {
      headers: { Cookie: sessionCookie },
    });
    assert.equal(typeaheadRes.status, 200);
    const typeaheadData = await typeaheadRes.json();
    assert.ok(typeaheadData.suggestions.some((s) => s.kind === 'golink' && s.slug === 'vpn'), 'Typeahead must suggest go/vpn');
    assert.ok(Array.isArray(typeaheadData.operatorHints) && typeaheadData.operatorHints.length >= 3, 'Typeahead must return operatorHints');

    const opOwnerRes = await fetch(
      `${baseUrl}/api/search?q=${encodeURIComponent('owner:sophiel')}`,
      { headers: { Cookie: sessionCookie } }
    );
    const opOwnerData = await opOwnerRes.json();
    assert.equal(opOwnerData.operators.owner, 'sophiel', 'Operator parser must extract owner:sophiel');
    assert.ok(
      opOwnerData.documents.every((d) => d.ownerLdap === 'sophiel'),
      'owner:sophiel operator must filter documents by owner'
    );

    // 11. Verify Whatis Acronym Decoder, Category Filter & Glossary Creation
    const whatisSearchRes = await fetch(
      `${baseUrl}/api/search?q=${encodeURIComponent('whatis:GRAD')}`,
      { headers: { Cookie: sessionCookie } }
    );
    const whatisSearchData = await whatisSearchRes.json();
    assert.ok(
      whatisSearchData.oneBoxCards.some((ob) => ob.oneboxKey === 'whatis-grad'),
      'Searching whatis:GRAD must trigger a Whatis Acronym OneBox card'
    );

    const createWhatisRes = await fetch(`${baseUrl}/api/whatis`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': sessData.csrfToken,
      },
      body: JSON.stringify({
        acronym: 'PRA',
        fullExpansion: 'Plan de Reprise d’Activité Critique',
        category: 'Engineering & SRE',
        goLink: 'go/oncall',
        definition: 'Procédure de bascule multi-région en cas de perte d’un datacenter primaire.',
      }),
    });
    assert.equal(createWhatisRes.status, 200, 'Creating a new acronym in go/whatis must succeed');

    const whatisCatRes = await fetch(
      `${baseUrl}/api/whatis?category=${encodeURIComponent('Engineering & SRE')}`,
      { headers: { Cookie: sessionCookie } }
    );
    const whatisCatData = await whatisCatRes.json();
    assert.ok(whatisCatData.acronyms.length >= 1, 'Category filter on /api/whatis must return matching acronyms');
    assert.ok(
      whatisCatData.acronyms.every((a) => a.category === 'Engineering & SRE'),
      'Category filter on /api/whatis must strictly filter out other categories'
    );

    // 12. Verify Personalized "My Moma" Widgets & Approval BOLA Authorization Enforcement
    const dashRes = await fetch(`${baseUrl}/api/dashboard`, {
      headers: { Cookie: sessionCookie },
    });
    const dashData = await dashRes.json();
    assert.ok(
      dashData.approvals.every((ap) => ap.approver_ldap === 'sophiel' || ap.requester_ldap === 'sophiel'),
      'Sophiel (non-admin) must only see approvals where she is approver or requester'
    );
    assert.ok(
      dashData.meetings.every((m) => m.ownerLdap === 'sophiel' || m.attendees.includes('sophiel')),
      'Sophiel must only see meetings she owns or attends'
    );
    assert.ok(dashData.campusMenu && dashData.campusMenu.campus.includes('Zurich'), 'Sophiel (Zurich office) must see Zurich campus cafeteria menu');

    // BOLA check: sophiel MUST NOT be allowed to approve PO-2026-8904 (assigned to jassouline)
    const bolaDeniedRes = await fetch(`${baseUrl}/api/approvals/act`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': sessData.csrfToken,
      },
      body: JSON.stringify({
        approvalKey: 'PO-2026-8904',
        decision: 'APPROVED',
      }),
    });
    assert.equal(bolaDeniedRes.status, 403, 'Approving another user’s approval request must fail with 403 BOLA protection');

    // Authorized check: sophiel CAN approve IAM-SEC-309 (assigned to sophiel)
    const approveRes = await fetch(`${baseUrl}/api/approvals/act`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': sessData.csrfToken,
      },
      body: JSON.stringify({
        approvalKey: 'IAM-SEC-309',
        decision: 'APPROVED',
      }),
    });
    assert.equal(approveRes.status, 200);
    const approveData = await approveRes.json();
    assert.equal(approveData.approval.status, 'APPROVED', 'Authorized 1-click approval must update status to APPROVED');

    const ticketCreateRes = await fetch(`${baseUrl}/api/tickets/create`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': sessData.csrfToken,
      },
      body: JSON.stringify({
        connectorKey: 'servicenow',
        title: 'Demande clé YubiKey de secours',
        priority: 'P2',
        summary: 'Besoin d’une seconde clé FIDO2 avant déplacement.',
      }),
    });
    assert.equal(ticketCreateRes.status, 200);
    const ticketCreateData = await ticketCreateRes.json();
    assert.ok(ticketCreateData.ticket.ticket_key.startsWith('IT-'), 'Quick ticket creation must generate an IT-* ticket');

    // 13. Verify Security Audit Logs Endpoint (Allowed for security_admin, Denied for standard employee)
    const auditAdminRes = await fetch(`${baseUrl}/api/audit-logs?limit=20`, {
      headers: { Cookie: sessionCookie },
    });
    assert.equal(auditAdminRes.status, 200, 'Security Admin must be able to read audit logs');
    const auditAdminData = await auditAdminRes.json();
    const auditActions = new Set(auditAdminData.auditLogs.map((l) => l.action));
    assert.ok(auditActions.has('PII_REVEAL'), 'Audit trail must record PII_REVEAL');
    assert.ok(auditActions.has('APPROVAL_DECISION'), 'Audit trail must record APPROVAL_DECISION');
    assert.ok(auditActions.has('CONNECTOR_INGEST'), 'Audit trail must record CONNECTOR_INGEST');

    // Switch to standard employee (thomasr) and verify /api/audit-logs returns 403
    await fetch(`${baseUrl}/api/auth/switch-persona`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': sessData.csrfToken,
      },
      body: JSON.stringify({ ldap: 'thomasr' }),
    });
    const auditDeniedRes = await fetch(`${baseUrl}/api/audit-logs`, {
      headers: { Cookie: sessionCookie },
    });
    assert.equal(auditDeniedRes.status, 403, 'Standard employee must be denied access to /api/audit-logs');

    // 14. Verify Multi-Turn Conversational "Ask Moma" Follow-Up API
    const chatRes = await fetch(`${baseUrl}/api/ai/chat`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': sessData.csrfToken,
      },
      body: JSON.stringify({
        question: 'Qui est le responsable de ce document ?',
        queryContext: 'vpn zero trust',
      }),
    });
    assert.equal(chatRes.status, 200);
    const chatData = await chatRes.json();
    assert.ok(chatData.reply && chatData.reply.answer.length > 10, 'Ask Moma multi-turn endpoint must return a grounded answer');

    // 15. Verify Production Zero-Trust IAP Mode (AUTH_MODE=iap)
    process.env.AUTH_MODE = 'iap';
    try {
      const unauthIapRes = await fetch(`${baseUrl}/api/search?q=vpn`);
      assert.equal(unauthIapRes.status, 401, 'Missing IAP identity header must fail closed with 401 in AUTH_MODE=iap');

      const hrIapRes = await fetch(
        `${baseUrl}/api/search?q=${encodeURIComponent('rémunération salaire grad')}`,
        {
          headers: {
            'X-Goog-Authenticated-User-Email': 'accounts.google.com:nadia.benali@corp.internal',
          },
        }
      );
      assert.equal(hrIapRes.status, 200);
      const hrIapData = await hrIapRes.json();
      assert.ok(
        hrIapData.documents.some((d) => d.docCode === 'DOC-HR-004'),
        'IAP header for nadia.benali@corp.internal must resolve @nadiab and grant HR ACL access'
      );

      const switchBlockedRes = await fetch(`${baseUrl}/api/auth/switch-persona`, {
        method: 'POST',
        headers: {
          Cookie: sessionCookie,
          'Content-Type': 'application/json',
          'X-CSRF-Token': sessData.csrfToken,
          'X-Goog-Authenticated-User-Email': 'accounts.google.com:nadia.benali@corp.internal',
        },
        body: JSON.stringify({ ldap: 'clairem' }),
      });
      assert.equal(switchBlockedRes.status, 403, 'Demo persona switcher must be locked with 403 in AUTH_MODE=iap');
    } finally {
      process.env.AUTH_MODE = 'demo';
    }

    // 16. Static Code Security & CSP Compliance Checks on public/app.js and public/index.html
    const frontendCode = fs.readFileSync(path.resolve(__dirname, '../public/app.js'), 'utf-8');
    const htmlCode = fs.readFileSync(path.resolve(__dirname, '../public/index.html'), 'utf-8');
    assert.ok(!frontendCode.includes('.innerHTML'), 'Frontend must not use .innerHTML');
    assert.ok(!frontendCode.includes('outerHTML'), 'Frontend must not use outerHTML');
    assert.ok(!frontendCode.includes('insertAdjacentHTML'), 'Frontend must not use insertAdjacentHTML');
    assert.ok(!frontendCode.includes('localStorage'), 'Frontend must not use localStorage');
    assert.ok(!frontendCode.includes('sessionStorage'), 'Frontend must not use sessionStorage');
    assert.ok(!frontendCode.includes('document.write'), 'Frontend must not use document.write');
    assert.ok(!/\b(alert|confirm|prompt)\s*\(/.test(frontendCode), 'Frontend must not use blocking alert/confirm/prompt dialogs');
    assert.ok(!/attrs:\s*\{[^}]*\bstyle\s*:/.test(frontendCode), 'Frontend attrs must not set inline style attribute (CSP style-src self)');
    assert.ok(!/\sstyle\s*=/.test(htmlCode), 'HTML must not contain inline style attributes (CSP style-src self)');

    // 17. Verify Persistent SQLite WAL Mode Across Process Restarts & DB_PATH Boundary Check
    const { spawnSync } = await import('node:child_process');
    const projectRoot = path.resolve(__dirname, '..');
    const testDbName = `verify-wal-${crypto.randomBytes(4).toString('hex')}.sqlite`;
    const testDbPath = path.join(projectRoot, 'data', testDbName);
    try {
      const p1 = spawnSync(
        process.execPath,
        [
          '--input-type=module',
          '-e',
          `import { initDatabase, createOrUpdateGoLink, ACTIVE_DB_PATH } from './src/db.js';
           initDatabase();
           createOrUpdateGoLink(
             { slug: 'persist-wal', targetUrl: 'https://docs.corp.internal/wal', title: 'WAL Check', description: 'Persisted across restarts', category: 'Engineering & SRE' },
             { ldap: 'jassouline', role: 'admin' }
           );
           if (!ACTIVE_DB_PATH.endsWith('${testDbName}')) process.exit(2);`,
        ],
        { cwd: projectRoot, env: { ...process.env, DB_PATH: testDbName }, encoding: 'utf8' }
      );
      assert.equal(p1.status, 0, `Process 1 persistent SQLite write must succeed: ${p1.stderr}`);
      assert.ok(fs.existsSync(testDbPath), 'Persistent SQLite file must exist inside ./data/');

      const p2 = spawnSync(
        process.execPath,
        [
          '--input-type=module',
          '-e',
          `import assert from 'node:assert/strict';
           import { initDatabase, resolveGoLink } from './src/db.js';
           initDatabase();
           const saved = resolveGoLink('persist-wal');
           assert.ok(saved && saved.target_url === 'https://docs.corp.internal/wal', 'Custom go/link must persist across process restarts');
           const menu = resolveGoLink('menu');
           const jira = resolveGoLink('jira');
           assert.ok(menu && jira, 'Supplemental go/menu and go/jira links must exist in persistent DB');`,
        ],
        { cwd: projectRoot, env: { ...process.env, DB_PATH: testDbName }, encoding: 'utf8' }
      );
      assert.equal(p2.status, 0, `Process 2 persistent SQLite read must succeed: ${p2.stderr}`);

      const pTraversal = spawnSync(
        process.execPath,
        ['--input-type=module', '-e', `import './src/db.js';`],
        { cwd: projectRoot, env: { ...process.env, DB_PATH: '../escape.sqlite' }, encoding: 'utf8' }
      );
      assert.notEqual(pTraversal.status, 0, 'DB_PATH attempting directory traversal outside ./data/ must fail closed');
    } finally {
      for (const suffix of ['', '-wal', '-shm']) {
        if (fs.existsSync(testDbPath + suffix)) {
          fs.unlinkSync(testDbPath + suffix);
        }
      }
    }

    // 18. Verify OpenSearch Browser Discovery (/opensearch.xml, /api/opensearch-suggest) & MV3 Extension
    const openSearchRes = await fetch(`${baseUrl}/opensearch.xml`);
    assert.equal(openSearchRes.status, 200);
    assert.ok(
      (openSearchRes.headers.get('content-type') || '').includes('application/opensearchdescription+xml'),
      'OpenSearch descriptor must serve application/opensearchdescription+xml'
    );
    const openSearchXml = await openSearchRes.text();
    assert.ok(openSearchXml.includes('<ShortName>WhatsMomat</ShortName>'));
    assert.ok(openSearchXml.includes('/?q={searchTerms}'));
    assert.ok(openSearchXml.includes('/api/opensearch-suggest?q={searchTerms}'));

    const osSuggestRes = await fetch(`${baseUrl}/api/opensearch-suggest?q=vpn`, {
      headers: { Cookie: sessionCookie },
    });
    assert.equal(osSuggestRes.status, 200);
    const osSuggestJson = await osSuggestRes.json();
    assert.ok(Array.isArray(osSuggestJson) && osSuggestJson.length === 4, 'OpenSearch suggest must return 4-tuple array');
    assert.equal(osSuggestJson[0], 'vpn');
    assert.ok(osSuggestJson[1].some((item) => item.includes('go/vpn')), 'OpenSearch suggest must include go/vpn');

    const extManifest = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, '../browser-extension/manifest.json'), 'utf-8')
    );
    assert.equal(extManifest.manifest_version, 3, 'Browser extension must use Manifest V3');
    assert.equal(extManifest.omnibox.keyword, 'moma', 'Browser extension must register moma omnibox keyword');

    // 19. Verify Hybrid Semantic Vector + BM25 RRF Search (Retrieves semantic match with zero exact title words)
    const semanticRes = await fetch(
      `${baseUrl}/api/search?q=${encodeURIComponent('fauteuil lombaire mal au dos')}`,
      { headers: { Cookie: sessionCookie } }
    );
    assert.equal(semanticRes.status, 200);
    const semanticData = await semanticRes.json();
    const matchedErgoDoc = semanticData.documents.find((d) => d.docCode === 'DOC-HR-001');
    assert.ok(
      matchedErgoDoc,
      'Hybrid Vector+BM25 RRF must retrieve DOC-HR-001 (Télétravail & Budget Équipement) via semantic concept similarity'
    );
    assert.ok(
      matchedErgoDoc.matchMode === 'semantic-vector' || matchedErgoDoc.matchMode === 'hybrid-rrf',
      'Matched semantic document must report semantic-vector or hybrid-rrf matchMode'
    );
    assert.ok(
      !semanticData.documents.some((d) => d.docCode === 'DOC-SEC-001'),
      'Hybrid Vector+BM25 RRF must still strictly enforce ACL Trimming against unauthorized SecOps docs'
    );

    // 20. Verify SCIM 2.0 User Provisioning & Immediate Active Session Revocation on Offboarding
    const scimToken = crypto.randomBytes(24).toString('hex');
    process.env.SCIM_API_TOKEN = scimToken;
    try {
      const scimUnauthRes = await fetch(`${baseUrl}/api/v1/scim/v2/Users`);
      assert.equal(scimUnauthRes.status, 401, 'SCIM endpoint without Bearer token must return 401');

      const scimCreateRes = await fetch(`${baseUrl}/api/v1/scim/v2/Users`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${scimToken}`,
          'Content-Type': 'application/scim+json',
        },
        body: JSON.stringify({
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
          externalId: 'amartin',
          userName: 'alice.martin@corp.internal',
          active: true,
          name: { formatted: 'Alice Martin' },
          title: 'Principal Cloud Architect',
          'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User': {
            department: 'Engineering',
            organization: 'Cloud Infrastructure',
          },
        }),
      });
      assert.equal(scimCreateRes.status, 201, 'SCIM user creation must return 201 Created');
      const scimCreated = await scimCreateRes.json();
      assert.equal(scimCreated.id, 'amartin');
      assert.equal(scimCreated.active, true);

      // Open a dedicated session cookie for @amartin
      const aliceInitRes = await fetch(`${baseUrl}/api/session`);
      const aliceCookie = (aliceInitRes.headers.get('set-cookie') || '').split(';')[0];
      const aliceSess = await aliceInitRes.json();

      const aliceSwitchRes = await fetch(`${baseUrl}/api/auth/switch-persona`, {
        method: 'POST',
        headers: {
          Cookie: aliceCookie,
          'Content-Type': 'application/json',
          'X-CSRF-Token': aliceSess.csrfToken,
        },
        body: JSON.stringify({ ldap: 'amartin' }),
      });
      assert.equal(aliceSwitchRes.status, 200, 'Switching demo session to SCIM-provisioned @amartin must succeed');

      const aliceDashBefore = await fetch(`${baseUrl}/api/dashboard`, {
        headers: { Cookie: aliceCookie },
      });
      assert.equal(aliceDashBefore.status, 200, 'Active SCIM user session must access /api/dashboard');

      // Offboard / deactivate @amartin via SCIM 2.0 (active: false)
      const scimDeactivateRes = await fetch(`${baseUrl}/api/v1/scim/v2/Users`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${scimToken}`,
          'Content-Type': 'application/scim+json',
        },
        body: JSON.stringify({
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
          externalId: 'amartin',
          userName: 'alice.martin@corp.internal',
          active: false,
          name: { formatted: 'Alice Martin' },
        }),
      });
      assert.equal(scimDeactivateRes.status, 200, 'SCIM user deactivation must return 200');

      const aliceDashAfter = await fetch(`${baseUrl}/api/dashboard`, {
        headers: { Cookie: aliceCookie },
      });
      assert.equal(
        aliceDashAfter.status,
        401,
        'Deactivating user via SCIM 2.0 must immediately revoke all active SQLite sessions (401)'
      );
    } finally {
      delete process.env.SCIM_API_TOKEN;
    }

    // 21. Verify SSRF-Hardened Live Outbound OneBox Federation & HMAC-Signed Approval Webhooks
    await fetch(`${baseUrl}/api/auth/switch-persona`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': sessData.csrfToken,
      },
      body: JSON.stringify({ ldap: 'jassouline' }),
    });

    for (const forbiddenUrl of [
      'http://169.254.169.254/latest/meta-data/',
      'http://10.0.0.8/internal-api',
      'http://192.168.1.10/admin',
      'file:///etc/passwd',
    ]) {
      const ssrfBlockedRes = await fetch(`${baseUrl}/api/connectors/endpoints`, {
        method: 'POST',
        headers: {
          Cookie: sessionCookie,
          'Content-Type': 'application/json',
          'X-CSRF-Token': sessData.csrfToken,
        },
        body: JSON.stringify({
          connectorKey: 'sap-erp',
          liveEndpointUrl: forbiddenUrl,
        }),
      });
      assert.equal(
        ssrfBlockedRes.status,
        400,
        `SSRF protection must block private/metadata URL ${forbiddenUrl} with 400`
      );
    }

    let capturedWebhook = null;
    const mockPartnerServer = http.createServer((req, res) => {
      const reqUrl = new URL(req.url || '/', 'http://127.0.0.1');
      if (req.method === 'GET' && reqUrl.pathname === '/live-onebox') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            badgeText: 'SAP Live Webhook OneBox',
            cardTitle: 'SAP S/4HANA — Taux Change & Clôture Temps Réel',
            cardSubtitle: 'Réponse HTTP sortante vérifiée',
            fields: [{ label: 'Statut Clôture', value: 'Ouvert • EUR/USD 1.092' }],
          })
        );
        return;
      }
      if (req.method === 'POST' && reqUrl.pathname === '/approval-hook') {
        const chunks = [];
        req.on('data', (c) => chunks.push(c));
        req.on('end', () => {
          capturedWebhook = {
            signature: req.headers['x-whatsmomat-signature'],
            event: req.headers['x-whatsmomat-event'],
            body: JSON.parse(Buffer.concat(chunks).toString('utf-8')),
          };
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ received: true }));
        });
        return;
      }
      res.writeHead(404).end();
    });

    await new Promise((resolve) => mockPartnerServer.listen(0, '127.0.0.1', resolve));
    const mockPort = mockPartnerServer.address().port;
    process.env.ALLOW_LOOPBACK_WEBHOOKS = '1';
    try {
      const cfgRes = await fetch(`${baseUrl}/api/connectors/endpoints`, {
        method: 'POST',
        headers: {
          Cookie: sessionCookie,
          'Content-Type': 'application/json',
          'X-CSRF-Token': sessData.csrfToken,
        },
        body: JSON.stringify({
          connectorKey: 'sap-erp',
          liveEndpointUrl: `http://127.0.0.1:${mockPort}/live-onebox`,
          approvalWebhookUrl: `http://127.0.0.1:${mockPort}/approval-hook`,
        }),
      });
      assert.equal(cfgRes.status, 200, 'Configuring loopback test endpoints in non-prod test mode must return 200');

      const liveSearchRes = await fetch(`${baseUrl}/api/search?q=sap`, {
        headers: { Cookie: sessionCookie },
      });
      assert.equal(liveSearchRes.status, 200);
      const liveSearchData = await liveSearchRes.json();
      assert.ok(
        liveSearchData.oneBoxCards.some((c) => c.cardTitle.includes('Taux Change & Clôture Temps Réel')),
        'Search must federate live outbound OneBox card from partner endpoint'
      );

      const sapApproveRes = await fetch(`${baseUrl}/api/approvals/act`, {
        method: 'POST',
        headers: {
          Cookie: sessionCookie,
          'Content-Type': 'application/json',
          'X-CSRF-Token': sessData.csrfToken,
        },
        body: JSON.stringify({
          approvalKey: 'PO-2026-8904',
          decision: 'APPROVED',
        }),
      });
      assert.equal(sapApproveRes.status, 200);
      const sapApproveData = await sapApproveRes.json();
      assert.ok(sapApproveData.webhookDelivery?.delivered, 'Approval must dispatch outbound webhook');
      assert.ok(capturedWebhook, 'Mock partner server must receive approval webhook POST');
      assert.equal(capturedWebhook.event, 'moma.approval.decided');
      assert.ok(
        String(capturedWebhook.signature || '').startsWith('sha256='),
        'Outbound approval webhook must carry HMAC-SHA256 X-WhatsMomat-Signature header'
      );
      assert.equal(capturedWebhook.body.approvalKey, 'PO-2026-8904');
    } finally {
      delete process.env.ALLOW_LOOPBACK_WEBHOOKS;
      mockPartnerServer.close();
    }

    // 22. Verify Moma Culture: Peer Kudos (go/kudos), Pinned go/links & ACL Full Document Reader + Freshness
    const selfKudoRes = await fetch(`${baseUrl}/api/kudos`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': sessData.csrfToken,
      },
      body: JSON.stringify({
        toLdap: 'jassouline',
        badgeType: 'Excellence Technique',
        message: 'Tentative auto-kudo interdite',
      }),
    });
    assert.equal(selfKudoRes.status, 400, 'Sending a Peer Kudo to oneself must fail with 400');

    const validKudoRes = await fetch(`${baseUrl}/api/kudos`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': sessData.csrfToken,
      },
      body: JSON.stringify({
        toLdap: 'sophiel',
        badgeType: 'Sécurité & Fiabilité',
        points: 100,
        message: 'Bravo pour le durcissement Zero-Trust BeyondCorp et anti-SSRF !',
      }),
    });
    assert.equal(validKudoRes.status, 201, 'Sending a Peer Kudo to a colleague must return 201');

    const sophieProfileRes = await fetch(`${baseUrl}/api/people/sophiel`, {
      headers: { Cookie: sessionCookie },
    });
    const sophieProfile = await sophieProfileRes.json();
    assert.ok(
      sophieProfile.kudosReceived.some((k) => k.message.includes('anti-SSRF')),
      'Recipient Teams profile must list received Peer Kudos'
    );

    const pinRes = await fetch(`${baseUrl}/api/pins/toggle`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': sessData.csrfToken,
      },
      body: JSON.stringify({ slug: 'vpn' }),
    });
    assert.equal(pinRes.status, 200);
    const pinData = await pinRes.json();
    assert.equal(pinData.pinned, true, 'Toggling unpinned go/vpn must pin it');

    // Switch to standard employee @thomasr and verify BOLA/ACL enforcement on GET /api/documents/:docCode
    await fetch(`${baseUrl}/api/auth/switch-persona`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': sessData.csrfToken,
      },
      body: JSON.stringify({ ldap: 'thomasr' }),
    });
    const secDocDenied = await fetch(`${baseUrl}/api/documents/DOC-SEC-001`, {
      headers: { Cookie: sessionCookie },
    });
    assert.equal(
      secDocDenied.status,
      403,
      'Full document reader must return 403 when non-SecOps employee requests DOC-SEC-001'
    );

    const engDocOk = await fetch(`${baseUrl}/api/documents/DOC-ENG-001`, {
      headers: { Cookie: sessionCookie },
    });
    assert.equal(engDocOk.status, 200, 'Engineering employee must read DOC-ENG-001');

    const flagRes = await fetch(`${baseUrl}/api/documents/flag-outdated`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': sessData.csrfToken,
      },
      body: JSON.stringify({
        docCode: 'DOC-ENG-001',
        reason: 'Nouvelle rotation PagerDuty Q4 à documenter',
      }),
    });
    assert.equal(flagRes.status, 200);
    const flagData = await flagRes.json();
    assert.equal(flagData.document.outdatedFlagged, true, 'Flagging document outdated must persist outdatedFlagged=true');

    console.log(
      '[VERIFY] ALL 22 SUITES PASSED (CORE MOMA, HYBRID VECTOR+BM25 RRF, OPENSEARCH+MV3, SCIM 2.0+REVOCATION, ANTI-SSRF LIVE ONEBOX+WEBHOOKS, KUDOS/PINS/FRESHNESS, IAP, BOLA, AUDIT & CSP)!'
    );
  } finally {
    server.close();
  }
}

runVerificationSuite().catch((err) => {
  console.error('[VERIFY FAILED]', err);
  process.exit(1);
});
