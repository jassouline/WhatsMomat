import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { server } from '../server.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function runVerificationSuite() {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  console.log(`[VERIFY] Moma-bis test server bound to ${baseUrl}`);

  try {
    // 1. Verify Security Headers & Session Cookie Creation
    const homeRes = await fetch(`${baseUrl}/`);
    assert.equal(homeRes.status, 200, 'Home page should return 200');
    const csp = homeRes.headers.get('content-security-policy') || '';
    assert.ok(csp.includes("script-src 'self' 'nonce-"), 'CSP must enforce per-request script nonce');
    assert.ok(!csp.includes('unsafe-inline'), 'CSP must not allow unsafe-inline');
    assert.equal(homeRes.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(homeRes.headers.get('x-frame-options'), 'DENY');

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

    // 5. Verify Federated Search, Moma OneBox & ACL Trimming
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

    // Search for the newly integrated custom tool -> verify OneBox, Document, and go/salesforce
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
      'Newly integrated custom tool document must appear in federated search'
    );
    assert.ok(
      searchCustomData.goLinks.some((g) => g.slug === 'salesforce'),
      'Newly integrated custom tool must auto-register go/salesforce'
    );

    // 7. Verify ACL Trimming on Restricted Documents
    const searchEngRes = await fetch(
      `${baseUrl}/api/search?q=${encodeURIComponent('confidentiel secops kms')}`,
      { headers: { Cookie: sessionCookie } }
    );
    const searchEngData = await searchEngRes.json();
    assert.equal(searchEngData.documents.length, 0, 'Engineering user must not see SecOps restricted doc');
    assert.ok(searchEngData.aclTrimmedCount >= 1, 'ACL Trimming count must reflect filtered restricted doc');

    // Switch persona to sophiel (Security Admin)
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

    // 8. Verify Teams Org Chart, Default PII Masking & Enriched Profile (Presence, Desk, Groups)
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

    // 9. Verify Phase 2: Predictive Omnibox Typeahead & Operator Parsing
    const typeaheadRes = await fetch(`${baseUrl}/api/typeahead?q=vpn`, {
      headers: { Cookie: sessionCookie },
    });
    assert.equal(typeaheadRes.status, 200);
    const typeaheadData = await typeaheadRes.json();
    assert.ok(typeaheadData.suggestions.some((s) => s.kind === 'golink' && s.slug === 'vpn'), 'Typeahead must suggest go/vpn');
    assert.ok(Array.isArray(typeaheadData.operatorHints) && typeaheadData.operatorHints.length >= 3, 'Typeahead must return operatorHints');

    // Verify search operator `owner:sophiel`
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

    // 10. Verify Phase 2: Whatis Acronym Decoder & Glossary
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

    // 11. Verify Phase 2: Personalized "My Moma" Widgets, 1-Click Approval Action & Quick Ticket Creation
    const dashRes = await fetch(`${baseUrl}/api/dashboard`, {
      headers: { Cookie: sessionCookie },
    });
    const dashData = await dashRes.json();
    assert.ok(Array.isArray(dashData.approvals) && dashData.approvals.length >= 1, 'Dashboard must include actionable approvals');
    assert.ok(Array.isArray(dashData.meetings) && dashData.meetings.length >= 1, 'Dashboard must include daily meetings');
    assert.ok(dashData.campusMenu && dashData.campusMenu.campus.includes('Zurich'), 'Sophiel (Zurich office) must see Zurich campus cafeteria menu');

    const approveRes = await fetch(`${baseUrl}/api/approvals/act`, {
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
    assert.equal(approveRes.status, 200);
    const approveData = await approveRes.json();
    assert.equal(approveData.approval.status, 'APPROVED', '1-click approval must update status to APPROVED');

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

    // 12. Verify Phase 2: Multi-Turn Conversational "Ask Moma" Follow-Up API
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

    // 13. Static code check on public/app.js for banned patterns
    const frontendCode = fs.readFileSync(path.resolve(__dirname, '../public/app.js'), 'utf-8');
    assert.ok(!frontendCode.includes('.innerHTML'), 'Frontend must not use .innerHTML');
    assert.ok(!frontendCode.includes('localStorage'), 'Frontend must not use localStorage');
    assert.ok(!frontendCode.includes('sessionStorage'), 'Frontend must not use sessionStorage');

    console.log('[VERIFY] ALL PHASE 1 & PHASE 2 FUNCTIONAL, ONEBOX, WHATIS, MY MOMA & SECURITY CHECKS PASSED!');
  } finally {
    server.close();
  }
}

runVerificationSuite().catch((err) => {
  console.error('[VERIFY FAILED]', err);
  process.exit(1);
});
