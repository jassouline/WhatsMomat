/**
 * Moma-bis Frontend Application (Secure Vanilla JS SPA)
 * Enforces strict DOM creation via document.createElement / textContent / replaceChildren.
 * Session state is managed via HttpOnly cookies and Synchronizer CSRF tokens in memory.
 */

const appState = {
  csrfToken: null,
  currentUser: null,
  personas: [],
  activeView: 'home',
  activeQuery: '',
  activeFacet: 'all',
  selectedPersonLdap: 'jassouline',
  lastSearchPayload: null,
  askMomaTurns: [],
  lastInteractionId: null,
};

/**
 * Safe DOM element builder using document.createElement and textContent.
 */
function el(tag, options = {}, children = []) {
  const node = document.createElement(tag);
  if (options.className) {
    node.className = options.className;
  }
  if (options.text !== undefined && options.text !== null) {
    node.textContent = String(options.text);
  }
  if (options.attrs) {
    for (const [k, v] of Object.entries(options.attrs)) {
      if (v !== undefined && v !== null) {
        node.setAttribute(k, String(v));
      }
    }
  }
  if (options.style) {
    for (const [prop, val] of Object.entries(options.style)) {
      node.style[prop] = val;
    }
  }
  if (options.onClick) {
    node.addEventListener('click', options.onClick);
  }
  for (const child of children) {
    if (child instanceof Node) {
      node.appendChild(child);
    } else if (typeof child === 'string') {
      node.appendChild(document.createTextNode(child));
    }
  }
  return node;
}

function initialsFromName(fullName) {
  return String(fullName || 'U')
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0].toUpperCase())
    .join('');
}

function createAvatar(person, large = false) {
  return el('span', {
    className: large ? 'avatar-circle avatar-lg' : 'avatar-circle',
    text: initialsFromName(person.fullName || person.ldap),
    style: { backgroundColor: person.avatarColor || '#1a73e8' },
  });
}

function createPresenceBadge(person) {
  const statusKey = person.presenceStatus || 'available';
  const label = person.presenceLabel || 'Disponible';
  return el('span', {
    className: `presence-pill presence-${statusKey}`,
    text: `● ${label}`,
  });
}

let toastTimer = null;
function showToast(message) {
  const toast = document.getElementById('momaToast');
  if (!toast) return;
  toast.textContent = String(message);
  toast.classList.remove('hidden');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.classList.add('hidden');
  }, 3800);
}

function openModal(titleText, bodyNodes) {
  const backdrop = document.getElementById('momaModalBackdrop');
  const titleEl = document.getElementById('modalTitle');
  const bodyEl = document.getElementById('modalBody');
  if (!backdrop || !titleEl || !bodyEl) return;

  titleEl.textContent = String(titleText);
  bodyEl.replaceChildren();
  if (Array.isArray(bodyNodes)) {
    for (const n of bodyNodes) {
      if (n instanceof Node) bodyEl.appendChild(n);
    }
  } else if (bodyNodes instanceof Node) {
    bodyEl.appendChild(bodyNodes);
  }
  backdrop.classList.remove('hidden');
}

function closeModal() {
  const backdrop = document.getElementById('momaModalBackdrop');
  if (backdrop) backdrop.classList.add('hidden');
}

async function apiFetch(url, options = {}) {
  const method = options.method || 'GET';
  const headers = {
    Accept: 'application/json',
  };
  if (method === 'POST') {
    headers['Content-Type'] = 'application/json';
    if (appState.csrfToken) {
      headers['X-CSRF-Token'] = appState.csrfToken;
    }
  }
  const response = await fetch(url, {
    method,
    headers,
    credentials: 'same-origin',
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || 'Erreur lors de la requête serveur.');
  }
  return data;
}

function switchView(viewName) {
  appState.activeView = viewName;
  hideOmniboxTypeahead();
  const views = {
    home: document.getElementById('viewHome'),
    connectors: document.getElementById('viewConnectors'),
    teams: document.getElementById('viewTeams'),
    golinks: document.getElementById('viewGolinks'),
    whatis: document.getElementById('viewWhatis'),
    blueprint: document.getElementById('viewBlueprint'),
  };
  for (const [key, section] of Object.entries(views)) {
    if (!section) continue;
    if (key === viewName) {
      section.classList.remove('hidden');
    } else {
      section.classList.add('hidden');
    }
  }

  const tabs = document.querySelectorAll('.nav-tab');
  tabs.forEach((btn) => {
    if (btn.getAttribute('data-view') === viewName) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });

  if (viewName === 'connectors') {
    loadConnectorsHub();
    renderConnectorPresets();
  } else if (viewName === 'teams') {
    loadPeopleDirectory();
    loadPersonOrgChart(appState.selectedPersonLdap, false);
  } else if (viewName === 'golinks') {
    loadGoLinksRegistry();
  } else if (viewName === 'whatis') {
    loadWhatisGlossary();
  } else if (viewName === 'blueprint') {
    renderBlueprintView();
  }
}

function renderHeaderUser() {
  const badge = document.getElementById('currentUserBadge');
  const select = document.getElementById('personaSelect');
  if (!badge || !select || !appState.currentUser) return;

  badge.replaceChildren(
    createAvatar(appState.currentUser, false),
    el('span', {
      text: `@${appState.currentUser.ldap} (${appState.currentUser.department})`,
    })
  );

  select.replaceChildren();
  for (const p of appState.personas) {
    const opt = el('option', {
      text: `${p.fullName} — ${p.department} (${p.role})`,
      attrs: { value: p.ldap },
    });
    if (p.ldap === appState.currentUser.ldap) {
      opt.selected = true;
    }
    select.appendChild(opt);
  }
}

function renderQuickQueryChips() {
  const container = document.getElementById('quickQueryChips');
  if (!container) return;
  const examples = [
    { label: 'whatis:GRAD (Décodeur Jargon)', query: 'whatis:GRAD' },
    { label: 'whatis:TGIF (Culture)', query: 'whatis:TGIF' },
    { label: 'owner:sophiel (Opérateur Owner)', query: 'owner:sophiel' },
    { label: 'source:servicenow (Opérateur Source)', query: 'source:servicenow laptop' },
    { label: 'OneBox Workday (Solde Congés)', query: 'congés rtt vacances workday' },
    { label: 'OneBox SAP Ariba (PO-8841)', query: 'commande sap achat po-8841' },
    { label: 'go/vpn (Zero-Trust)', query: 'go/vpn' },
    { label: 'SecOps Confidentiel (Test ACL)', query: 'confidentiel secops kms' },
  ];

  container.replaceChildren();
  for (const item of examples) {
    const chip = el('button', {
      className: 'chip-btn',
      text: item.label,
      attrs: { type: 'button' },
      onClick: () => {
        const input = document.getElementById('globalSearchInput');
        if (input) input.value = item.query;
        updateOmniboxBadge(item.query);
        switchView('home');
        runFederatedSearch(item.query, 'all');
      },
    });
    container.appendChild(chip);
  }
}

function updateOmniboxBadge(val) {
  const badge = document.getElementById('omniboxModeBadge');
  if (!badge) return;
  const trimmed = String(val || '').trim().toLowerCase();
  if (trimmed.startsWith('go/')) {
    badge.textContent = 'go/ link';
    badge.classList.add('go-mode');
  } else if (trimmed.startsWith('whatis:') || trimmed.startsWith('whatis ')) {
    badge.textContent = 'go/whatis';
    badge.classList.add('go-mode');
  } else if (/(owner:|source:|type:)/.test(trimmed)) {
    badge.textContent = 'Filtre Moma';
    badge.classList.add('go-mode');
  } else {
    badge.textContent = 'Moma Search';
    badge.classList.remove('go-mode');
  }
}

async function loadDashboard() {
  const data = await apiFetch('/api/dashboard');

  const aclBadge = document.getElementById('dashboardAclBadge');
  if (aclBadge && appState.currentUser) {
    aclBadge.textContent = `ACL: @${appState.currentUser.ldap} (${appState.currentUser.department})`;
  }

  // 1. Render Actionable Approvals Center (1-click Approve / Reject)
  const approvalsList = document.getElementById('dashboardApprovalsList');
  if (approvalsList) {
    approvalsList.replaceChildren();
    for (const a of data.approvals || []) {
      const isPending = a.status === 'PENDING';
      const statusBadgeClass =
        a.status === 'APPROVED'
          ? 'badge badge-green'
          : a.status === 'REJECTED'
            ? 'badge badge-red'
            : 'badge badge-amber';

      const card = el('div', { className: 'doc-item' }, [
        el('div', { className: 'doc-item-header' }, [
          el('div', {}, [
            el('span', { className: 'badge badge-blue', text: a.source_system }),
            el('strong', { text: ` ${a.title}`, style: { marginLeft: '0.45rem', fontSize: '0.9rem' } }),
          ]),
          el('span', { className: statusBadgeClass, text: `${a.approval_key} • ${a.status}` }),
        ]),
        el('p', { className: 'doc-summary', text: a.summary }),
        el('div', { className: 'doc-meta' }, [
          el('span', { text: `Demandeur : @${a.requester_ldap}` }),
          el('span', { text: `Impact / Montant : ${a.amount_or_impact}` }),
          isPending
            ? el('div', { className: 'approval-actions' }, [
                el('button', {
                  className: 'btn-approve',
                  text: '✓ Approuver en 1 clic',
                  attrs: { type: 'button' },
                  onClick: () => handleApprovalDecision(a.approval_key, 'APPROVED'),
                }),
                el('button', {
                  className: 'btn-reject',
                  text: '✕ Refuser',
                  attrs: { type: 'button' },
                  onClick: () => handleApprovalDecision(a.approval_key, 'REJECTED'),
                }),
              ])
            : el('span', {
                text: `Traité (${a.status}) le ${a.created_at}`,
                style: { fontWeight: '600', color: '#0f766e' },
              }),
        ]),
      ]);
      approvalsList.appendChild(card);
    }
  }

  // 2. Render Personalized Daily Agenda ("Up Next")
  const meetingsList = document.getElementById('dashboardMeetingsList');
  if (meetingsList) {
    meetingsList.replaceChildren();
    for (const m of data.meetings || []) {
      const attendeesRow = el('div', { className: 'quick-chips', style: { marginTop: '0.3rem' } });
      for (const ldap of m.attendees || []) {
        attendeesRow.appendChild(
          el('button', {
            className: 'citation-pill',
            text: `@${ldap}`,
            attrs: { type: 'button' },
            onClick: () => {
              appState.selectedPersonLdap = ldap;
              switchView('teams');
            },
          })
        );
      }

      meetingsList.appendChild(
        el('div', { className: 'ticket-item' }, [
          el('div', { className: 'doc-item-header' }, [
            el('span', { className: 'badge badge-teal', text: `${m.start_time} – ${m.end_time}` }),
            el('button', {
              className: 'btn-link',
              text: m.video_link,
              attrs: { type: 'button' },
              onClick: () => triggerGoLinkResolution(m.video_link),
            }),
          ]),
          el('div', { className: 'golink-mini-title', text: m.title }),
          el('div', {
            className: 'golink-mini-meta',
            text: `Salle : ${m.room}`,
          }),
          attendeesRow,
        ])
      );
    }
  }

  // 3. Render Campus Life & Cafeteria Menu matched to user's office city
  const campusCard = document.getElementById('dashboardCampusCard');
  const campusBadge = document.getElementById('dashboardCampusBadge');
  if (campusCard && data.campusMenu) {
    const cm = data.campusMenu;
    if (campusBadge) {
      campusBadge.textContent = cm.campus;
    }
    campusCard.replaceChildren(
      el('div', { style: { fontWeight: '700', color: '#0f172a' } }, [
        `${cm.cafe_name} (${cm.crowd_status})`,
      ]),
      el('div', { className: 'campus-menu-row' }, [
        el('div', { className: 'info-label', text: 'Plat du Chef' }),
        el('div', { text: cm.main_dish }),
      ]),
      el('div', { className: 'campus-menu-row' }, [
        el('div', { className: 'info-label', text: 'Option Végétarienne / Plant-Based' }),
        el('div', { text: cm.vegetarian_dish }),
      ]),
      el('div', { className: 'campus-menu-row' }, [
        el('div', { className: 'info-label', text: 'Micro-Kitchen & Barista' }),
        el('div', { text: cm.barista_special }),
      ])
    );
  }

  // 4. Render connected third-party tools strip
  const connStrip = document.getElementById('dashboardConnectorsStrip');
  if (connStrip) {
    connStrip.replaceChildren();
    for (const c of data.connectors || []) {
      const pill = el(
        'div',
        {
          className: c.enabled ? 'connector-mini-pill' : 'connector-mini-pill disabled-conn',
        },
        [
          el('div', { className: 'doc-item-header' }, [
            el('strong', { text: c.name, style: { fontSize: '0.82rem' } }),
            el('span', {
              className: c.enabled ? 'badge badge-green' : 'badge badge-amber',
              text: c.enabled ? 'Actif' : 'Off',
            }),
          ]),
          el('div', {
            className: 'golink-mini-meta',
            text: `${c.vendor} • ${c.stats.documents} docs • ${c.stats.oneboxes} OneBox`,
          }),
        ]
      );
      connStrip.appendChild(pill);
    }
  }

  // 5. Render top go/links
  const goGrid = document.getElementById('dashboardGoLinksGrid');
  if (goGrid) {
    goGrid.replaceChildren();
    for (const g of data.topGoLinks || []) {
      const card = el(
        'button',
        {
          className: 'golink-card-mini',
          attrs: { type: 'button' },
          onClick: () => triggerGoLinkResolution(g.slug),
        },
        [
          el('div', { className: 'golink-slug', text: `go/${g.slug}` }),
          el('div', { className: 'golink-mini-title', text: g.title }),
          el('div', {
            className: 'golink-mini-meta',
            text: `${g.hits} utilisations • @${g.owner_ldap}`,
          }),
        ]
      );
      goGrid.appendChild(card);
    }
  }

  // 6. Render accessible documents
  const docsList = document.getElementById('dashboardDocsList');
  if (docsList) {
    docsList.replaceChildren();
    for (const d of data.accessibleDocs || []) {
      docsList.appendChild(createDocumentCard(d));
    }
  }

  // 7. Render announcements
  const annContainer = document.getElementById('dashboardAnnouncements');
  if (annContainer) {
    annContainer.replaceChildren();
    for (const a of data.announcements || []) {
      const item = el('div', { className: 'announcement-item' }, [
        el('div', { className: 'doc-item-header' }, [
          el('span', { className: 'badge badge-blue', text: a.category }),
          el('span', { className: 'golink-mini-meta', text: a.published_at }),
        ]),
        el('div', { className: 'golink-mini-title', text: a.title }),
        el('p', { className: 'doc-summary', text: a.summary }),
        el('div', { className: 'doc-meta' }, [
          el('span', { text: `Par @${a.author_ldap}` }),
          a.go_link
            ? el('button', {
                className: 'btn-link',
                text: a.go_link,
                attrs: { type: 'button' },
                onClick: () => triggerGoLinkResolution(a.go_link),
              })
            : null,
        ]),
      ]);
      annContainer.appendChild(item);
    }
  }

  // 8. Render IT, SRE & SAP tickets
  const ticketsContainer = document.getElementById('dashboardTickets');
  if (ticketsContainer) {
    ticketsContainer.replaceChildren();
    for (const t of data.recentTickets || []) {
      const item = el('div', { className: 'ticket-item' }, [
        el('div', { className: 'doc-item-header' }, [
          el('span', { className: 'badge badge-amber', text: `${t.ticket_key} • ${t.status}` }),
          el('span', { className: 'golink-mini-meta', text: t.priority }),
        ]),
        el('div', { className: 'golink-mini-title', text: t.title }),
        el('p', { className: 'doc-summary', text: t.summary }),
        el('div', { className: 'doc-meta' }, [
          el('span', { text: `${t.system_name} • Assigné à @${t.assignee_ldap}` }),
        ]),
      ]);
      ticketsContainer.appendChild(item);
    }
  }
}

function createDocumentCard(doc) {
  const isRestricted = doc.visibilityDept && doc.visibilityDept !== 'ALL';
  return el('div', { className: 'doc-item' }, [
    el('div', { className: 'doc-item-header' }, [
      el('button', {
        className: 'doc-title-btn',
        text: doc.title,
        attrs: { type: 'button' },
        onClick: () => showDocumentModal(doc),
      }),
      el('span', {
        className: isRestricted ? 'badge badge-red' : 'badge badge-teal',
        text: isRestricted ? `ACL: ${doc.visibilityDept}` : doc.sourceSystem,
      }),
    ]),
    el('p', { className: 'doc-summary', text: doc.summary }),
    el('div', { className: 'doc-meta' }, [
      el('span', { text: `${doc.docCode} • Connecteur: ${doc.connectorKey || 'interne'}` }),
      el('button', {
        className: 'btn-link',
        text: `Owner: @${doc.ownerLdap}`,
        attrs: { type: 'button' },
        onClick: () => {
          appState.selectedPersonLdap = doc.ownerLdap;
          switchView('teams');
        },
      }),
      doc.goLink
        ? el('button', {
            className: 'btn-link',
            text: doc.goLink,
            attrs: { type: 'button' },
            onClick: () => triggerGoLinkResolution(doc.goLink),
          })
        : null,
    ]),
  ]);
}

function showDocumentModal(doc) {
  const body = el('div', {}, [
    el('div', { className: 'doc-meta', style: { marginBottom: '0.75rem' } }, [
      el('span', { className: 'badge badge-blue', text: doc.docCode }),
      el('span', { className: 'badge badge-teal', text: doc.sourceSystem }),
      el('span', { text: `Mis à jour : ${doc.updatedAt || 'Récent'}` }),
    ]),
    el('p', {
      text: doc.content || doc.summary,
      style: { marginBottom: '1rem', color: '#0f172a' },
    }),
    doc.goLink
      ? el('button', {
          className: 'btn-primary btn-sm',
          text: `Ouvrir le raccourci associé (${doc.goLink})`,
          attrs: { type: 'button' },
          onClick: () => {
            closeModal();
            triggerGoLinkResolution(doc.goLink);
          },
        })
      : null,
  ]);
  openModal(doc.title, body);
}

async function triggerGoLinkResolution(slug) {
  try {
    const res = await apiFetch('/api/golinks/resolve', {
      method: 'POST',
      body: { slug },
    });
    const g = res.resolved;
    const modalContent = el('div', {}, [
      el('div', { className: 'exact-go-banner', style: { marginBottom: '0.9rem' } }, [
        el('div', {}, [
          el('div', { className: 'golink-slug', text: `http://go/${g.slug}` }),
          el('div', { text: `Redirection HTTP 302 vers : ${g.target_url}`, style: { fontSize: '0.82rem' } }),
        ]),
        el('span', { className: 'badge badge-green', text: `${g.hits} visites` }),
      ]),
      el('p', { text: g.description, style: { marginBottom: '0.85rem' } }),
      el('div', { className: 'doc-meta' }, [
        el('span', { text: `Catégorie : ${g.category}` }),
        el('button', {
          className: 'btn-link',
          text: `Mainteneur : @${g.owner_ldap}`,
          attrs: { type: 'button' },
          onClick: () => {
            closeModal();
            appState.selectedPersonLdap = g.owner_ldap;
            switchView('teams');
          },
        }),
      ]),
    ]);
    openModal(`Résolution go/${g.slug} — ${g.title}`, modalContent);
    loadDashboard();
    if (appState.activeView === 'golinks') {
      loadGoLinksRegistry();
    }
  } catch (err) {
    showToast(err.message);
  }
}

async function runFederatedSearch(query, facet = 'all') {
  const cleanQ = String(query || '').trim();
  const isNewQuery = cleanQ !== appState.activeQuery;
  appState.activeQuery = cleanQ;
  appState.activeFacet = facet;
  hideOmniboxTypeahead();

  if (isNewQuery) {
    appState.askMomaTurns = [];
    appState.lastInteractionId = null;
  }

  const searchWrapper = document.getElementById('searchResultsSection');
  const dashboardWrapper = document.getElementById('dashboardWidgetsSection');
  if (!cleanQ) {
    if (searchWrapper) searchWrapper.classList.add('hidden');
    if (dashboardWrapper) dashboardWrapper.classList.remove('hidden');
    return;
  }

  if (searchWrapper) searchWrapper.classList.remove('hidden');
  if (dashboardWrapper) dashboardWrapper.classList.add('hidden');

  const data = await apiFetch(
    `/api/search?q=${encodeURIComponent(cleanQ)}&facet=${encodeURIComponent(facet)}`
  );
  appState.lastSearchPayload = data;
  renderSearchResults(data);
}

function renderSearchResults(data) {
  // 1. Render Facet buttons
  const facetBar = document.getElementById('searchFacetButtons');
  if (facetBar) {
    facetBar.replaceChildren();
    const facets = [
      { id: 'all', label: `Tout (${data.counts.total})` },
      { id: 'documents', label: `Documents & Outils (${data.counts.documents})` },
      { id: 'golinks', label: `Raccourcis go/ (${data.counts.goLinks})` },
      { id: 'people', label: `Personnes Teams (${data.counts.people})` },
      { id: 'tickets', label: `Tickets ITSM/ERP (${data.counts.tickets})` },
    ];
    for (const f of facets) {
      const btn = el('button', {
        className: f.id === data.facet ? 'facet-btn active' : 'facet-btn',
        text: f.label,
        attrs: { type: 'button' },
        onClick: () => runFederatedSearch(data.query, f.id),
      });
      facetBar.appendChild(btn);
    }
  }

  // 1b. Render Active Search Operators Banner if present
  const opBanner = document.getElementById('activeOperatorsBanner');
  if (opBanner) {
    opBanner.replaceChildren();
    const ops = data.operators || {};
    const activeOpTags = [];
    if (ops.owner) activeOpTags.push(`owner:@${ops.owner}`);
    if (ops.source) activeOpTags.push(`source:${ops.source}`);
    if (ops.type) activeOpTags.push(`type:${ops.type}`);
    if (ops.whatis) activeOpTags.push(`whatis:${ops.whatis}`);

    if (activeOpTags.length > 0) {
      opBanner.classList.remove('hidden');
      const row = el('div', { className: 'operators-banner' }, [
        el('strong', { text: 'Opérateurs Moma actifs :' }),
      ]);
      for (const tag of activeOpTags) {
        row.appendChild(el('span', { className: 'badge badge-blue', text: tag }));
      }
      opBanner.appendChild(row);
    } else {
      opBanner.classList.add('hidden');
    }
  }

  // 2. Render Exact go/link Match Banner if found
  const exactGoContainer = document.getElementById('exactGoMatchContainer');
  if (exactGoContainer) {
    exactGoContainer.replaceChildren();
    if (data.exactGoMatch) {
      const g = data.exactGoMatch;
      exactGoContainer.classList.remove('hidden');
      exactGoContainer.appendChild(
        el('div', { className: 'exact-go-banner' }, [
          el('div', {}, [
            el('span', { className: 'badge badge-green', text: 'Raccourci direct détecté' }),
            el('strong', {
              text: ` go/${g.slug} → ${g.title}`,
              style: { marginLeft: '0.5rem' },
            }),
            el('div', {
              text: `${g.target_url} • Maintenu par @${g.owner_ldap} (${g.hits} clics)`,
              style: { fontSize: '0.8rem', color: '#475569', marginTop: '0.2rem' },
            }),
          ]),
          el('button', {
            className: 'btn-primary btn-sm',
            text: `Ouvrir go/${g.slug}`,
            attrs: { type: 'button' },
            onClick: () => triggerGoLinkResolution(g.slug),
          }),
        ])
      );
    } else {
      exactGoContainer.classList.add('hidden');
    }
  }

  // 2b. Render Moma OneBox Live Structured Cards (Whatis, ServiceNow, Workday, SAP, Custom Tools)
  const oneBoxContainer = document.getElementById('oneBoxContainer');
  if (oneBoxContainer) {
    oneBoxContainer.replaceChildren();
    const oneBoxes = data.oneBoxCards || [];
    if (oneBoxes.length > 0) {
      oneBoxContainer.classList.remove('hidden');
      for (const ob of oneBoxes) {
        const fieldsGrid = el('div', { className: 'onebox-fields' });
        for (const f of ob.fields || []) {
          fieldsGrid.appendChild(
            el('div', { className: 'info-box' }, [
              el('div', { className: 'info-label', text: f.label }),
              el('div', { text: f.value, style: { fontWeight: '600', marginTop: '0.15rem' } }),
            ])
          );
        }
        oneBoxContainer.appendChild(
          el('div', { className: 'onebox-card' }, [
            el('div', { className: 'doc-item-header' }, [
              el('div', {}, [
                el('span', { className: 'badge badge-blue', text: ob.badgeText }),
                el('strong', { text: ` ${ob.cardTitle}`, style: { marginLeft: '0.45rem' } }),
              ]),
              el('button', {
                className: 'btn-primary btn-sm',
                text: ob.actionLabel,
                attrs: { type: 'button' },
                onClick: () => triggerGoLinkResolution(ob.actionGoLink),
              }),
            ]),
            el('div', {
              text: `${ob.cardSubtitle} (Connecteur actif : ${ob.connectorName})`,
              style: { fontSize: '0.78rem', color: '#475569' },
            }),
            fieldsGrid,
          ])
        );
      }
    } else {
      oneBoxContainer.classList.add('hidden');
    }
  }

  // 3. Render AI Overview + Multi-Turn Conversational "Ask Moma"
  const aiContainer = document.getElementById('aiOverviewContainer');
  if (aiContainer && data.aiOverview) {
    const ai = data.aiOverview;
    aiContainer.replaceChildren();

    const bulletsList = el('ul', { className: 'ai-bullets' });
    for (const b of ai.bullets || []) {
      bulletsList.appendChild(el('li', { text: b }));
    }

    const citationsRow = el('div', { className: 'ai-citations-row' });
    for (const c of ai.citations || []) {
      const pill = el('button', {
        className: 'citation-pill',
        text: `[${c.index}] ${c.code} — ${c.title}`,
        attrs: { type: 'button' },
        onClick: () => {
          if (c.goLink) {
            triggerGoLinkResolution(c.goLink);
          }
        },
      });
      citationsRow.appendChild(pill);
    }

    aiContainer.appendChild(
      el('div', { className: 'ai-header' }, [
        el('div', { className: 'ai-title-group' }, [
          el('span', { className: 'ai-sparkle', text: 'AI' }),
          el('strong', { text: 'Moma AI Overview & Ask Moma' }),
          el('span', { className: 'badge badge-teal', text: ai.model }),
        ]),
        el('span', {
          className: data.aclTrimmedCount > 0 ? 'badge badge-amber' : 'badge badge-blue',
          text: ai.aclNotice,
        }),
      ])
    );
    aiContainer.appendChild(el('p', { className: 'ai-answer-text', text: ai.answer }));
    if ((ai.bullets || []).length > 0) {
      aiContainer.appendChild(bulletsList);
    }
    if ((ai.citations || []).length > 0) {
      aiContainer.appendChild(citationsRow);
    }

    // Multi-Turn Conversational "Ask Moma" section
    const askMomaSection = el('div', { className: 'ask-moma-section' });
    const turnsContainer = el('div', { className: 'ask-moma-turns' });
    for (const turn of appState.askMomaTurns) {
      const turnNodes = [
        el('div', {
          text: `Vous : « ${turn.question} »`,
          style: { fontWeight: '700', color: '#0369a1', marginBottom: '0.2rem' },
        }),
        el('div', { text: `Ask Moma : ${turn.answer}`, style: { color: '#0f172a' } }),
      ];
      if (turn.suggestedAction) {
        const act = turn.suggestedAction;
        turnNodes.push(
          el('div', { style: { marginTop: '0.4rem' } }, [
            el('button', {
              className: 'btn-secondary btn-sm',
              text: `⚡ ${act.label}`,
              attrs: { type: 'button' },
              onClick: () => {
                if (act.type === 'create_ticket') {
                  openQuickTicketModal(act.defaultTitle);
                } else if (act.type === 'open_golink') {
                  triggerGoLinkResolution(act.slug);
                } else if (act.type === 'view_person') {
                  appState.selectedPersonLdap = act.ldap;
                  switchView('teams');
                }
              },
            }),
          ])
        );
      }
      turnsContainer.appendChild(el('div', { className: 'ask-moma-turn' }, turnNodes));
    }

    const followUpInput = el('input', {
      className: 'form-input',
      attrs: {
        type: 'text',
        placeholder:
          'Poser une question de suivi à Ask Moma (ex: Qui est le responsable ? Quel est le lien go/ ? Ouvrir un ticket ?)...',
        'aria-label': 'Poser une question de suivi à Ask Moma',
      },
    });
    const followUpForm = el(
      'form',
      {
        className: 'ask-moma-form',
      },
      [
        followUpInput,
        el('button', {
          className: 'btn-primary btn-sm',
          text: 'Demander à Ask Moma',
          attrs: { type: 'submit' },
        }),
      ]
    );
    followUpForm.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const qVal = followUpInput.value.trim();
      if (!qVal) return;
      followUpInput.value = '';
      await handleAskMomaFollowUp(qVal);
    });

    askMomaSection.appendChild(turnsContainer);
    askMomaSection.appendChild(followUpForm);
    aiContainer.appendChild(askMomaSection);
  }

  // 4. Render Federated Results Columns
  const resultsGrid = document.getElementById('federatedResultsContainer');
  if (resultsGrid) {
    resultsGrid.replaceChildren();

    const leftCol = el('div', { className: 'docs-list' });
    leftCol.appendChild(
      el('h3', {
        className: 'card-title',
        text: `Documents & Politiques Multi-Connecteurs (${(data.documents || []).length})`,
      })
    );
    if ((data.documents || []).length === 0) {
      leftCol.appendChild(
        el('div', {
          className: 'doc-item',
          text:
            data.disabledConnectorSkippedCount > 0
              ? `Aucun document affiché (${data.disabledConnectorSkippedCount} résultat(s) masqué(s) car leur connecteur est désactivé).`
              : 'Aucun document dans ce filtre.',
        })
      );
    } else {
      for (const doc of data.documents) {
        leftCol.appendChild(createDocumentCard(doc));
      }
    }

    if ((data.tickets || []).length > 0) {
      leftCol.appendChild(
        el('h3', {
          className: 'card-title',
          text: `Tickets ITSM, Jira & Commandes SAP (${data.tickets.length})`,
          style: { marginTop: '0.8rem' },
        })
      );
      for (const t of data.tickets) {
        leftCol.appendChild(
          el('div', { className: 'ticket-item' }, [
            el('div', { className: 'doc-item-header' }, [
              el('span', { className: 'badge badge-amber', text: `${t.ticket_key} • ${t.status}` }),
              el('span', { className: 'golink-mini-meta', text: t.priority }),
            ]),
            el('div', { className: 'golink-mini-title', text: t.title }),
            el('p', { className: 'doc-summary', text: t.summary }),
          ])
        );
      }
    }

    const rightCol = el('div', { className: 'docs-list' });
    rightCol.appendChild(
      el('h3', {
        className: 'card-title',
        text: `Personnes & Experts Teams (${(data.people || []).length})`,
      })
    );
    for (const p of data.people || []) {
      rightCol.appendChild(
        el(
          'button',
          {
            className: 'person-list-btn',
            attrs: { type: 'button' },
            onClick: () => {
              appState.selectedPersonLdap = p.ldap;
              switchView('teams');
            },
          },
          [
            createAvatar(p, false),
            el('div', {}, [
              el('div', {
                text: `${p.fullName} (@${p.ldap})`,
                style: { fontWeight: '700', fontSize: '0.86rem' },
              }),
              el('div', {
                text: `${p.title} • ${p.team}`,
                style: { fontSize: '0.76rem', color: '#475569' },
              }),
            ]),
          ]
        )
      );
    }

    rightCol.appendChild(
      el('h3', {
        className: 'card-title',
        text: `Raccourcis go/links (${(data.goLinks || []).length})`,
        style: { marginTop: '0.8rem' },
      })
    );
    for (const g of data.goLinks || []) {
      rightCol.appendChild(
        el(
          'button',
          {
            className: 'golink-card-mini',
            attrs: { type: 'button' },
            onClick: () => triggerGoLinkResolution(g.slug),
          },
          [
            el('div', { className: 'golink-slug', text: `go/${g.slug}` }),
            el('div', { className: 'golink-mini-title', text: g.title }),
            el('div', { className: 'golink-mini-meta', text: g.description }),
          ]
        )
      );
    }

    resultsGrid.appendChild(leftCol);
    resultsGrid.appendChild(rightCol);
  }
}

/**
 * Connectors Hub & Custom Tool Studio (View 2)
 */
async function loadConnectorsHub() {
  const data = await apiFetch('/api/connectors');
  const container = document.getElementById('connectorsListContainer');
  if (!container) return;
  container.replaceChildren();

  for (const c of data.connectors || []) {
    const firstTrigger = String(c.oneboxTrigger || c.connectorKey)
      .split(',')[0]
      .trim();

    const card = el('div', { className: 'doc-item' }, [
      el('div', { className: 'doc-item-header' }, [
        el('div', {}, [
          el('strong', { text: c.name, style: { fontSize: '0.95rem' } }),
          c.isCustom
            ? el('span', {
                className: 'badge badge-teal',
                text: 'Outil Client Custom',
                style: { marginLeft: '0.5rem' },
              })
            : el('span', {
                className: 'badge badge-blue',
                text: c.vendor,
                style: { marginLeft: '0.5rem' },
              }),
        ]),
        el('div', { style: { display: 'flex', gap: '0.45rem', alignItems: 'center' } }, [
          el('span', {
            className: c.enabled ? 'badge badge-green' : 'badge badge-amber',
            text: c.enabled ? 'Indexé & OneBox Actif' : 'Désactivé',
          }),
          el('button', {
            className: 'btn-secondary btn-sm',
            text: 'Tester dans Moma Search',
            attrs: { type: 'button' },
            onClick: () => {
              const input = document.getElementById('globalSearchInput');
              if (input) input.value = firstTrigger;
              switchView('home');
              runFederatedSearch(firstTrigger, 'all');
            },
          }),
          el('button', {
            className: c.enabled ? 'btn-danger' : 'btn-primary btn-sm',
            text: c.enabled ? 'Désactiver' : 'Activer',
            attrs: { type: 'button' },
            onClick: () => handleToggleConnector(c.connectorKey),
          }),
        ]),
      ]),
      el('p', {
        className: 'doc-summary',
        text: `Protocole : ${c.protocol} • URL : ${c.baseUrl} • Mode ACL : ${c.aclMode}`,
      }),
      el('div', { className: 'doc-meta' }, [
        el('span', { text: `Déclencheurs OneBox : "${c.oneboxTrigger}"` }),
        el('span', {
          text: `Éléments synchronisés : ${c.stats.documents} doc(s), ${c.stats.tickets} ticket(s), ${c.stats.oneboxes} OneBox`,
        }),
        el('span', { text: `Dernière sync : ${c.lastSyncAt} (@${c.ownerLdap})` }),
      ]),
    ]);
    container.appendChild(card);
  }
}

async function handleToggleConnector(connectorKey) {
  try {
    const res = await apiFetch('/api/connectors/toggle', {
      method: 'POST',
      body: { connectorKey },
    });
    const st = res.connector.enabled ? 'activé' : 'désactivé';
    showToast(`Connecteur ${res.connector.name} ${st}.`);
    loadConnectorsHub();
    loadDashboard();
  } catch (err) {
    showToast(err.message);
  }
}

function renderConnectorPresets() {
  const row = document.getElementById('connectorPresetsRow');
  if (!row) return;
  row.replaceChildren();

  const presets = [
    {
      label: '+ Salesforce CRM',
      name: 'Salesforce CRM Enterprise',
      key: 'salesforce',
      vendor: 'Salesforce',
      protocol: 'REST API + Webhook + OAuth 2.0',
      url: 'https://salesforce.corp.internal',
      trigger: 'salesforce, crm, client, contrat, opportunité',
      dept: 'ALL',
      metricLabel: 'Pipeline Entreprise Q4 2026',
      metricValue: '18.4 M€ sécurisés • 42 comptes grands clients actifs',
      sampleTitle: 'Processus Commercial, Contrats Clients & Opportunités Salesforce CRM',
      sampleContent:
        'Toutes les opportunités commerciales grands comptes, les contrats signés et les fiches clients sont synchronisés depuis Salesforce CRM (accessible sur go/salesforce). Pour créer un devis, validez les conditions tarifaires dans Salesforce avant envoi.',
    },
    {
      label: '+ Zendesk Support',
      name: 'Zendesk Customer Support',
      key: 'zendesk',
      vendor: 'Zendesk',
      protocol: 'REST API + Webhook + OAuth 2.0',
      url: 'https://zendesk.corp.internal',
      trigger: 'zendesk, support client, sla, ticket client',
      dept: 'ALL',
      metricLabel: 'File Support Client (SLA Temps Réel)',
      metricValue: 'CSAT 97.4% • Temps de 1ère réponse médian : 11 min',
      sampleTitle: 'Escalade Support Client Niveau 3 (Zendesk <-> Engineering)',
      sampleContent:
        'Les tickets clients critiques reçus dans Zendesk (go/zendesk) avec un impact de production sont automatiquement liés aux équipes d’ingénierie via le connecteur Moma-bis.',
    },
    {
      label: '+ Datadog Observability',
      name: 'Datadog APM & Logs',
      key: 'datadog',
      vendor: 'Datadog',
      protocol: 'MCP Server Tool + mTLS',
      url: 'https://datadog.corp.internal',
      trigger: 'datadog, apm, logs, latence, monitoring',
      dept: 'Engineering',
      metricLabel: 'Santé Globale Cluster Production',
      metricValue: 'Latence P99 : 64ms • 0 alerte critique active',
      sampleTitle: 'Dashboards APM, Traces Distribuées & Logs dans Datadog',
      sampleContent:
        'Les métriques applicatives, traces OpenTelemetry et journaux d’audit des microservices sont centralisés dans Datadog (go/datadog, restreint ACL Engineering).',
    },
  ];

  for (const p of presets) {
    row.appendChild(
      el('button', {
        className: 'chip-btn',
        text: p.label,
        attrs: { type: 'button' },
        onClick: () => {
          document.getElementById('connNameInput').value = p.name;
          document.getElementById('connKeyInput').value = p.key;
          document.getElementById('connVendorInput').value = p.vendor;
          document.getElementById('connProtocolInput').value = p.protocol;
          document.getElementById('connUrlInput').value = p.url;
          document.getElementById('connTriggerInput').value = p.trigger;
          document.getElementById('connDeptInput').value = p.dept;
          document.getElementById('connMetricLabelInput').value = p.metricLabel;
          document.getElementById('connMetricValueInput').value = p.metricValue;
          document.getElementById('connSampleTitleInput').value = p.sampleTitle;
          document.getElementById('connSampleContentInput').value = p.sampleContent;
          showToast(`Modèle "${p.name}" pré-rempli. Cliquez sur "Brancher l'outil" pour l'indexer !`);
        },
      })
    );
  }
}

async function loadPeopleDirectory() {
  const qInput = document.getElementById('peopleSearchInput');
  const deptSelect = document.getElementById('peopleDeptSelect');
  const q = qInput ? qInput.value.trim() : '';
  const dept = deptSelect ? deptSelect.value : '';

  const data = await apiFetch(
    `/api/people?q=${encodeURIComponent(q)}&department=${encodeURIComponent(dept)}`
  );
  const listEl = document.getElementById('peopleDirectoryList');
  if (!listEl) return;

  listEl.replaceChildren();
  for (const p of data.people || []) {
    const itemBtn = el(
      'button',
      {
        className:
          p.ldap === appState.selectedPersonLdap ? 'person-list-btn active' : 'person-list-btn',
        attrs: { type: 'button' },
        onClick: () => {
          appState.selectedPersonLdap = p.ldap;
          loadPeopleDirectory();
          loadPersonOrgChart(p.ldap, false);
        },
      },
      [
        createAvatar(p, false),
        el('div', { style: { flex: '1' } }, [
          el('div', {
            text: `${p.fullName} (@${p.ldap})`,
            style: { fontWeight: '700', fontSize: '0.85rem' },
          }),
          el('div', {
            text: `${p.title}`,
            style: { fontSize: '0.76rem', color: '#475569' },
          }),
          el('div', { style: { marginTop: '0.2rem' } }, [createPresenceBadge(p)]),
        ]),
      ]
    );
    listEl.appendChild(itemBtn);
  }
}

async function loadPersonOrgChart(ldap, revealPii = false) {
  const url = `/api/people/${encodeURIComponent(ldap)}${revealPii ? '?revealPii=1' : ''}`;
  const data = await apiFetch(url);
  const p = data.profile;

  const detailContainer = document.getElementById('personDetailContainer');
  if (detailContainer && p) {
    detailContainer.replaceChildren();

    const badgesRow = el('div', { className: 'quick-chips', style: { marginBottom: '0.85rem' } });
    badgesRow.appendChild(createPresenceBadge(p));
    for (const b of p.badges || []) {
      badgesRow.appendChild(el('span', { className: 'badge badge-teal', text: b }));
    }

    const skillsRow = el('div', { className: 'quick-chips', style: { marginTop: '0.35rem' } });
    for (const s of p.skills || []) {
      skillsRow.appendChild(el('span', { className: 'badge badge-blue', text: s }));
    }

    const groupsRow = el('div', { className: 'quick-chips', style: { marginTop: '0.35rem' } });
    for (const gName of p.groups || []) {
      groupsRow.appendChild(el('span', { className: 'citation-pill', text: gName }));
    }

    const projectsList = el('ul', { className: 'ai-bullets', style: { marginTop: '0.35rem' } });
    for (const prj of p.projects || []) {
      projectsList.appendChild(el('li', { text: prj }));
    }

    detailContainer.appendChild(
      el('div', { className: 'person-header-banner' }, [
        el('div', { className: 'person-identity' }, [
          createAvatar(p, true),
          el('div', {}, [
            el('h2', { className: 'card-title', text: `${p.fullName} (@${p.ldap})` }),
            el('div', {
              text: `${p.title} • ${p.level} • ${p.team}`,
              style: { fontSize: '0.86rem', color: '#475569', fontWeight: '600' },
            }),
            el('div', {
              text: p.bio,
              style: { fontSize: '0.82rem', color: '#64748b', marginTop: '0.25rem' },
            }),
          ]),
        ]),
        p.piiMasked
          ? el('button', {
              className: 'btn-secondary btn-sm',
              text: 'Révéler Contact (PII protégée)',
              attrs: { type: 'button' },
              onClick: () => loadPersonOrgChart(p.ldap, true),
            })
          : el('span', { className: 'badge badge-green', text: 'Coordonnées démasquées' }),
      ])
    );

    detailContainer.appendChild(badgesRow);

    // Interactive Campus Building / Floor / Desk Map Locator
    detailContainer.appendChild(
      el('div', { className: 'campus-map-box' }, [
        el('div', {}, [
          el('div', { className: 'info-label', text: 'Plan de Campus & Emplacement Bureau (Moma Maps)' }),
          el('div', {
            text: `${p.office} • Poste : ${p.deskLocation || 'N/A'}`,
            style: { fontWeight: '700', color: '#0f172a', marginTop: '0.15rem' },
          }),
        ]),
        el('span', { className: 'badge badge-blue', text: `Zone ${p.deskLocation || p.office}` }),
      ])
    );

    detailContainer.appendChild(
      el('div', { className: 'person-info-grid' }, [
        el('div', { className: 'info-box' }, [
          el('div', { className: 'info-label', text: 'Bureau & Localisation' }),
          el('div', { text: `${p.office} (${p.deskLocation || ''})` }),
        ]),
        el('div', { className: 'info-box' }, [
          el('div', { className: 'info-label', text: 'Fuseau & Horaires' }),
          el('div', { text: `${p.timezone} (${p.workingHours})` }),
        ]),
        el('div', { className: 'info-box' }, [
          el('div', { className: 'info-label', text: 'Email & Téléphone (PII Masking)' }),
          el('div', { text: `${p.email} • ${p.phone}` }),
        ]),
        el('div', { className: 'info-box' }, [
          el('div', { className: 'info-label', text: 'Centre de Coût & Ancienneté' }),
          el('div', { text: `${p.costCenter} • Entrée : ${p.hireDate}` }),
        ]),
      ])
    );

    detailContainer.appendChild(el('div', { className: 'info-label', text: 'Compétences & Expertise' }));
    detailContainer.appendChild(skillsRow);

    detailContainer.appendChild(
      el('div', { className: 'info-label', text: 'Groupes IAM & Mailing-Lists (Moma Groups)', style: { marginTop: '0.85rem' } })
    );
    detailContainer.appendChild(groupsRow);

    detailContainer.appendChild(
      el('div', { className: 'info-label', text: 'Projets & OKRs Actifs', style: { marginTop: '0.85rem' } })
    );
    detailContainer.appendChild(projectsList);
  }

  // Render Interactive Org Chart Tree
  const orgContainer = document.getElementById('orgChartContainer');
  if (orgContainer && p) {
    orgContainer.replaceChildren();
    orgContainer.appendChild(
      el('div', { className: 'card-header' }, [
        el('h3', {
          className: 'card-title',
          text: `Organigramme Interactif (Moma Teams) — @${p.ldap}`,
        }),
        el('span', {
          className: 'golink-mini-meta',
          text: 'Cliquez sur n’importe quel collaborateur pour parcourir la hiérarchie',
        }),
      ])
    );

    const tree = el('div', { className: 'org-tree-section' });

    if ((data.managementChain || []).length > 0) {
      const mgrRow = el('div', { className: 'org-nodes-row' });
      for (const m of data.managementChain) {
        mgrRow.appendChild(createOrgNodeButton(m, false));
      }
      tree.appendChild(
        el('div', { className: 'org-tier' }, [
          el('div', { className: 'org-tier-title', text: 'Chaîne de Management (Ascendants N+1 / VP)' }),
          mgrRow,
        ])
      );
    }

    const focusRow = el('div', { className: 'org-nodes-row' });
    focusRow.appendChild(createOrgNodeButton(p, true));
    for (const peer of data.peers || []) {
      focusRow.appendChild(createOrgNodeButton(peer, false));
    }
    tree.appendChild(
      el('div', { className: 'org-tier' }, [
        el('div', {
          className: 'org-tier-title',
          text: `Collaborateur sélectionné & Pairs (${(data.peers || []).length} pair(s) dans l'équipe)`,
        }),
        focusRow,
      ])
    );

    const reportsRow = el('div', { className: 'org-nodes-row' });
    if ((data.directReports || []).length === 0) {
      reportsRow.appendChild(
        el('span', {
          className: 'golink-mini-meta',
          text: 'Contributeur Individuel (IC) — aucun collaborateur N-1 rattaché directement.',
        })
      );
    } else {
      for (const r of data.directReports) {
        reportsRow.appendChild(createOrgNodeButton(r, false));
      }
    }
    tree.appendChild(
      el('div', { className: 'org-tier' }, [
        el('div', {
          className: 'org-tier-title',
          text: `Équipe Rattachée / Direct Reports N-1 (${(data.directReports || []).length})`,
        }),
        reportsRow,
      ])
    );

    if ((data.ownedGoLinks || []).length > 0) {
      const goRow = el('div', { className: 'org-nodes-row' });
      for (const g of data.ownedGoLinks) {
        goRow.appendChild(
          el('button', {
            className: 'citation-pill',
            text: `go/${g.slug} (${g.hits} clics)`,
            attrs: { type: 'button' },
            onClick: () => triggerGoLinkResolution(g.slug),
          })
        );
      }
      tree.appendChild(
        el('div', { className: 'org-tier' }, [
          el('div', {
            className: 'org-tier-title',
            text: `Raccourcis go/links administrés par @${p.ldap}`,
          }),
          goRow,
        ])
      );
    }

    orgContainer.appendChild(tree);
  }
}

function createOrgNodeButton(person, isCurrent) {
  return el(
    'button',
    {
      className: isCurrent ? 'org-node-card current-focus' : 'org-node-card',
      attrs: { type: 'button' },
      onClick: () => {
        appState.selectedPersonLdap = person.ldap;
        loadPeopleDirectory();
        loadPersonOrgChart(person.ldap, false);
      },
    },
    [
      createAvatar(person, false),
      el('div', {}, [
        el('div', {
          text: `${person.fullName} (@${person.ldap})`,
          style: { fontWeight: '700', fontSize: '0.82rem' },
        }),
        el('div', {
          text: `${person.title} • ${person.level}`,
          style: { fontSize: '0.74rem', color: '#475569' },
        }),
      ]),
    ]
  );
}

async function loadGoLinksRegistry() {
  const catSelect = document.getElementById('goCategoryFilter');
  const category = catSelect ? catSelect.value : '';
  const data = await apiFetch(`/api/golinks?category=${encodeURIComponent(category)}`);

  const wrapper = document.getElementById('goLinksTableContainer');
  if (!wrapper) return;
  wrapper.replaceChildren();

  const table = el('table', { className: 'golinks-table' });
  const thead = el('thead', {}, [
    el('tr', {}, [
      el('th', { text: 'Alias go/' }),
      el('th', { text: 'Titre & Destination' }),
      el('th', { text: 'Catégorie' }),
      el('th', { text: 'Owner' }),
      el('th', { text: 'Clics' }),
      el('th', { text: 'Actions' }),
    ]),
  ]);

  const tbody = el('tbody');
  for (const g of data.goLinks || []) {
    const canDelete =
      appState.currentUser &&
      (appState.currentUser.ldap === g.owner_ldap || appState.currentUser.role === 'admin');

    const tr = el('tr', {}, [
      el('td', {}, [
        el('button', {
          className: 'btn-link golink-slug',
          text: `go/${g.slug}`,
          attrs: { type: 'button' },
          onClick: () => triggerGoLinkResolution(g.slug),
        }),
      ]),
      el('td', {}, [
        el('div', { text: g.title, style: { fontWeight: '700' } }),
        el('div', { text: g.description, style: { fontSize: '0.78rem', color: '#475569' } }),
        el('div', {
          text: g.target_url,
          style: { fontSize: '0.72rem', color: '#64748b', fontFamily: 'monospace' },
        }),
      ]),
      el('td', {}, [el('span', { className: 'badge badge-blue', text: g.category })]),
      el('td', {}, [
        el('button', {
          className: 'btn-link',
          text: `@${g.owner_ldap}`,
          attrs: { type: 'button' },
          onClick: () => {
            appState.selectedPersonLdap = g.owner_ldap;
            switchView('teams');
          },
        }),
      ]),
      el('td', { text: String(g.hits), style: { fontWeight: '700' } }),
      el('td', {}, [
        el('div', { style: { display: 'flex', gap: '0.4rem' } }, [
          el('button', {
            className: 'btn-secondary btn-sm',
            text: 'Ouvrir',
            attrs: { type: 'button' },
            onClick: () => triggerGoLinkResolution(g.slug),
          }),
          canDelete
            ? el('button', {
                className: 'btn-danger',
                text: 'Suppr.',
                attrs: { type: 'button' },
                onClick: () => handleDeleteGoLink(g.slug),
              })
            : null,
        ]),
      ]),
    ]);
    tbody.appendChild(tr);
  }

  table.appendChild(thead);
  table.appendChild(tbody);
  wrapper.appendChild(table);
}

async function handleDeleteGoLink(slug) {
  try {
    await apiFetch('/api/golinks/delete', {
      method: 'POST',
      body: { slug },
    });
    showToast(`Raccourci go/${slug} supprimé.`);
    loadGoLinksRegistry();
    loadDashboard();
  } catch (err) {
    showToast(err.message);
  }
}

function renderBlueprintView() {
  const container = document.getElementById('blueprintContainer');
  if (!container) return;
  container.replaceChildren();

  const pillars = [
    {
      badge: 'Pilier 1 • Indexation Fédérée & Schéma Universel',
      title: 'Connecteurs Pluggables (SharePoint, Jira, ServiceNow, SAP, Workday, Custom API)',
      desc: 'Chez Google, Moma s’appuie sur un index unifié où chaque outil interne pousse ses données (ItemContent + ItemMetadata + ACLs). Pour un client externe, ce SDK de connecteurs permet d’ingérer ses propres outils (Microsoft 365, Atlassian, SAP, Salesforce ou API métier) sans dépendre des outils internes Google.',
    },
    {
      badge: 'Pilier 2 • Architecture Moma OneBox (Temps Réel)',
      title: 'Fédération Temps Réel & Cartes Structurées « OneBox »',
      desc: 'Lorsqu’un collaborateur tape une requête métier (ex: numéro de commande SAP, solde de congés Workday, astreinte On-Call, ou un mot-clé d’outil custom), le routeur OneBox interroge en parallèle l’API de l’outil cible et affiche une carte structurée au-dessus des résultats en < 150 ms.',
    },
    {
      badge: 'Pilier 3 • Contrôle d’Accès (Query-Time ACL Trimming)',
      title: 'Propagation d’Identité & Sécurité Zero-Trust avant l’IA',
      desc: 'Chaque document ou carte OneBox porte sa liste de contrôle d’accès (ACL) synchronisée depuis Entra ID / Okta / LDAP. Le filtrage s’exécute AVANT l’envoi du contexte au LLM : Gemini ne voit jamais un document auquel l’employé n’a pas accès.',
    },
    {
      badge: 'Pilier 4 • Synthèse IA Générative',
      title: 'Moma AI Overview propulsé par Gemini 3.8 Flash (@google/genai)',
      desc: 'Utilisation de l’API Interactions (client.interactions.create avec gemini-3.8-flash) ancrée exclusivement sur les extraits autorisés issus de tous les connecteurs actifs, avec citations numérotées [1], [2] et recommandation d’experts internes.',
    },
    {
      badge: 'Pilier 5 • Mécanisme go/links',
      title: 'Domaine DNS Interne "go" + Création Automatique par Outil',
      desc: 'Déploiement d’une entrée DHCP/DNS Search Domain (go.corp.internal). Chaque nouvel outil branché dans le Studio de Connecteurs reçoit automatiquement son raccourci go/<outil> en plus des liens créés par les équipes.',
    },
    {
      badge: 'Pilier 6 • Annuaire & Graphe Teams (Who’s Who)',
      title: 'Synchronisation SIRH (Workday / Entra ID) & Masquage PII',
      desc: 'Reconstitution temps réel de la chaîne de management (N+1, pairs, N-1), des badges culturels, des fuseaux horaires et des raccourcis go/ maintenus par chaque collaborateur, avec masquage PII par défaut.',
    },
  ];

  const grid = el('div', { className: 'blueprint-grid' });
  for (const p of pillars) {
    grid.appendChild(
      el('div', { className: 'card' }, [
        el('span', { className: 'badge badge-teal', text: p.badge }),
        el('h3', {
          className: 'card-title',
          text: p.title,
          style: { marginTop: '0.5rem', marginBottom: '0.45rem' },
        }),
        el('p', { className: 'doc-summary', text: p.desc }),
      ])
    );
  }

  container.appendChild(
    el('div', { className: 'card' }, [
      el('h2', {
        className: 'card-title',
        text: 'Blueprint d’Architecture Moma : Comment Adapter le Modèle Google aux Outils d’un Client',
      }),
      el('p', {
        className: 'card-subtitle',
        text: 'Ce portail implémente le pattern architectural exact de Moma (Index Unifié ACL + Routeur OneBox Temps Réel + AI Overview + Teams + go/links) tout en permettant au client d’intégrer ses propres outils dans l’onglet « Connecteurs & Outils Client ».',
      }),
      grid,
    ])
  );
}

/**
 * Phase 2: Predictive Instant Omnibox Typeahead & Operator Hints
 */
let typeaheadTimer = null;
function hideOmniboxTypeahead() {
  const dropdown = document.getElementById('omniboxTypeahead');
  if (dropdown) {
    dropdown.classList.add('hidden');
  }
}

async function handleOmniboxTypeahead(rawQuery) {
  const dropdown = document.getElementById('omniboxTypeahead');
  if (!dropdown) return;

  try {
    const data = await apiFetch(`/api/typeahead?q=${encodeURIComponent(rawQuery || '')}`);
    const suggestions = data.suggestions || [];
    const operatorHints = data.operatorHints || [];

    if (suggestions.length === 0 && operatorHints.length === 0) {
      dropdown.classList.add('hidden');
      return;
    }

    dropdown.replaceChildren();
    if (suggestions.length > 0) {
      dropdown.appendChild(
        el('div', {
          className: 'typeahead-group-title',
          text: 'Suggestions Instantanées Moma (go/links, Whatis, Teams, Documents ACL)',
        })
      );
      for (const item of suggestions) {
        const badgeClass =
          item.kind === 'golink'
            ? 'badge badge-green'
            : item.kind === 'whatis'
              ? 'badge badge-teal'
              : item.kind === 'person'
                ? 'badge badge-amber'
                : 'badge badge-blue';

        dropdown.appendChild(
          el(
            'button',
            {
              className: 'typeahead-item',
              attrs: { type: 'button', role: 'option' },
              onClick: () => {
                hideOmniboxTypeahead();
                if (item.kind === 'golink' && item.slug) {
                  triggerGoLinkResolution(item.slug);
                } else if (item.kind === 'person' && item.ldap) {
                  appState.selectedPersonLdap = item.ldap;
                  switchView('teams');
                } else {
                  const input = document.getElementById('globalSearchInput');
                  if (input) input.value = item.queryValue;
                  updateOmniboxBadge(item.queryValue);
                  switchView('home');
                  runFederatedSearch(item.queryValue, 'all');
                }
              },
            },
            [
              el('div', {}, [
                el('strong', { text: item.label, style: { color: '#0f172a' } }),
                el('span', {
                  text: ` — ${item.sublabel}`,
                  style: { color: '#475569', fontSize: '0.79rem' },
                }),
              ]),
              el('span', { className: badgeClass, text: item.badge }),
            ]
          )
        );
      }
    }

    if (operatorHints.length > 0) {
      const opsRow = el('div', { className: 'typeahead-operators-row' }, [
        el('span', {
          className: 'info-label',
          text: 'Opérateurs Moma :',
          style: { alignSelf: 'center', marginRight: '0.25rem' },
        }),
      ]);
      for (const op of operatorHints) {
        opsRow.appendChild(
          el('button', {
            className: 'operator-pill-btn',
            text: op.token,
            attrs: { type: 'button', title: op.desc },
            onClick: () => {
              const input = document.getElementById('globalSearchInput');
              if (input) {
                input.value = op.token;
                updateOmniboxBadge(op.token);
                input.focus();
              }
              hideOmniboxTypeahead();
              switchView('home');
              runFederatedSearch(op.token, 'all');
            },
          })
        );
      }
      dropdown.appendChild(opsRow);
    }

    dropdown.classList.remove('hidden');
  } catch {
    dropdown.classList.add('hidden');
  }
}

/**
 * Phase 2: 1-Click Approval Actions & Direct Ticket Creation Modal
 */
async function handleApprovalDecision(approvalKey, decision) {
  try {
    const res = await apiFetch('/api/approvals/act', {
      method: 'POST',
      body: { approvalKey, decision },
    });
    const label = res.approval.status === 'APPROVED' ? 'approuvée ✓' : 'refusée ✕';
    showToast(`Demande ${res.approval.approval_key} (${res.approval.source_system}) ${label}`);
    await loadDashboard();
  } catch (err) {
    showToast(err.message);
  }
}

function openQuickTicketModal(defaultTitle = '') {
  const titleInput = el('input', {
    className: 'form-input',
    attrs: {
      type: 'text',
      placeholder: 'ex: Demande d’accès VPN BeyondCorp ou renouvellement YubiKey',
      required: 'required',
      value: defaultTitle,
    },
  });
  const systemSelect = el('select', { className: 'form-select' }, [
    el('option', { text: 'ServiceNow ITSM (go/techstop)', attrs: { value: 'servicenow' } }),
    el('option', { text: 'Atlassian Jira Engineering (go/jira)', attrs: { value: 'jira' } }),
    el('option', { text: 'SAP S/4HANA & Ariba (go/sap)', attrs: { value: 'sap' } }),
  ]);
  const prioritySelect = el('select', { className: 'form-select' }, [
    el('option', { text: 'P2 — Standard (SLA 4h)', attrs: { value: 'P2' } }),
    el('option', { text: 'P1 — Critique / Bloquant (SLA 30 min)', attrs: { value: 'P1' } }),
    el('option', { text: 'P3 — Demande planifiée', attrs: { value: 'P3' } }),
  ]);
  const summaryInput = el('textarea', {
    className: 'form-textarea',
    attrs: {
      rows: '3',
      placeholder: 'Précisez le contexte technique ou métier pour l’équipe support...',
      required: 'required',
    },
  });

  const form = el('form', { className: 'golink-form' }, [
    el('label', { className: 'form-label', text: 'Outil cible connecté' }),
    systemSelect,
    el('label', { className: 'form-label', text: 'Objet du ticket / de la demande' }),
    titleInput,
    el('label', { className: 'form-label', text: 'Priorité SLA' }),
    prioritySelect,
    el('label', { className: 'form-label', text: 'Description & justification' }),
    summaryInput,
    el('button', {
      className: 'btn-primary btn-full',
      text: 'Créer le ticket directement depuis Moma',
      attrs: { type: 'submit', style: 'margin-top: 0.5rem' },
    }),
  ]);

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      const res = await apiFetch('/api/tickets/create', {
        method: 'POST',
        body: {
          connectorKey: systemSelect.value,
          title: titleInput.value,
          priority: prioritySelect.value,
          summary: summaryInput.value,
        },
      });
      closeModal();
      showToast(`Ticket ${res.ticket.ticket_key} créé dans ${res.ticket.source_system} !`);
      await loadDashboard();
      if (appState.activeQuery) {
        await runFederatedSearch(appState.activeQuery, appState.activeFacet);
      }
    } catch (err) {
      showToast(err.message);
    }
  });

  openModal('Action Directe Moma — Créer un Ticket IT / Engineering', form);
}

/**
 * Phase 2: Multi-Turn Conversational "Ask Moma" Follow-Up Handler
 */
async function handleAskMomaFollowUp(question) {
  try {
    const res = await apiFetch('/api/ai/chat', {
      method: 'POST',
      body: {
        question,
        previousInteractionId: appState.lastInteractionId,
        queryContext: appState.activeQuery,
      },
    });
    if (res.reply) {
      appState.lastInteractionId = res.reply.interactionId || null;
      appState.askMomaTurns.push(res.reply);
      if (appState.lastSearchPayload) {
        renderSearchResults(appState.lastSearchPayload);
      }
    }
  } catch (err) {
    showToast(err.message);
  }
}

/**
 * Phase 2: Whatis Acronym Decoder & Collaborative Glossary (View 5)
 */
async function loadWhatisGlossary() {
  const input = document.getElementById('whatisSearchInput');
  const q = input ? input.value.trim() : '';
  const data = await apiFetch(`/api/whatis?q=${encodeURIComponent(q)}`);

  const container = document.getElementById('whatisListContainer');
  if (!container) return;
  container.replaceChildren();

  for (const a of data.acronyms || []) {
    container.appendChild(
      el('div', { className: 'doc-item' }, [
        el('div', { className: 'doc-item-header' }, [
          el('div', {}, [
            el('span', { className: 'badge badge-teal', text: `whatis:${a.acronym}` }),
            el('strong', {
              text: ` ${a.acronym} — ${a.full_expansion}`,
              style: { marginLeft: '0.45rem', fontSize: '0.94rem' },
            }),
          ]),
          el('span', { className: 'badge badge-blue', text: a.category }),
        ]),
        el('p', { className: 'doc-summary', text: a.definition }),
        el('div', { className: 'doc-meta' }, [
          el('button', {
            className: 'btn-link',
            text: `Tester OneBox "whatis:${a.acronym}"`,
            attrs: { type: 'button' },
            onClick: () => {
              const sInput = document.getElementById('globalSearchInput');
              if (sInput) sInput.value = `whatis:${a.acronym}`;
              updateOmniboxBadge(`whatis:${a.acronym}`);
              switchView('home');
              runFederatedSearch(`whatis:${a.acronym}`, 'all');
            },
          }),
          a.go_link
            ? el('button', {
                className: 'btn-link',
                text: a.go_link,
                attrs: { type: 'button' },
                onClick: () => triggerGoLinkResolution(a.go_link),
              })
            : null,
          el('span', { text: `Ajouté par @${a.owner_ldap} (${a.updated_at})` }),
        ]),
      ])
    );
  }
}

async function bootstrapMomaApp() {
  try {
    const sessionData = await apiFetch('/api/session');
    appState.csrfToken = sessionData.csrfToken;
    appState.currentUser = sessionData.currentUser;
    appState.personas = sessionData.personas || [];

    renderHeaderUser();
    renderQuickQueryChips();
    await loadDashboard();

    const params = new URLSearchParams(window.location.search);
    const goResolved = params.get('goResolved');
    if (goResolved) {
      triggerGoLinkResolution(goResolved);
      window.history.replaceState({}, '', '/');
    }
  } catch (err) {
    showToast(err.message);
  }

  const brandBtn = document.getElementById('brandHomeBtn');
  if (brandBtn) {
    brandBtn.addEventListener('click', () => {
      const input = document.getElementById('globalSearchInput');
      if (input) input.value = '';
      updateOmniboxBadge('');
      switchView('home');
      runFederatedSearch('');
    });
  }

  const searchInput = document.getElementById('globalSearchInput');
  if (searchInput) {
    searchInput.addEventListener('focus', () => {
      handleOmniboxTypeahead(searchInput.value);
    });
    searchInput.addEventListener('input', (e) => {
      const val = e.target.value;
      updateOmniboxBadge(val);
      if (typeaheadTimer) clearTimeout(typeaheadTimer);
      typeaheadTimer = setTimeout(() => {
        handleOmniboxTypeahead(val);
      }, 90);
    });
  }

  document.addEventListener('click', (e) => {
    const wrapper = document.querySelector('.moma-omnibox-wrapper');
    if (wrapper && !wrapper.contains(e.target)) {
      hideOmniboxTypeahead();
    }
  });

  const searchForm = document.getElementById('globalSearchForm');
  if (searchForm) {
    searchForm.addEventListener('submit', (e) => {
      e.preventDefault();
      hideOmniboxTypeahead();
      const q = searchInput ? searchInput.value.trim() : '';
      switchView('home');
      runFederatedSearch(q, 'all');
    });
  }

  const clearSearchBtn = document.getElementById('clearSearchBtn');
  if (clearSearchBtn) {
    clearSearchBtn.addEventListener('click', () => {
      if (searchInput) searchInput.value = '';
      updateOmniboxBadge('');
      runFederatedSearch('');
    });
  }

  const openCreateTicketBtn = document.getElementById('openCreateTicketBtn');
  if (openCreateTicketBtn) {
    openCreateTicketBtn.addEventListener('click', () => openQuickTicketModal(''));
  }

  const searchCreateTicketBtn = document.getElementById('searchCreateTicketBtn');
  if (searchCreateTicketBtn) {
    searchCreateTicketBtn.addEventListener('click', () =>
      openQuickTicketModal(appState.activeQuery ? `Support : ${appState.activeQuery}` : '')
    );
  }

  document.addEventListener('keydown', (e) => {
    if (
      e.key === '/' &&
      document.activeElement &&
      !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)
    ) {
      e.preventDefault();
      if (searchInput) searchInput.focus();
    } else if (e.key === 'Escape') {
      closeModal();
      hideOmniboxTypeahead();
    }
  });

  document.querySelectorAll('.nav-tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetView = btn.getAttribute('data-view');
      if (targetView) switchView(targetView);
    });
  });

  const openGoLinksBtn = document.getElementById('openGoLinksViewBtn');
  if (openGoLinksBtn) {
    openGoLinksBtn.addEventListener('click', () => switchView('golinks'));
  }

  const openConnectorsBtn = document.getElementById('openConnectorsViewBtn');
  if (openConnectorsBtn) {
    openConnectorsBtn.addEventListener('click', () => switchView('connectors'));
  }

  const personaSelect = document.getElementById('personaSelect');
  if (personaSelect) {
    personaSelect.addEventListener('change', async (e) => {
      try {
        const res = await apiFetch('/api/auth/switch-persona', {
          method: 'POST',
          body: { ldap: e.target.value },
        });
        appState.currentUser = res.currentUser;
        renderHeaderUser();
        showToast(res.message);
        await loadDashboard();
        if (appState.activeQuery) {
          await runFederatedSearch(appState.activeQuery, appState.activeFacet);
        }
        if (appState.activeView === 'golinks') {
          await loadGoLinksRegistry();
        }
      } catch (err) {
        showToast(err.message);
      }
    });
  }

  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      try {
        await apiFetch('/api/auth/logout', { method: 'POST' });
      } finally {
        appState.csrfToken = null;
        appState.currentUser = null;
        appState.lastSearchPayload = null;
        window.location.href = '/';
      }
    });
  }

  // Custom Tool Connector Registration Form
  const createConnectorForm = document.getElementById('createConnectorForm');
  if (createConnectorForm) {
    createConnectorForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        name: document.getElementById('connNameInput').value,
        connectorKey: document.getElementById('connKeyInput').value,
        vendor: document.getElementById('connVendorInput').value,
        protocol: document.getElementById('connProtocolInput').value,
        baseUrl: document.getElementById('connUrlInput').value,
        oneboxTrigger: document.getElementById('connTriggerInput').value,
        visibilityDept: document.getElementById('connDeptInput').value,
        oneboxMetricLabel: document.getElementById('connMetricLabelInput').value,
        oneboxMetricValue: document.getElementById('connMetricValueInput').value,
        sampleTitle: document.getElementById('connSampleTitleInput').value,
        sampleContent: document.getElementById('connSampleContentInput').value,
      };
      try {
        const res = await apiFetch('/api/connectors/custom', {
          method: 'POST',
          body: payload,
        });
        showToast(
          `Outil "${res.connector.name}" intégré avec OneBox et raccourci go/${res.connector.connectorKey} !`
        );
        createConnectorForm.reset();
        await loadConnectorsHub();
        await loadDashboard();
      } catch (err) {
        showToast(err.message);
      }
    });
  }

  const peopleSearchInput = document.getElementById('peopleSearchInput');
  const peopleDeptSelect = document.getElementById('peopleDeptSelect');
  if (peopleSearchInput) {
    peopleSearchInput.addEventListener('input', () => loadPeopleDirectory());
  }
  if (peopleDeptSelect) {
    peopleDeptSelect.addEventListener('change', () => loadPeopleDirectory());
  }

  const goCategoryFilter = document.getElementById('goCategoryFilter');
  if (goCategoryFilter) {
    goCategoryFilter.addEventListener('change', () => loadGoLinksRegistry());
  }

  const goQuickTestForm = document.getElementById('goQuickTestForm');
  if (goQuickTestForm) {
    goQuickTestForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const input = document.getElementById('goQuickTestInput');
      if (input && input.value.trim()) {
        triggerGoLinkResolution(input.value.trim());
      }
    });
  }

  const createGoLinkForm = document.getElementById('createGoLinkForm');
  if (createGoLinkForm) {
    createGoLinkForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const slug = document.getElementById('goSlugInput').value;
      const targetUrl = document.getElementById('goTargetInput').value;
      const title = document.getElementById('goTitleInput').value;
      const category = document.getElementById('goCategoryInput').value;
      const description = document.getElementById('goDescInput').value;

      try {
        const res = await apiFetch('/api/golinks', {
          method: 'POST',
          body: { slug, targetUrl, title, category, description },
        });
        showToast(`Raccourci go/${res.goLink.slug} enregistré avec succès !`);
        createGoLinkForm.reset();
        loadGoLinksRegistry();
        loadDashboard();
      } catch (err) {
        showToast(err.message);
      }
    });
  }

  // Whatis Acronym Glossary Search & Creation Form
  const whatisSearchInput = document.getElementById('whatisSearchInput');
  if (whatisSearchInput) {
    whatisSearchInput.addEventListener('input', () => loadWhatisGlossary());
  }

  const createWhatisForm = document.getElementById('createWhatisForm');
  if (createWhatisForm) {
    createWhatisForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const acronym = document.getElementById('whatisAcronymInput').value;
      const fullExpansion = document.getElementById('whatisExpansionInput').value;
      const category = document.getElementById('whatisCategoryInput').value;
      const goLink = document.getElementById('whatisGoLinkInput').value;
      const definition = document.getElementById('whatisDefInput').value;

      try {
        const res = await apiFetch('/api/whatis', {
          method: 'POST',
          body: { acronym, fullExpansion, category, goLink, definition },
        });
        showToast(`Acronyme "${res.acronym.acronym}" publié dans go/whatis !`);
        createWhatisForm.reset();
        await loadWhatisGlossary();
      } catch (err) {
        showToast(err.message);
      }
    });
  }

  const modalCloseBtn = document.getElementById('modalCloseBtn');
  if (modalCloseBtn) {
    modalCloseBtn.addEventListener('click', () => closeModal());
  }
}

document.addEventListener('DOMContentLoaded', bootstrapMomaApp);
