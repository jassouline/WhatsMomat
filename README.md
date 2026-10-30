# WhatsMomat — Portail Intranet, Recherche Hybride RRF, OneBox, IA, SCIM & `go/links` (inspiré de Google Moma)

**WhatsMomat** (`v1.2`) est une implémentation de référence complète, portable et sécurisée qui reproduit l'expérience et l'architecture de **Moma**, le portail intranet et moteur de recherche interne de Google, conçue pour permettre à une entreprise cliente d'y connecter **ses propres outils IT et métiers** (ServiceNow, SharePoint, Atlassian Jira/Confluence, SAP S/4HANA, Workday, GitLab, Salesforce, APIs internes).

---

## Fonctionnalités Clés

1. **Recherche Hybride Fédérée (*BM25 + Vecteurs Sémantiques RRF*) Sensible aux Droits (*ACL Trimming*)**
   - Fusion par **Reciprocal Rank Fusion (RRF)** de l'index plein-texte **SQLite `FTS5` (`bm25`)** et d'embeddings vectoriels (`gemini-embedding-2` via `@google/genai`, avec repli automatique sur un espace sémantique multilingue 256-D hors-ligne dans `src/embeddings.js`). Retrouve un document RH ou IT pertinent même sans aucun mot-clé exact en commun !
   - Opérateurs Moma (`owner:sophiel`, `source:servicenow`, `type:documents`, `whatis:GRAD`) et **ACL Trimming strict avant IA** : les documents non autorisés et les connecteurs désactivés sont écartés avant tout envoi au LLM.

2. **Intégration Barre d'Adresse Navigateur (`opensearch.xml` + Extension Chrome/Edge MV3 `go/`)**
   - Découverte native **OpenSearch** (`GET /opensearch.xml` + autocomplétion temps réel `GET /api/opensearch-suggest`) permettant de taper `moma <Tab> <requête>` directement dans la barre d'adresse Chrome, Edge ou Firefox.
   - Extension navigateur prête à déployer dans [`browser-extension/`](file:///Users/jassouline/Desktop/git/momabis/browser-extension/README.md) (Manifest V3 `declarativeNetRequest` + `omnibox`) interceptant `http://go/<alias>` vers `/go/<alias>` sans modification DNS/DHCP.

3. **Moma OneBox Temps Réel (Sortant Anti-SSRF), Webhooks d'Approbation Signés & `/api/v1/ingest`**
   - Cartes **Moma OneBox** au-dessus des résultats + fédération sortante temps réel (`live_endpoint_url` dans `src/outbound.js`, durcie anti-SSRF avec blocage `169.254.169.254`/RFC1918, `redirect: 'error'` et *circuit-breaker* 1,5 s).
   - **Webhooks d'action 1-clic signés HMAC-SHA256** (`X-WhatsMomat-Signature`) lors d'une approbation/rejet dans *My Moma*, et **API REST d'ingestion** (`POST /api/v1/ingest`).

4. **Moma AI Overview & Assistant Conversationnel Multi-Tours *Ask Moma***
   - Synthèse sourcée avec citations cliquables `[1]`, `[2]` et questions de suivi multi-tours (`previous_interaction_id`) propulsées par `@google/genai` (**Interactions API**, modèle `gemini-3.8-flash` par défaut, configurable via `GEMINI_MODEL`), avec bascule transparente hors-ligne.

5. **Synchronisation d'Identités SCIM 2.0 (`Okta` / `Entra ID` / `Workday`) & Sessions SQLite**
   - Endpoint standard `GET / POST /api/v1/scim/v2/Users` (`application/scim+json`, `Bearer ${SCIM_API_TOKEN}`) pour provisionner/mettre à jour les collaborateurs et **révoquer instantanément toutes les sessions SQLite actives** lorsqu'un compte passe à `active: false`.

6. **Annuaire *Moma Teams*, Culture *Peer Kudos* (`go/kudos`), Favoris Épinglés & Fraîcheur Documentaire**
   - Organigramme interactif (`N+1`, pairs, `N-1`), masquage PII audité (`PII_REVEAL`), reconnaissance entre pairs **Peer Kudos** (`go/kudos`), épinglage personnel de raccourcis `go/links` sur *My Moma*, et lecteur intégral ACL avec signalement d'obsolescence documentaire (*g3doc freshness*).

---

## Démarrage Rapide (Local)

Prérequis : **Node.js >= 22.5** (utilise nativement `node:http`, `node:sqlite` + `FTS5`, `node:crypto`, `node:dns`).

```bash
# (Optionnel) Installer le SDK officiel @google/genai pour Gemini Interactions API & gemini-embedding-2
npm install

# Démarrer le portail sur http://127.0.0.1:3000 (base SQLite WAL persistante dans ./data/whatsmomat.sqlite)
npm start

# Démarrer avec Gemini Interactions API + Embeddings activés en direct
GEMINI_API_KEY="votre_cle_api" npm start

# Exécuter les 22 suites de tests fonctionnels, Hybride RRF, OpenSearch, SCIM, Anti-SSRF, BOLA & Sécurité
npm test
```

---

## Pousser les Données (`POST /api/v1/ingest`) & Synchroniser l'Annuaire (`POST /api/v1/scim/v2/Users`)

```bash
# 1. Ingestion temps réel d'un document ACL + ticket + OneBox (indexé automatiquement en FTS5 + Vecteurs)
curl -X POST http://127.0.0.1:3000/api/v1/ingest \
  -H "Authorization: Bearer ${INGEST_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "connectorKey": "servicenow",
    "documents": [{
      "docCode": "SN-KB-901",
      "title": "Procédure Enrôlement Clé Matérielle FIDO2",
      "content": "Rendez-vous au comptoir go/techstop muni de votre badge collaborateur.",
      "tags": ["fido2", "yubikey", "securite"],
      "visibilityDept": "ALL"
    }]
  }'

# 2. Provisioning ou désactivation SCIM 2.0 (Okta / Microsoft Entra ID / Workday)
curl -X POST http://127.0.0.1:3000/api/v1/scim/v2/Users \
  -H "Authorization: Bearer ${SCIM_API_TOKEN}" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "externalId": "lucasv",
    "userName": "lucasv@corp.internal",
    "active": true,
    "name": { "formatted": "Lucas Vasseur" },
    "title": "Cloud Architect",
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
      "department": "Engineering",
      "organization": "Cloud Platform"
    }
  }'
```

---

## Déploiement Conteneurisé & Production Zero-Trust (IAP)

```bash
docker build -t whatsmomat:1.2 .

docker run -d \
  -p 127.0.0.1:3000:3000 \
  -v whatsmomat_data:/app/data \
  -e HOST=0.0.0.0 \
  -e NODE_ENV=production \
  -e AUTH_MODE=iap \
  -e SESSION_SECRET="$(openssl rand -hex 32)" \
  -e INGEST_API_TOKEN="$(openssl rand -hex 24)" \
  -e SCIM_API_TOKEN="$(openssl rand -hex 24)" \
  whatsmomat:1.2
```

---

## Architecture de Sécurité (*Secure-by-Design*)

- **Serveur BFF Durci** ([`server.js`](file:///Users/jassouline/Desktop/git/momabis/server.js)) : écoute par défaut sur `127.0.0.1`, liste blanche des méthodes HTTP (`GET`, `POST`), Rate Limiting par IP, `Content-Security-Policy` stricte à **nonce cryptographique** (`style-src 'self'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, CORS par liste blanche.
- **Sessions SQLite Révocables, CSRF & Secrets** : cookies `__Secure-moma_sid` persistés en SQLite avec révocation immédiate au logout ou sur `active: false` SCIM 2.0, jeton `X-CSRF-Token` vérifié via `crypto.timingSafeEqual`, zéro secret codé en dur.
- **Protection Anti-SSRF Sortante** ([`src/outbound.js`](file:///Users/jassouline/Desktop/git/momabis/src/outbound.js)) : validation syntaxique et résolution DNS préalable bloquant `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254` (Cloud Metadata) et `fe80::/10`, `redirect: 'error'`, plafond de réponse 16 Ko et timeout 1,5 s.
- **Contrôle d'Accès (BOLA / ACL) & Frontend Zéro-XSS** ([`src/db.js`](file:///Users/jassouline/Desktop/git/momabis/src/db.js), [`public/app.js`](file:///Users/jassouline/Desktop/git/momabis/public/app.js)) : requêtes SQLite 100 % paramétrées, contrôle ACL sur la recherche hybride et le lecteur intégral `GET /api/documents/:docCode`, DOM construit exclusivement via `createElement` / `textContent`.
