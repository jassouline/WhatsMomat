# WhatsMomat — Portail Intranet, Recherche Fédérée ACL, OneBox, IA & `go/links` (inspiré de Google Moma)

**WhatsMomat** (`v1.1`) est une implémentation de référence complète, portable et sécurisée qui reproduit l'expérience et l'architecture de **Moma**, le portail intranet et moteur de recherche interne de Google, conçue pour permettre à une entreprise cliente d'y connecter **ses propres outils IT et métiers** (ServiceNow, SharePoint, Atlassian Jira/Confluence, SAP S/4HANA, Workday, GitLab, Salesforce, APIs internes).

---

## Fonctionnalités Clés

1. **Recherche Fédérée Sensible aux Droits (*Identity-Aware Search*) & Index `FTS5` BM25**
   - Indexation plein-texte native via **SQLite `FTS5` (`bm25`)** combinée aux opérateurs Moma (`owner:sophiel`, `source:servicenow`, `type:documents`, `whatis:GRAD`) et à l'autocomplétion prédictive dans l'Omnibox (raccourci clavier `/`).
   - **ACL Trimming strict avant IA** : les documents restreints (*SecOps Confidentiel*, *Grille Rémunération RH*) et les connecteurs désactivés sont filtrés au moment de la requête **avant** tout envoi au modèle génératif.

2. **Moma OneBox & Studio d'Intégration d'Outils Clients + API REST `/api/v1/ingest`**
   - Cartes temps réel **Moma OneBox** au-dessus des résultats (statut SLA ServiceNow, soldes congés Workday, commandes d'achat SAP Ariba, décodeur d'acronymes *Whatis*, ou métriques d'outils personnalisés).
   - **Connector Studio** interactif pour brancher un outil tiers en 30 secondes + **API REST d'ingestion temps réel** (`POST /api/v1/ingest`) permettant aux webhooks CI/CD, scripts Python ou connecteurs d'entreprise de pousser documents ACL, tickets et cartes OneBox.

3. **Moma AI Overview & Assistant Conversationnel Multi-Tours *Ask Moma***
   - Synthèse sourcée avec citations cliquables `[1]`, `[2]` et questions de suivi multi-tours (`previous_interaction_id`) propulsées par le SDK officiel `@google/genai` (**Interactions API**, modèle `gemini-3.7-flash` par défaut, configurable via `GEMINI_MODEL`).
   - Bascule automatique et transparente sur le **moteur RAG déterministe embarqué** lorsque `GEMINI_API_KEY` n'est pas renseigné (100 % fonctionnel hors-ligne).

4. **Annuaire & Organigramme Interactif (*Moma Teams / Who's Who*)**
   - Fiches collaborateurs enrichies : niveau (`L4`–`L9`), statut de présence en direct, localisation bureau/étage, groupes IAM, badges culturels, compétences et OKRs.
   - Navigation hiérarchique cliquable (`N+2` / `N+1` → Pairs → Équipe `N-1` → liens `go/` détenus) et **masquage PII par défaut** (`j***e@corp.internal`, `***-***-5412`) avec journalisation d'audit (`PII_REVEAL`) lors d'une révélation explicite.

5. **Raccourcis Internes `go/links` (`http://go/<alias>`) & Décodeur *Whatis* (`go/whatis`)**
   - Résolution directe via `/go/<alias>` : redirection HTTP `302` réelle vers les URLs externes accessibles (ou forcée via `GO_REDIRECT_MODE=302` / `?redirect=1`) et modale interactive pour les domaines de démo `.corp.internal`.
   - Glossaire collaboratif **Whatis** avec recherche par catégorie, votes et déclenchement automatique d'une OneBox sur `whatis:<TERME>`.

6. **Espace Personnel *My Moma* Actionnable**
   - Centre d'approbations 1-clic protégé contre les accès transverses (**contrôle BOLA** : seul l'approbateur désigné ou un administrateur peut statuer), agenda personnel filtré par participant, création directe de tickets IT et menu cafétéria adapté au campus de l'utilisateur (Paris, Zurich, Londres).

---

## Démarrage Rapide (Local)

Prérequis : **Node.js >= 22.5** (utilise nativement `node:http`, `node:sqlite` + `FTS5`, `node:crypto`).

```bash
# (Optionnel) Installer le SDK officiel @google/genai pour l'IA générative live
npm install

# Démarrer le portail sur http://127.0.0.1:3000 (base SQLite persistante dans ./data/whatsmomat.sqlite)
npm start

# Démarrer avec Gemini Interactions API activée en direct
GEMINI_API_KEY="votre_cle_api" npm start

# Exécuter la suite complète de tests fonctionnels, BOLA, FTS5, Ingestion & Sécurité (en base :memory: isolée)
npm test
```

---

## Pousser les Données de Vos Propres Outils (`POST /api/v1/ingest`)

Définissez un jeton connecteur (`INGEST_API_TOKEN`, ≥ 24 caractères) au démarrage du serveur, puis poussez vos documents ACL, tickets ou indicateurs OneBox depuis n'importe quel outil interne (GitLab CI, ServiceNow, Jira, Airflow, script Python) :

```bash
curl -X POST http://127.0.0.1:3000/api/v1/ingest \
  -H "Authorization: Bearer ${INGEST_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "connectorKey": "servicenow",
    "documents": [
      {
        "docCode": "SN-KB-901",
        "title": "Procédure Enrôlement Clé Matérielle FIDO2",
        "content": "Rendez-vous au comptoir go/techstop muni de votre badge collaborateur.",
        "tags": ["fido2", "yubikey", "securite"],
        "visibilityDept": "ALL"
      }
    ],
    "tickets": [
      {
        "ticketKey": "INC-7781",
        "title": "Latence passerelle OData EMEA",
        "status": "En cours",
        "priority": "P1 - Critique",
        "summary": "Investigation conjointe SRE & réseau."
      }
    ],
    "oneboxCard": {
      "cardTitle": "ServiceNow ITSM — Statut Temps Réel",
      "fields": [
        { "label": "Disponibilité SLA", "value": "99.98% (Temps d’attente TechStop : 4 min)" }
      ]
    }
  }'
```

---

## Déploiement Conteneurisé & Production Zero-Trust (IAP)

```bash
# Construire l'image Docker durcie (utilisateur non-root `node`, volume /app/data)
docker build -t whatsmomat:1.1 .

# Lancer avec persistance SQLite, secret de session et mode production IAP
docker run -d \
  -p 127.0.0.1:3000:3000 \
  -v whatsmomat_data:/app/data \
  -e HOST=0.0.0.0 \
  -e NODE_ENV=production \
  -e AUTH_MODE=iap \
  -e SESSION_SECRET="$(openssl rand -hex 32)" \
  -e INGEST_API_TOKEN="$(openssl rand -hex 24)" \
  whatsmomat:1.1
```

Lorsque `AUTH_MODE=iap` est activé derrière un reverse-proxy d'entreprise (Google Cloud Identity-Aware Proxy, Envoy/Pomerium, Okta Access Gateway) :
- Le sélecteur de personas de démonstration est **verrouillé** (`403 Forbidden` côté serveur et désactivé dans l'UI).
- L'identité collaborateur est résolue depuis l'en-tête vérifié `X-Goog-Authenticated-User-Email` (ou `X-Forwarded-User`) en mode *fail-closed* (`401 Unauthorized` si absent).

---

## Architecture de Sécurité (*Secure-by-Design*)

- **Serveur BFF Durci** ([`server.js`](file:///Users/jassouline/Desktop/git/momabis/server.js)) : écoute par défaut sur `127.0.0.1`, liste blanche des méthodes HTTP (`GET`, `POST`), Rate Limiting par IP, `Content-Security-Policy` stricte à **nonce cryptographique** par requête (`style-src 'self'` sans attributs `style` inline), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, CORS par liste blanche explicite.
- **Sessions, CSRF & Secrets** : cookies `__Secure-moma_sid` (`HttpOnly`, `SameSite=Strict`, `Secure` en production, TTL 30 min), jeton synchronisé `X-CSRF-Token` vérifié avec `crypto.timingSafeEqual`, aucun secret codé en dur (`SESSION_SECRET` obligatoire en `NODE_ENV=production`).
- ** Contrôle d'Accès & Audit** ([`src/db.js`](file:///Users/jassouline/Desktop/git/momabis/src/db.js)) : requêtes SQLite 100 % paramétrées (`db.prepare()`), contrôle d'autorisation ressource par ressource (ACL documents, propriété `go/links`, BOLA sur `actOnApproval`), et journalisation dans `audit_logs` consultable via `GET /api/audit-logs` par les profils `admin` et `security_admin`.
- **Frontend Zéro-XSS** ([`public/app.js`](file:///Users/jassouline/Desktop/git/momabis/public/app.js)) : construction DOM exclusive via `document.createElement`, `textContent` et `replaceChildren` (zéro `innerHTML`, zéro `localStorage`/`sessionStorage`, zéro `alert()`).
