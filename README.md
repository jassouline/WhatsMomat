# Moma-bis — Enterprise Intranet, Federated Search, Teams Org Chart & `go/links`

**Moma-bis** est une implémentation de référence (Architecture + Prototype Full-Stack sécurisé) qui reproduit les mécanismes emblématiques de **Moma**, le portail interne de Google, afin de permettre à une entreprise cliente de déployer la même expérience pour son IT interne.

---

## Fonctionnalités Clés Répliquées

1. **Recherche Fédérée Sensible aux Droits (Identity-Aware Search) + AI Overview (`gemini-3.8-flash`)**
   - Recherche unifiée à travers les politiques RH/IT, runbooks SRE, personnes (*Teams*), raccourcis `go/` et tickets ITSM.
   - **Filtrage ACL (ACL Trimming)** : les documents restreints (ex: *SecOps Confidentiel* ou *Grille Rémunération RH*) sont automatiquement filtrés avant même d'être transmis au modèle IA selon le profil actif.
   - **Moma AI Overview** : synthèse générative sourcée avec citations cliquables `[1]`, `[2]` propulsée par le SDK officiel `@google/genai` (`client.interactions.create` avec `gemini-3.8-flash`) lorsque `GEMINI_API_KEY` est défini, ou par le moteur RAG déterministe embarqué hors-ligne.

2. **Annuaire & Organigramme Interactif (*Moma Teams / Who's Who*)**
   - Fiches collaborateurs enrichies : niveau (`L4` à `L9`), badges culturels (*Noogler*, *Security Champion*, *On-Call Primary*, *Bar Raiser*), compétences, projets/OKRs, fuseau horaire et bureau.
   - **Graphe hiérarchique cliquable** : navigation instantanée dans la chaîne de management Ascendants (`N+2` / `N+1`) → Collaborateur & Pairs → Équipe rattachée (`N-1`) → Raccourcis `go/` maintenus.
   - **Protection de la vie privée (PII Masking)** : masquage par défaut des coordonnées (`j***e@corp.internal`, `***-***-5412`) avec révélation explicite journalisée.

3. **Système de Raccourcis Internes `go/links` (`http://go/<alias>`)**
   - Résolution directe via `/go/<alias>` (ex: `go/vpn`, `go/oncall`, `go/new-laptop`, `go/okrs`, `go/perks`, `go/holiday`).
   - Compteur d'utilisation en temps réel, création/mise à jour de raccourcis et contrôle strict de propriété (seul le propriétaire `@ldap` ou un `admin` peut modifier ou supprimer un lien `go/`).

---

## Démarrage Rapide

Prérequis : **Node.js >= 22.5** (utilise les modules natifs `node:http`, `node:sqlite`, `node:crypto` — aucune dépendance externe obligatoire).

```bash
# Lancer le serveur sur http://127.0.0.1:3000
npm start

# (Optionnel) Activer Gemini 3.8 Flash en direct via @google/genai
GEMINI_API_KEY="votre_cle_api" npm start

# Exécuter la suite de tests fonctionnels et de sécurité
npm test
```

---

## Sécurité par Construction (Secure-by-Design)

- **Serveur BFF Durci** ([`server.js`](file:///Users/jassouline/Desktop/git/momabis/server.js)) : écoute exclusive sur `127.0.0.1`, liste blanche des méthodes HTTP (`GET`, `POST`), Rate Limiting par IP, en-têtes `Content-Security-Policy` à **nonce cryptographique** par requête, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Permissions-Policy`.
- **Sessions & CSRF** : cookies `__Secure-moma_sid` (`HttpOnly`, `SameSite=Strict`, durée de vie finie 30 min) et validation par jeton synchronisé `X-CSRF-Token` en temps constant (`crypto.timingSafeEqual`).
- **Base de données SQLite** ([`src/db.js`](file:///Users/jassouline/Desktop/git/momabis/src/db.js)) : 100 % des requêtes utilisent des requêtes préparées paramétrées (`db.prepare()`), hachage de mots de passe via `crypto.scryptSync` avec sel aléatoire par utilisateur.
- **Frontend Zéro-XSS** ([`public/app.js`](file:///Users/jassouline/Desktop/git/momabis/public/app.js)) : manipulation DOM exclusivement via `document.createElement`, `textContent` et `replaceChildren` (zéro `innerHTML`, zéro `localStorage`, zéro `alert()`).
