# Extension Navigateur Chrome / Edge (Manifest V3) — WhatsMomat `go/` & Omnibox

Chez Google, les collaborateurs tapent directement `go/okrs` ou `moma <Tab> <requête>` dans la barre d'adresse de Chrome. Cette extension **Manifest V3** apporte exactement cette expérience à **WhatsMomat** sans nécessiter de modification DNS sur le poste de démonstration.

## Fonctionnalités
1. **Redirection native `http://go/<alias>`** via `declarativeNetRequest` ([`rules.json`](./rules.json)) vers `http://127.0.0.1:3000/go/<alias>`.
2. **Mot-clé Omnibox `moma`** ([`background.js`](./background.js)) : tapez `moma` puis `Tab` dans la barre d'adresse pour obtenir les suggestions temps réel (`/api/opensearch-suggest`) filtrées selon vos ACLs.

## Installation en 30 secondes (Chrome / Brave / Edge)
1. Ouvrez `chrome://extensions` (ou `edge://extensions`).
2. Activez le **Mode développeur** en haut à droite.
3. Cliquez sur **Charger l'extension non empaquetée** (*Load unpacked*) et sélectionnez ce dossier `browser-extension/`.
4. Pour un déploiement entreprise, remplacez `http://127.0.0.1:3000` dans `manifest.json`, `rules.json` et `background.js` par votre domaine intranet HTTPS (ex: `https://moma.entreprise.fr`).
