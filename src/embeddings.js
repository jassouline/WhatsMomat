/**
 * WhatsMomat Hybrid Vector Embedding & Reciprocal Rank Fusion (RRF) Engine
 *
 * - Supports live Gemini Embeddings (`gemini-embedding-2` or `gemini-embedding-001`) via `@google/genai`
 *   when `GEMINI_API_KEY` is configured.
 * - Provides a fast, deterministic 256-dimensional L2-normalized multilingual semantic + n-gram vector
 *   fallback so hybrid semantic search works out-of-the-box offline and in CI tests.
 */

export const EMBEDDING_DIM = 256;
export const DEFAULT_EMBEDDING_MODEL = process.env.GEMINI_EMBEDDING_MODEL || 'gemini-embedding-2';

/**
 * Curated bilingual (FR/EN) enterprise concept clusters mapped onto dedicated semantic dimensions (0..31).
 * Enables zero-keyword-overlap semantic retrieval even when running offline without GEMINI_API_KEY
 * (e.g., "fauteuil mal de dos maison" -> matches WFH 500€ ergonomic equipment policy).
 */
const ENTERPRISE_CONCEPT_CLUSTERS = [
  ['teletravail', 'remote', 'hybride', 'domicile', 'maison', 'wfh', 'wfa', 'chaise', 'fauteuil', 'ecran', 'ergonomique', 'mal de dos', 'equipement', 'bureau maison', '500'],
  ['conges', 'vacances', 'rtt', 'absence', 'repos', 'ferie', 'holiday', 'cet', 'solde', 'time off', 'pto'],
  ['laptop', 'macbook', 'ordinateur', 'portable', 'poste', 'machine', 'materiel', 'thinkpad', 'linux', 'chromebook', 'renouvellement', 'techstop', 'cmdb', 'station'],
  ['vpn', 'beyondcorp', 'zero-trust', 'iap', 'acces distant', 'externe', 'tunnel', 'certificat', 'fido2', 'titan', 'yubikey', 'mfa', 'authentification'],
  ['oncall', 'astreinte', 'incident', 'panne', 'urgence', 'alerte', 'p0', 'p1', 'sre', 'post-mortem', 'slo', 'sla', 'pagerduty', 'indisponibilite'],
  ['sap', 'ariba', 'achat', 'commande', 'fournisseur', 'facture', 'devis', 'po', 'bon de commande', 'note de frais', 'remboursement', 'depense', 'budget', 'sepa', 'finance'],
  ['salaire', 'remuneration', 'augmentation', 'prime', 'bonus', 'promotion', 'evaluation', 'carriere', 'grad', 'calibration', 'grille'],
  ['secops', 'cyber', 'securite', 'compromission', 'fuite', 'piratage', 'phishing', 'kms', 'rotation', 'siem', 'forensique', 'isolation', 'cert'],
  ['moma', 'architecture', 'onebox', 'connecteur', 'index', 'federation', 'acl', 'sharepoint', 'confluence', 'servicenow', 'workday', 'salesforce'],
  ['gemini', 'ia', 'ai', 'rag', 'embedding', 'vecteur', 'llm', 'genai', 'prompt', 'interactions', 'sandbox'],
  ['okr', 'objectif', 'strategie', 'trimestre', 'q4', 'resultat cle', 'feuille de route', 'roadmap'],
  ['onboarding', 'noogler', 'nouvel arrivant', 'integration', 'buddy', 'embauche', 'recrutement', 'periode essai'],
  ['cafeteria', 'menu', 'repas', 'dejeuner', 'barista', 'cafe', 'vegetarien', 'campus', 'cantine', 'micro-kitchen'],
  ['kudos', 'reconnaissance', 'merci', 'bravo', 'peer bonus', 'felicitations', 'recompense', 'culture'],
  ['scim', 'annuaire', 'organigramme', 'teams', 'ldap', 'manager', 'equipe', 'okta', 'entra', 'identite'],
  ['gitlab', 'github', 'code', 'merge request', 'pull request', 'ci', 'cd', 'revue', 'lgtm', 'deploy'],
];

const STOPWORDS = new Set([
  'le', 'la', 'les', 'un', 'une', 'des', 'du', 'de', 'd', 'et', 'ou', 'a', 'au', 'aux',
  'en', 'dans', 'sur', 'pour', 'par', 'avec', 'sans', 'ce', 'ces', 'cet', 'cette', 'mon',
  'ma', 'mes', 'ton', 'ta', 'tes', 'son', 'sa', 'ses', 'notre', 'votre', 'leur', 'qui',
  'que', 'quoi', 'dont', 'ou', 'est', 'sont', 'etre', 'avoir', 'faire', 'plus', 'comment',
  'the', 'and', 'for', 'with', 'from', 'that', 'this', 'how', 'what', 'where', 'who',
]);

export function normalizeSemanticText(rawText) {
  return String(rawText || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9\s/-]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function fnv1aHash(str, seed = 2166136261) {
  let h = seed >>> 0;
  for (let i = 0; i < str.length; i += 1) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}

export function l2Normalize(vec) {
  let sumSq = 0;
  for (let i = 0; i < vec.length; i += 1) {
    sumSq += vec[i] * vec[i];
  }
  if (sumSq <= 1e-12) {
    return Array.from(vec);
  }
  const invNorm = 1 / Math.sqrt(sumSq);
  const out = new Array(vec.length);
  for (let i = 0; i < vec.length; i += 1) {
    out[i] = Number((vec[i] * invNorm).toFixed(6));
  }
  return out;
}

/**
 * Deterministic 256-D local semantic + character n-gram feature hashing vector.
 * Dimensions 0..31 encode curated enterprise semantic concepts;
 * Dimensions 32..255 encode signed random projections of word stems, bigrams, and 4-char n-grams.
 */
export function computeLocalSemanticEmbedding(rawText) {
  const norm = normalizeSemanticText(rawText);
  const vec = new Float32Array(EMBEDDING_DIM);
  if (!norm) {
    return Array.from(vec);
  }

  // 1. Activate enterprise semantic concept dimensions (0..31)
  for (let cIdx = 0; cIdx < ENTERPRISE_CONCEPT_CLUSTERS.length; cIdx += 1) {
    const cluster = ENTERPRISE_CONCEPT_CLUSTERS[cIdx];
    let hits = 0;
    for (const phrase of cluster) {
      if (phrase.includes(' ')) {
        if (norm.includes(phrase)) hits += 2.2;
      } else {
        const regex = new RegExp(`(^|\\s|-|/)${phrase}`, 'i');
        if (regex.test(norm)) hits += 1.6;
      }
    }
    if (hits > 0) {
      vec[cIdx * 2] += Math.min(4.5, hits * 1.35);
      vec[cIdx * 2 + 1] += Math.log1p(hits) * 1.5;
    }
  }

  // 2. Hash word tokens, stems & character 4-grams into dimensions 32..255
  const hashSpace = EMBEDDING_DIM - 32;
  const tokens = norm
    .split(/[\s/-]+/)
    .filter((t) => t.length >= 2 && !STOPWORDS.has(t));

  for (let i = 0; i < tokens.length; i += 1) {
    const tok = tokens[i];
    const stem = tok.length > 5 ? tok.slice(0, tok.length - 1) : tok;

    const h1 = fnv1aHash(stem, 2166136261);
    const dim1 = 32 + (h1 % hashSpace);
    const sign1 = (h1 & 1) === 0 ? 1 : -1;
    vec[dim1] += sign1 * 1.0;

    if (i + 1 < tokens.length) {
      const bigram = `${stem}_${tokens[i + 1].slice(0, 5)}`;
      const hb = fnv1aHash(bigram, 314159265);
      const dimB = 32 + (hb % hashSpace);
      const signB = (hb & 1) === 0 ? 1 : -1;
      vec[dimB] += signB * 0.65;
    }

    if (tok.length >= 4) {
      for (let g = 0; g <= tok.length - 4; g += 1) {
        const ngram = tok.slice(g, g + 4);
        const hg = fnv1aHash(ngram, 271828182);
        const dimG = 32 + (hg % hashSpace);
        const signG = (hg & 1) === 0 ? 1 : -1;
        vec[dimG] += signG * 0.25;
      }
    }
  }

  return l2Normalize(vec);
}

/**
 * Generates an embedding via `@google/genai` (`gemini-embedding-2` / `gemini-embedding-001`)
 * when `GEMINI_API_KEY` is configured, falling back seamlessly to `computeLocalSemanticEmbedding`.
 */
export async function generateTextEmbedding(rawText) {
  const clean = String(rawText || '').trim();
  if (!clean) {
    return {
      model: 'local-semantic-v1',
      dimensions: EMBEDDING_DIM,
      vector: new Array(EMBEDDING_DIM).fill(0),
    };
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (apiKey) {
    try {
      const { GoogleGenAI } = await import('@google/genai');
      const ai = new GoogleGenAI({ apiKey });
      const response = await ai.models.embedContent({
        model: DEFAULT_EMBEDDING_MODEL,
        contents: clean.slice(0, 6000),
        config: {
          outputDimensionality: EMBEDDING_DIM,
        },
      });
      const values = response?.embeddings?.[0]?.values;
      if (Array.isArray(values) && values.length === EMBEDDING_DIM) {
        return {
          model: DEFAULT_EMBEDDING_MODEL,
          dimensions: EMBEDDING_DIM,
          vector: l2Normalize(values),
        };
      }
    } catch {
      // Graceful fallback to local deterministic vector space when offline or SDK unavailable
    }
  }

  return {
    model: 'local-semantic-v1',
    dimensions: EMBEDDING_DIM,
    vector: computeLocalSemanticEmbedding(clean),
  };
}

/**
 * Computes Cosine Similarity between two L2-normalized vectors of matching dimensionality.
 */
export function cosineSimilarity(vecA, vecB) {
  if (!Array.isArray(vecA) || !Array.isArray(vecB) || vecA.length !== vecB.length || vecA.length === 0) {
    return 0;
  }
  let dot = 0;
  for (let i = 0; i < vecA.length; i += 1) {
    dot += vecA[i] * vecB[i];
  }
  return dot;
}

/**
 * Reciprocal Rank Fusion (RRF) combining BM25/lexical rank and Vector semantic rank:
 * score(d) = w_lex / (k + rank_lex(d)) + w_sem / (k + rank_sem(d))
 */
export function computeRrfScore(lexicalRank, semanticRank, k = 60) {
  let rrf = 0;
  if (lexicalRank !== null && lexicalRank >= 1) {
    rrf += 1.0 / (k + lexicalRank);
  }
  if (semanticRank !== null && semanticRank >= 1) {
    rrf += 0.92 / (k + semanticRank);
  }
  return Number((rrf * 1000).toFixed(3));
}
