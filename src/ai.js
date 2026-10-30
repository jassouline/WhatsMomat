/**
 * WhatsMomat AI Overview & Multi-Turn Enterprise RAG Synthesis Engine
 * Uses @google/genai (Interactions API) with `gemini-3.8-flash` (or GEMINI_MODEL) when GEMINI_API_KEY is set,
 * and provides a deterministic grounded RAG synthesis fallback when running offline.
 */

const DEFAULT_GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-3.8-flash';

export async function generateMomaAiOverview(query, searchResults, currentUser) {
  const cleanQuery = String(query || '').trim();
  const topDocs = (searchResults.documents || []).slice(0, 3);
  const topGoLinks = (searchResults.goLinks || []).slice(0, 3);
  const topPeople = (searchResults.people || []).slice(0, 2);
  const topTickets = (searchResults.tickets || []).slice(0, 2);

  const citations = [
    ...topDocs.map((d, idx) => ({
      index: idx + 1,
      type: 'document',
      code: d.docCode,
      title: d.title,
      source: d.sourceSystem,
      goLink: d.goLink || null,
      ownerLdap: d.ownerLdap,
    })),
    ...topGoLinks.map((g, idx) => ({
      index: topDocs.length + idx + 1,
      type: 'golink',
      code: `go/${g.slug}`,
      title: g.title,
      source: g.target_url,
      goLink: `go/${g.slug}`,
      ownerLdap: g.owner_ldap,
    })),
  ];

  if (!cleanQuery) {
    return {
      mode: 'idle',
      model: DEFAULT_GEMINI_MODEL,
      interactionId: null,
      answer: '',
      bullets: [],
      citations: [],
      recommendedExperts: [],
      aclNotice: `Recherche filtrée selon les droits ACL de @${currentUser.ldap} (${currentUser.department}).`,
    };
  }

  // If GEMINI_API_KEY is configured in environment, call Gemini via @google/genai Interactions API
  const apiKey = process.env.GEMINI_API_KEY;
  if (apiKey) {
    try {
      const { GoogleGenAI } = await import('@google/genai');
      const client = new GoogleGenAI({ apiKey });

      const groundingContext = JSON.stringify({
        userRole: { ldap: currentUser.ldap, department: currentUser.department, role: currentUser.role },
        authorizedDocuments: topDocs.map((d, i) => ({
          ref: `[${i + 1}]`,
          code: d.docCode,
          title: d.title,
          content: d.content,
          goLink: d.goLink,
          owner: d.ownerLdap,
        })),
        matchingGoLinks: topGoLinks.map((g) => ({
          shortlink: `go/${g.slug}`,
          title: g.title,
          description: g.description,
          owner: g.owner_ldap,
        })),
        experts: topPeople.map((p) => ({
          ldap: p.ldap,
          name: p.fullName,
          title: p.title,
          team: p.team,
        })),
      });

      // Keep server-side state enabled (default store=true) so Ask Moma follow-ups can chain previous_interaction_id
      const interaction = await client.interactions.create({
        model: DEFAULT_GEMINI_MODEL,
        system_instruction:
          'Tu es Moma AI, l’assistant de recherche interne d’entreprise (inspiré de Google Moma). ' +
          'Réponds en français de manière concise, précise et professionnelle en te basant UNIQUEMENT sur le contexte autorisé (ACL) fourni. ' +
          'Mentionne systématiquement les raccourcis internes go/ pertinents et les références [1], [2].',
        input: `Question collaborateur : "${cleanQuery}"\n\nContexte interne autorisé (ACL vérifiées) :\n${groundingContext}`,
      });

      const outputText = interaction.output_text || '';
      if (outputText) {
        return {
          mode: 'gemini-live',
          model: `${DEFAULT_GEMINI_MODEL} (Interactions API)`,
          interactionId: interaction.id || null,
          answer: outputText,
          bullets: buildActionableBullets(topDocs, topGoLinks, topTickets),
          citations,
          recommendedExperts: topPeople.map((p) => ({
            ldap: p.ldap,
            fullName: p.fullName,
            title: p.title,
            team: p.team,
            office: p.office,
            avatarColor: p.avatarColor,
          })),
          aclNotice:
            searchResults.aclTrimmedCount > 0
              ? `${searchResults.aclTrimmedCount} document(s) restreint(s) exclu(s) du contexte IA conformément aux ACLs de @${currentUser.ldap}.`
              : `Synthèse générée dans le périmètre ACL de @${currentUser.ldap} (${currentUser.department}).`,
        };
      }
    } catch {
      // Fallback gracefully to grounded local synthesis if @google/genai is not installed or offline
    }
  }

  // Grounded local RAG synthesis (offline-ready client demo mode)
  if (topDocs.length === 0 && topGoLinks.length === 0 && topPeople.length === 0 && topTickets.length === 0) {
    return {
      mode: 'grounded-rag',
      model: `${DEFAULT_GEMINI_MODEL} (Grounded Enterprise RAG)`,
      interactionId: null,
      answer:
        searchResults.aclTrimmedCount > 0
          ? `Aucun document ouvert ne correspond à « ${cleanQuery} » pour votre profil (@${currentUser.ldap}), mais ${searchResults.aclTrimmedCount} document(s) confidentiel(s) ont été masqués par le contrôle d’accès (ACL Trimming). Essayez de basculer sur le profil Security Admin ou Executive pour vérifier les droits.`
          : `Aucun document interne ni lien go/ exact n’a été trouvé pour « ${cleanQuery} ». Vous pouvez créer un nouveau raccourci go/ ou consulter l’annuaire Teams.`,
      bullets: [
        'Vérifiez l’orthographe ou essayez un mot-clé comme « vpn », « laptop », « télétravail », « oncall », « congés » ou « architecture ».',
        'Utilisez la syntaxe directe go/<alias> dans la barre de recherche (ex: go/vpn, go/perks, go/techstop).',
      ],
      citations: [],
      recommendedExperts: [],
      aclNotice:
        searchResults.aclTrimmedCount > 0
          ? `Sécurité Zero-Trust : ${searchResults.aclTrimmedCount} document(s) restreint(s) filtré(s) avant génération IA.`
          : `Périmètre ACL vérifié pour @${currentUser.ldap} (${currentUser.department}).`,
    };
  }

  const primaryDoc = topDocs[0];
  const secondaryDoc = topDocs[1];
  const primaryGo = topGoLinks[0];

  let synthesizedAnswer = '';
  if (primaryDoc) {
    synthesizedAnswer = `${primaryDoc.content} [1]`;
    if (secondaryDoc) {
      synthesizedAnswer += ` Par ailleurs, le document « ${secondaryDoc.title} » (${secondaryDoc.docCode}) précise : ${secondaryDoc.summary} [2]`;
    }
  } else if (primaryGo) {
    synthesizedAnswer = `Le raccourci interne officiel pour votre recherche est go/${primaryGo.slug} (« ${primaryGo.title} ») : ${primaryGo.description} [1]`;
  } else if (topPeople[0]) {
    const p = topPeople[0];
    synthesizedAnswer = `Collaborateur identifié dans Moma Teams : ${p.fullName} (@${p.ldap}), ${p.title} au sein de l’équipe ${p.team} (${p.office}). ${p.bio}`;
  } else if (topTickets[0]) {
    const t = topTickets[0];
    synthesizedAnswer = `Ticket IT associé : ${t.ticket_key} — « ${t.title} » (${t.status}, priorité ${t.priority}). ${t.summary}`;
  }

  return {
    mode: 'grounded-rag',
    model: `${DEFAULT_GEMINI_MODEL} (Grounded Enterprise RAG)`,
    interactionId: null,
    answer: synthesizedAnswer,
    bullets: buildActionableBullets(topDocs, topGoLinks, topTickets),
    citations,
    recommendedExperts: topPeople.map((p) => ({
      ldap: p.ldap,
      fullName: p.fullName,
      title: p.title,
      team: p.team,
      office: p.office,
      avatarColor: p.avatarColor,
    })),
    aclNotice:
      searchResults.aclTrimmedCount > 0
        ? `ACL Trimming actif : ${searchResults.aclTrimmedCount} document(s) confidentiel(s) exclu(s) du prompt IA pour @${currentUser.ldap} (${currentUser.department}).`
        : `Synthèse sourcée et filtrée selon les ACLs de @${currentUser.ldap} (${currentUser.department}).`,
  };
}

function buildActionableBullets(topDocs, topGoLinks, topTickets) {
  const bullets = [];
  if (topGoLinks.length > 0) {
    const linksList = topGoLinks.map((g) => `go/${g.slug}`).join(', ');
    bullets.push(`Accès rapide : tapez ${linksList} directement dans la barre d’adresse ou l’omnibox Moma.`);
  }
  if (topDocs.length > 0) {
    const d = topDocs[0];
    bullets.push(
      `Source de vérité : ${d.docCode} (${d.sourceSystem}), maintenu par @${d.ownerLdap} — mis à jour le ${d.updatedAt}.`
    );
  }
  if (topTickets.length > 0) {
    const t = topTickets[0];
    bullets.push(`Activité ITSM liée : Ticket ${t.ticket_key} (${t.status}) assigné à @${t.assignee_ldap}.`);
  }
  return bullets;
}

/**
 * Multi-Turn Conversational "Ask Moma" follow-up handler.
 * Uses @google/genai Interactions API (`previous_interaction_id`) when GEMINI_API_KEY is present,
 * and a grounded ACL-safe RAG response otherwise.
 */
export async function askMomaFollowUp({ question, previousInteractionId, queryContext, currentUser, searchResults }) {
  const cleanQuestion = String(question || '').trim();
  if (!cleanQuestion) {
    throw new Error('Veuillez saisir une question de suivi.');
  }

  const topDocs = (searchResults?.documents || []).slice(0, 3);
  const topGoLinks = (searchResults?.goLinks || []).slice(0, 3);
  const topPeople = (searchResults?.people || []).slice(0, 2);
  const topTickets = (searchResults?.tickets || []).slice(0, 2);
  const topAcronyms = (searchResults?.acronyms || []).slice(0, 2);

  const apiKey = process.env.GEMINI_API_KEY;
  if (apiKey) {
    try {
      const { GoogleGenAI } = await import('@google/genai');
      const client = new GoogleGenAI({ apiKey });

      // Per Interactions API specification, system_instruction is interaction-scoped and re-specified each turn
      const requestPayload = {
        model: DEFAULT_GEMINI_MODEL,
        system_instruction:
          'Tu es Ask Moma, l’assistant conversationnel multi-tour de l’intranet WhatsMomat. ' +
          'Réponds en français de façon directe, sourcée et sécurisée selon les ACLs de l’utilisateur.',
        input:
          `Question de suivi de @${currentUser.ldap} (${currentUser.department}) : "${cleanQuestion}"\n` +
          `Requête initiale : "${queryContext || ''}"\n` +
          `Documents autorisés : ${JSON.stringify(topDocs.map((d) => ({ code: d.docCode, title: d.title, content: d.content, goLink: d.goLink })))}\n` +
          `Liens go/ : ${JSON.stringify(topGoLinks.map((g) => ({ slug: `go/${g.slug}`, title: g.title })))}\n` +
          `Acronymes Whatis : ${JSON.stringify(topAcronyms)}`,
      };
      if (previousInteractionId && !String(previousInteractionId).startsWith('local-turn-')) {
        requestPayload.previous_interaction_id = String(previousInteractionId);
      }

      const interaction = await client.interactions.create(requestPayload);
      if (interaction && interaction.output_text) {
        return {
          mode: 'gemini-live',
          model: DEFAULT_GEMINI_MODEL,
          interactionId: interaction.id || null,
          question: cleanQuestion,
          answer: interaction.output_text,
          suggestedAction: buildSuggestedAction(cleanQuestion, topDocs, topGoLinks, topTickets),
        };
      }
    } catch {
      // Fallback to grounded local multi-turn synthesis
    }
  }

  // Deterministic grounded local multi-turn answer based on follow-up intent
  const qLower = cleanQuestion.toLowerCase();
  let answer = '';

  if (qLower.includes('qui') || qLower.includes('contact') || qLower.includes('owner') || qLower.includes('responsable') || qLower.includes('expert')) {
    if (topPeople.length > 0) {
      const p = topPeople[0];
      answer = `Le référent interne identifié est ${p.fullName} (@${p.ldap}), ${p.title} au sein de l’équipe ${p.team} (${p.office}, bureau ${p.deskLocation || p.office}). Statut actuel : ${p.presenceLabel || 'Disponible'}.`;
    } else if (topDocs.length > 0) {
      const d = topDocs[0];
      answer = `Le document de référence ${d.docCode} (« ${d.title} ») est maintenu par @${d.ownerLdap} via ${d.sourceSystem}.`;
    } else {
      answer = `Vous pouvez contacter le support IT interne via go/techstop ou consulter l’annuaire Moma Teams.`;
    }
  } else if (qLower.includes('lien') || qLower.includes('raccourci') || qLower.includes('go/') || qLower.includes('url') || qLower.includes('où')) {
    if (topGoLinks.length > 0) {
      const list = topGoLinks.map((g) => `go/${g.slug} (${g.title})`).join(', ');
      answer = `Voici les raccourcis internes directs à utiliser : ${list}.`;
    } else if (topDocs.length > 0 && topDocs[0].goLink) {
      answer = `Vous pouvez accéder directement à la ressource via le raccourci ${topDocs[0].goLink} (source : ${topDocs[0].sourceSystem}).`;
    } else {
      answer = `Utilisez go/techstop pour le support matériel/accès ou go/whatis pour le glossaire interne.`;
    }
  } else if (qLower.includes('ticket') || qLower.includes('incident') || qLower.includes('demande') || qLower.includes('approuver') || qLower.includes('action')) {
    if (topTickets.length > 0) {
      const t = topTickets[0];
      const sysName = t.system_name || t.source_system || 'ServiceNow ITSM';
      answer = `Le ticket associé est ${t.ticket_key} (« ${t.title} ») sur ${sysName}, actuellement au statut ${t.status} (priorité ${t.priority}). Vous pouvez aussi ouvrir un nouveau ticket directement depuis le bouton « + Créer un ticket IT » ci-dessous.`;
    } else {
      answer = `Vous pouvez déclencher un ticket ServiceNow / Jira directement depuis Moma en cliquant sur « + Créer un ticket IT » ou valider vos demandes en attente dans le centre d’approbations.`;
    }
  } else if (topAcronyms.length > 0) {
    const a = topAcronyms[0];
    answer = `D’après le glossaire go/whatis, l’acronyme ${a.acronym} signifie « ${a.full_expansion} » (${a.category}) : ${a.definition}`;
  } else if (topDocs.length > 0) {
    const d = topDocs[0];
    answer = `En complément sur « ${d.title} » (${d.docCode}, ${d.sourceSystem}) : ${d.content} ${d.goLink ? `Accès direct : ${d.goLink}.` : ''}`;
  } else {
    answer = `Dans le périmètre ACL de @${currentUser.ldap} (${currentUser.department}), aucune restriction supplémentaire n’est signalée pour « ${cleanQuestion} ». Consultez go/techstop ou créez un ticket rapide si vous avez besoin d’une habilitation.`;
  }

  return {
    mode: 'grounded-rag',
    model: `${DEFAULT_GEMINI_MODEL} (Multi-Turn RAG)`,
    interactionId: `local-turn-${Date.now()}`,
    question: cleanQuestion,
    answer,
    suggestedAction: buildSuggestedAction(cleanQuestion, topDocs, topGoLinks, topTickets),
  };
}

function buildSuggestedAction(question, topDocs, topGoLinks, topTickets) {
  const qLower = String(question || '').toLowerCase();
  if (qLower.includes('ticket') || qLower.includes('incident') || qLower.includes('accès') || qLower.includes('vpn') || qLower.includes('laptop')) {
    return {
      type: 'create_ticket',
      label: 'Ouvrir un ticket IT pré-rempli',
      defaultTitle: `Demande d’assistance : ${question.slice(0, 60)}`,
    };
  }
  if (topGoLinks.length > 0) {
    return {
      type: 'open_golink',
      label: `Ouvrir go/${topGoLinks[0].slug}`,
      slug: topGoLinks[0].slug,
    };
  }
  if (topDocs.length > 0 && topDocs[0].ownerLdap) {
    return {
      type: 'view_person',
      label: `Voir le profil de @${topDocs[0].ownerLdap}`,
      ldap: topDocs[0].ownerLdap,
    };
  }
  if (topTickets.length > 0) {
    return {
      type: 'create_ticket',
      label: 'Créer un ticket IT lié',
      defaultTitle: `Suivi ${topTickets[0].ticket_key}`,
    };
  }
  return null;
}
