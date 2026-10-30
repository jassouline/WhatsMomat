import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// TODO(security): In production deployments with an external RDBMS (e.g., Cloud SQL / AlloyDB),
// enforce mTLS connections, isolate database schemas per service, and use a least-privilege
// database user restricted strictly to SELECT/INSERT/UPDATE/DELETE on app tables (never root/admin).

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, '..');
const DATA_DIR = path.resolve(PROJECT_ROOT, 'data');

/**
 * Resolves the SQLite database path safely:
 * - Uses ':memory:' when DB_PATH=':memory:' or NODE_ENV='test'.
 * - Otherwise stores a persistent SQLite database strictly inside the sandboxed ./data/ directory,
 *   failing closed on any directory traversal attempt.
 */
function resolveDatabaseTarget() {
  const rawEnvPath = String(process.env.DB_PATH || '').trim();
  if (rawEnvPath === ':memory:' || process.env.NODE_ENV === 'test') {
    return ':memory:';
  }
  fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  const candidate = !rawEnvPath
    ? path.resolve(DATA_DIR, 'whatsmomat.sqlite')
    : !rawEnvPath.includes('/') && !rawEnvPath.includes('\\')
      ? path.resolve(DATA_DIR, rawEnvPath)
      : path.resolve(PROJECT_ROOT, rawEnvPath);

  if (!candidate.startsWith(DATA_DIR + path.sep)) {
    throw new Error('Unsafe database path outside sandboxed ./data/ directory.');
  }
  if (!/^[a-zA-Z0-9._-]+\.(sqlite|db)$/.test(path.basename(candidate))) {
    throw new Error('Invalid database filename; expected <name>.sqlite or <name>.db inside ./data/.');
  }
  return candidate;
}

export const ACTIVE_DB_PATH = resolveDatabaseTarget();
const db = new DatabaseSync(ACTIVE_DB_PATH);
if (ACTIVE_DB_PATH !== ':memory:') {
  db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;');
}

/**
 * Validates password strength according to OWASP / NIST guidelines:
 * - Minimum 8 characters (12+ recommended)
 * - Maximum 128 characters
 * - Allows all characters including spaces and special symbols
 */
export function validatePasswordStrength(password) {
  if (typeof password !== 'string') {
    return { valid: false, reason: 'Password must be a string.' };
  }
  if (password.length < 8) {
    return { valid: false, reason: 'Password must be at least 8 characters long.' };
  }
  if (password.length > 128) {
    return { valid: false, reason: 'Password must not exceed 128 characters.' };
  }
  // TODO(security): Integrate with a breached/leaked password detection service (e.g. k-anonymity HIBP range API).
  return { valid: true };
}

/**
 * Hashes a password using memory-hard scrypt with a unique random per-user salt.
 */
export function hashPassword(password, existingSaltHex = null) {
  const salt = existingSaltHex
    ? Buffer.from(existingSaltHex, 'hex')
    : crypto.randomBytes(16);
  const derivedKey = crypto.scryptSync(password, salt, 64, {
    N: 16384,
    r: 8,
    p: 1,
  });
  return {
    hash: derivedKey.toString('hex'),
    salt: salt.toString('hex'),
  };
}

/**
 * Constant-time verification of a password against stored scrypt hash and salt.
 */
export function verifyPassword(password, storedHashHex, storedSaltHex) {
  if (!password || !storedHashHex || !storedSaltHex) {
    return false;
  }
  const { hash } = hashPassword(password, storedSaltHex);
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(storedHashHex, 'hex');
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

/**
 * Masks an email address for safe UI list rendering (PII masking: j***e@corp.internal).
 */
export function maskEmail(email) {
  if (typeof email !== 'string' || !email.includes('@')) {
    return '***@***';
  }
  const [local, domain] = email.split('@');
  if (local.length <= 2) {
    return `${local[0] || '*'}***@${domain}`;
  }
  return `${local[0]}***${local[local.length - 1]}@${domain}`;
}

/**
 * Masks a phone number so only the last 4 digits are visible (PII masking: ***-***-1234).
 */
export function maskPhone(phone) {
  if (typeof phone !== 'string') {
    return '***-***-****';
  }
  const digits = phone.replace(/\D/g, '');
  const last4 = digits.slice(-4).padStart(4, '*');
  return `***-***-${last4}`;
}

export function initDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ldap TEXT UNIQUE NOT NULL,
      full_name TEXT NOT NULL,
      title TEXT NOT NULL,
      level TEXT NOT NULL,
      department TEXT NOT NULL,
      team TEXT NOT NULL,
      manager_ldap TEXT,
      office TEXT NOT NULL,
      desk_location TEXT NOT NULL DEFAULT 'Bâtiment A • 4e • Desk 4A-12',
      presence_status TEXT NOT NULL DEFAULT 'available',
      presence_label TEXT NOT NULL DEFAULT 'Au bureau (Disponible)',
      timezone TEXT NOT NULL,
      working_hours TEXT NOT NULL,
      email TEXT NOT NULL,
      phone TEXT NOT NULL,
      cost_center TEXT NOT NULL,
      hire_date TEXT NOT NULL,
      avatar_color TEXT NOT NULL,
      badges_json TEXT NOT NULL,
      skills_json TEXT NOT NULL,
      projects_json TEXT NOT NULL,
      groups_json TEXT NOT NULL DEFAULT '[]',
      bio TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'employee',
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS connectors (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      connector_key TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      vendor TEXT NOT NULL,
      category TEXT NOT NULL,
      protocol TEXT NOT NULL,
      base_url TEXT NOT NULL,
      onebox_trigger TEXT NOT NULL,
      acl_mode TEXT NOT NULL,
      visibility_dept TEXT NOT NULL DEFAULT 'ALL',
      enabled INTEGER NOT NULL DEFAULT 1,
      is_custom INTEGER NOT NULL DEFAULT 0,
      owner_ldap TEXT NOT NULL,
      last_sync_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS onebox_cards (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      connector_key TEXT NOT NULL,
      trigger_keywords TEXT NOT NULL,
      card_title TEXT NOT NULL,
      card_subtitle TEXT NOT NULL,
      badge_text TEXT NOT NULL,
      fields_json TEXT NOT NULL,
      action_label TEXT NOT NULL,
      action_go_link TEXT NOT NULL,
      visibility_dept TEXT NOT NULL DEFAULT 'ALL'
    );

    CREATE TABLE IF NOT EXISTS acronyms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      term TEXT UNIQUE NOT NULL,
      expansion TEXT NOT NULL,
      definition TEXT NOT NULL,
      category TEXT NOT NULL,
      related_go_link TEXT,
      author_ldap TEXT NOT NULL,
      upvotes INTEGER NOT NULL DEFAULT 1,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS approvals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      approval_key TEXT UNIQUE NOT NULL,
      connector_key TEXT NOT NULL,
      source_tool TEXT NOT NULL,
      title TEXT NOT NULL,
      requester_ldap TEXT NOT NULL,
      approver_ldap TEXT NOT NULL,
      amount_or_scope TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS meetings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_ldap TEXT NOT NULL,
      time_slot TEXT NOT NULL,
      title TEXT NOT NULL,
      room_and_floor TEXT NOT NULL,
      meet_go_link TEXT NOT NULL,
      attendees_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS campus_menus (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      campus_key TEXT UNIQUE NOT NULL,
      campus_name TEXT NOT NULL,
      cafe_name TEXT NOT NULL,
      chef_special TEXT NOT NULL,
      vegetarian_option TEXT NOT NULL,
      barista_status TEXT NOT NULL,
      crowd_level TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS go_links (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      slug TEXT UNIQUE NOT NULL,
      target_url TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      category TEXT NOT NULL,
      owner_ldap TEXT NOT NULL,
      hits INTEGER NOT NULL DEFAULT 0,
      is_verified INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS documents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      doc_code TEXT UNIQUE NOT NULL,
      connector_key TEXT NOT NULL DEFAULT 'sharepoint',
      title TEXT NOT NULL,
      summary TEXT NOT NULL,
      content TEXT NOT NULL,
      source_system TEXT NOT NULL,
      category TEXT NOT NULL,
      owner_ldap TEXT NOT NULL,
      go_link TEXT,
      tags_json TEXT NOT NULL,
      visibility_dept TEXT NOT NULL DEFAULT 'ALL',
      min_role TEXT NOT NULL DEFAULT 'employee',
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS tickets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_key TEXT UNIQUE NOT NULL,
      connector_key TEXT NOT NULL DEFAULT 'servicenow',
      title TEXT NOT NULL,
      status TEXT NOT NULL,
      priority TEXT NOT NULL,
      system_name TEXT NOT NULL,
      requester_ldap TEXT NOT NULL,
      assignee_ldap TEXT NOT NULL,
      summary TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS announcements (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      summary TEXT NOT NULL,
      category TEXT NOT NULL,
      severity TEXT NOT NULL,
      author_ldap TEXT NOT NULL,
      go_link TEXT,
      published_at TEXT NOT NULL
    );

    CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
      doc_code UNINDEXED,
      title,
      summary,
      content,
      tags,
      source_system,
      category
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_ldap TEXT NOT NULL,
      action TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_key TEXT NOT NULL,
      metadata_json TEXT NOT NULL DEFAULT '{}',
      client_ip TEXT NOT NULL DEFAULT '127.0.0.1',
      created_at TEXT NOT NULL
    );
  `);

  seedInitialData();
  ensureSupplementalGoLinks();
  rebuildDocumentsFts();
}

function ensureSupplementalGoLinks() {
  const nowIso = '2026-10-28T08:30:00Z';
  const extras = [
    {
      slug: 'menu',
      target_url: 'https://workplace.corp.internal/microkitchens-and-menus',
      title: 'Menu du Jour Cafétéria & Micro-Kitchens (Alias go/cafeteria)',
      description: 'Accès rapide aux menus du jour Paris, Zurich et Londres, options végétariennes et horaires Barista.',
      category: 'Workplace & Life',
      owner_ldap: 'marcdu',
      hits: 4210,
      is_verified: 1,
    },
    {
      slug: 'jira',
      target_url: 'https://atlassian.corp.internal/jira/projects',
      title: 'Atlassian Jira Engineering — Tableaux Sprints & Incidents SRE',
      description: 'Création et suivi des tickets d’ingénierie, sprints produit et backlogs SRE.',
      category: 'Engineering & SRE',
      owner_ldap: 'thomasr',
      hits: 5310,
      is_verified: 1,
    },
  ];
  const stmt = db.prepare(`
    INSERT OR IGNORE INTO go_links (
      slug, target_url, title, description, category, owner_ldap, hits, is_verified, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  for (const g of extras) {
    stmt.run(
      g.slug,
      g.target_url,
      g.title,
      g.description,
      g.category,
      g.owner_ldap,
      g.hits,
      g.is_verified,
      nowIso,
      nowIso
    );
  }
}

export function syncDocumentFts(docRow) {
  if (!docRow || !docRow.doc_code) return;
  db.prepare('DELETE FROM documents_fts WHERE doc_code = ?').run(docRow.doc_code);
  db.prepare(`
    INSERT INTO documents_fts (doc_code, title, summary, content, tags, source_system, category)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    docRow.doc_code,
    docRow.title || '',
    docRow.summary || '',
    docRow.content || '',
    docRow.tags_json || '[]',
    docRow.source_system || '',
    docRow.category || ''
  );
}

export function rebuildDocumentsFts() {
  db.exec('DELETE FROM documents_fts;');
  const docs = db.prepare('SELECT * FROM documents').all();
  const insertFts = db.prepare(`
    INSERT INTO documents_fts (doc_code, title, summary, content, tags, source_system, category)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  for (const d of docs) {
    insertFts.run(
      d.doc_code,
      d.title || '',
      d.summary || '',
      d.content || '',
      d.tags_json || '[]',
      d.source_system || '',
      d.category || ''
    );
  }
}

export function recordAuditLog({
  actorLdap = 'anonymous',
  action,
  targetType,
  targetKey,
  metadata = {},
  clientIp = '127.0.0.1',
}) {
  if (!action || !targetType || !targetKey) return;
  db.prepare(`
    INSERT INTO audit_logs (actor_ldap, action, target_type, target_key, metadata_json, client_ip, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    String(actorLdap).slice(0, 64),
    String(action).slice(0, 64),
    String(targetType).slice(0, 64),
    String(targetKey).slice(0, 128),
    JSON.stringify(metadata || {}),
    String(clientIp || '127.0.0.1').slice(0, 64),
    new Date().toISOString()
  );
}

export function listAuditLogs(currentUser, limit = 50) {
  if (!currentUser || (currentUser.role !== 'admin' && currentUser.role !== 'security_admin')) {
    const err = new Error('Accès refusé : journal d’audit réservé aux administrateurs et à SecOps.');
    err.statusCode = 403;
    throw err;
  }
  const safeLimit = Math.min(Math.max(Number(limit) || 50, 1), 200);
  const rows = db
    .prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?')
    .all(safeLimit);
  return rows.map((r) => ({
    id: r.id,
    actorLdap: r.actor_ldap,
    action: r.action,
    targetType: r.target_type,
    targetKey: r.target_key,
    metadata: JSON.parse(r.metadata_json || '{}'),
    clientIp: r.client_ip,
    createdAt: r.created_at,
  }));
}

function seedInitialData() {
  const countRow = db.prepare('SELECT COUNT(*) AS count FROM users').get();
  if (countRow && countRow.count > 0) {
    return;
  }

  // 1. Seed Users (Moma Teams / Org Chart + Real-Time Status + Groups + Campus Desk)
  const insertUser = db.prepare(`
    INSERT INTO users (
      ldap, full_name, title, level, department, team, manager_ldap,
      office, desk_location, presence_status, presence_label,
      timezone, working_hours, email, phone, cost_center,
      hire_date, avatar_color, badges_json, skills_json, projects_json,
      groups_json, bio, role, password_hash, password_salt, active
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
  `);

  const seedUsers = [
    {
      ldap: 'clairem',
      full_name: 'Claire Moreau',
      title: 'VP of Engineering & CIO',
      level: 'L9 (VP)',
      department: 'Executive',
      team: 'Core Enterprise & Infrastructure',
      manager_ldap: null,
      office: 'Paris - 8 Rue de Londres (Bâtiment A, 6e)',
      desk_location: 'Bâtiment A • 6e Étage • Aile Nord • Bureau 6A-01 (Salle proche : Montmartre)',
      presence_status: 'in_meeting',
      presence_label: 'En réunion (Architecture Review Board)',
      timezone: 'Europe/Paris (UTC+1)',
      working_hours: '08:30 - 18:30',
      email: 'claire.moreau@corp.internal',
      phone: '+33 1 42 68 50 01',
      cost_center: 'CC-100-EXEC',
      hire_date: '2016-03-14',
      avatar_color: '#1a73e8',
      badges: ['10+ Years Tenure', 'Executive Sponsor', 'BeyondCorp Pioneer', 'Women in Tech Mentor'],
      skills: ['Enterprise Architecture', 'Cloud Transformation', 'IT Governance', 'Site Reliability', 'AI Strategy'],
      projects: ['Project Moma-bis (Enterprise Knowledge Portal)', 'Zero-Trust BeyondCorp Rollout', 'Q4 Cloud FinOps'],
      groups: ['exec-leadership@corp.internal', 'architecture-review-board@corp.internal', 'all-paris@corp.internal'],
      bio: 'Responsable de l’ingénierie plateforme, de la sécurité Cloud et des systèmes IT internes. Sponsor exécutif du programme Moma-bis et Agentspace.',
      role: 'admin',
    },
    {
      ldap: 'jassouline',
      full_name: 'Jordan Assouline',
      title: 'Staff AI & Cloud Architect',
      level: 'L7 (Staff)',
      department: 'Engineering',
      team: 'Enterprise AI & Search Platform',
      manager_ldap: 'clairem',
      office: 'Paris - 8 Rue de Londres (Bâtiment B, 4e)',
      desk_location: 'Bâtiment B • 4e Étage • Zone AI Lab • Desk 4B-14 (Micro-Kitchen Espresso)',
      presence_status: 'available',
      presence_label: 'Au bureau Paris (Disponible • Focus Moma-bis)',
      timezone: 'Europe/Paris (UTC+1)',
      working_hours: '09:00 - 18:00',
      email: 'jordan.assouline@corp.internal',
      phone: '+33 1 42 68 54 12',
      cost_center: 'CC-210-ENG-AI',
      hire_date: '2020-09-01',
      avatar_color: '#0d9488',
      badges: ['5+ Years Tenure', 'Gemini 3.8 Champion', 'Moma-bis Creator', 'Bar Raiser', 'Speaker'],
      skills: ['Gemini API', 'Vertex AI Search', 'Agentspace', 'Distributed Systems', 'Node.js', 'Security Architecture'],
      projects: ['Moma-bis Federated Search & AI Overview', 'Internal go/links Resolver', 'Enterprise RAG Connectors'],
      groups: [
        'ai-architects@corp.internal',
        'architecture-review-board@corp.internal',
        'moma-core-team@corp.internal',
        'all-paris@corp.internal',
      ],
      bio: 'Architecte principal de la plateforme de recherche fédérée Moma-bis, du moteur OneBox et de l’intégration Gemini 3.8 Flash.',
      role: 'admin',
    },
    {
      ldap: 'sophiel',
      full_name: 'Sophie Laurent',
      title: 'Principal Security Engineer (CISO Office)',
      level: 'L7 (Principal)',
      department: 'Security',
      team: 'Zero-Trust & Identity (BeyondCorp)',
      manager_ldap: 'clairem',
      office: 'Zurich - Europaallee 36',
      desk_location: 'Europaallee Bât. C • 3e Étage • SOC Zone • Desk 3C-04',
      presence_status: 'oncall',
      presence_label: 'En Astreinte Cyber (Incident Commander)',
      timezone: 'Europe/Zurich (UTC+1)',
      working_hours: '08:30 - 17:30',
      email: 'sophie.laurent@corp.internal',
      phone: '+41 44 668 18 90',
      cost_center: 'CC-305-SEC',
      hire_date: '2019-05-20',
      avatar_color: '#d93025',
      badges: ['Security Champion', 'Red Team Lead', 'Incident Commander', '5+ Years Tenure'],
      skills: ['Zero-Trust IAP', 'OIDC / OAuth 2.0', 'Threat Modeling', 'Incident Response', 'CSP & Web Hardening'],
      projects: ['BeyondCorp Device Posture', 'ACL Enforcement for Enterprise Search', 'SOC2 / ISO27001 Automation'],
      groups: ['security-champions@corp.internal', 'cert-oncall@corp.internal', 'architecture-review-board@corp.internal'],
      bio: 'Pilote l’architecture Zero-Trust, la gouvernance des ACLs dans le moteur de recherche interne et la réponse aux incidents P0.',
      role: 'security_admin',
    },
    {
      ldap: 'marcdu',
      full_name: 'Marc Dubois',
      title: 'Head of Corp IT & Workplace Engineering',
      level: 'L7 (Director)',
      department: 'IT Operations',
      team: 'Corp Eng & TechStop',
      manager_ldap: 'clairem',
      office: 'Paris - 8 Rue de Londres (TechStop 1er)',
      desk_location: 'Bâtiment A • 1er Étage • Comptoir TechStop • Desk 1A-02',
      presence_status: 'available',
      presence_label: 'Au bureau Paris (Disponible au TechStop)',
      timezone: 'Europe/Paris (UTC+1)',
      working_hours: '09:00 - 18:00',
      email: 'marc.dubois@corp.internal',
      phone: '+33 1 42 68 51 88',
      cost_center: 'CC-410-CORP-IT',
      hire_date: '2018-11-12',
      avatar_color: '#f29900',
      badges: ['TechStop Hero', 'MDM Architect', 'On-Call Escalation', '5+ Years Tenure'],
      skills: ['macOS / Linux Fleet', 'DNS & go/links Infrastructure', 'ServiceNow ITSM', 'Okta / Entra ID'],
      projects: ['Zero-Touch MacBook M4 Provisioning', 'Internal DNS go/ Domain Deployment', 'TechStop Self-Service Kiosk'],
      groups: ['corp-it-leads@corp.internal', 'techstop-paris@corp.internal', 'all-paris@corp.internal'],
      bio: 'Dirige les équipes Corp IT, le support TechStop et l’infrastructure réseau/DNS interne (dont la résolution native des liens go/).',
      role: 'employee',
    },
    {
      ldap: 'nadiab',
      full_name: 'Nadia Benali',
      title: 'People Operations Director (HRBP)',
      level: 'L7 (Director)',
      department: 'People Ops',
      team: 'Employee Experience & Culture',
      manager_ldap: 'clairem',
      office: 'Paris - 8 Rue de Londres (Bâtiment A, 5e)',
      desk_location: 'Bâtiment A • 5e Étage • Espace People Ops • Bureau 5A-08',
      presence_status: 'remote',
      presence_label: 'En Télétravail (Disponible sur Meet/Chat)',
      timezone: 'Europe/Paris (UTC+1)',
      working_hours: '09:30 - 18:00',
      email: 'nadia.benali@corp.internal',
      phone: '+33 1 42 68 59 04',
      cost_center: 'CC-500-PEOPLE',
      hire_date: '2021-02-01',
      avatar_color: '#1e8e3e',
      badges: ['Culture Ambassador', 'Noogler Onboarding Lead', 'Wellbeing Coach'],
      skills: ['Workday SIRH', 'Hybrid Work Framework', 'Performance Reviews (GRAD)', 'Learning & Development'],
      projects: ['Noogler 2026 Onboarding Journey', 'Hybrid Work & Flex-Work Policy', 'Workday Connector Sync'],
      groups: ['people-ops-hrbp@corp.internal', 'noogler-mentors@corp.internal', 'all-paris@corp.internal'],
      bio: 'En charge de l’expérience collaborateur, de l’onboarding des nouveaux arrivants et des politiques RH internationales.',
      role: 'hr_manager',
    },
    {
      ldap: 'thomasr',
      full_name: 'Thomas Richard',
      title: 'Senior Site Reliability Engineer (SRE)',
      level: 'L6 (Senior)',
      department: 'Engineering',
      team: 'Enterprise AI & Search Platform',
      manager_ldap: 'jassouline',
      office: 'London - 6 Pancras Square',
      desk_location: '6 Pancras Square • Floor 7 • SRE Pod • Desk 7L-22',
      presence_status: 'oncall',
      presence_label: 'Astreinte Primary SRE (go/oncall)',
      timezone: 'Europe/London (UTC+0)',
      working_hours: '09:00 - 17:30',
      email: 'thomas.richard@corp.internal',
      phone: '+44 20 7031 3044',
      cost_center: 'CC-210-ENG-AI',
      hire_date: '2022-06-15',
      avatar_color: '#1967d2',
      badges: ['On-Call Primary', 'Kubernetes SME', 'SLO Guardian'],
      skills: ['Google Kubernetes Engine', 'Terraform', 'Prometheus / Datadog', 'Incident Management', 'Go'],
      projects: ['Search Indexing Pipeline (<150ms P99)', 'Multi-Region Cloud Run Failover', 'On-Call Runbook Automation'],
      groups: ['sre-oncall@corp.internal', 'moma-core-team@corp.internal', 'eng-london@corp.internal'],
      bio: 'Garant de la fiabilité (99.95% SLO) et de la latence du moteur d’indexation Moma-bis et des connecteurs temps réel.',
      role: 'employee',
    },
    {
      ldap: 'elodiep',
      full_name: 'Élodie Petit',
      title: 'Senior Frontend & UX Engineer',
      level: 'L5 (Senior)',
      department: 'Engineering',
      team: 'Enterprise AI & Search Platform',
      manager_ldap: 'jassouline',
      office: 'Paris - 8 Rue de Londres (Bâtiment B, 4e)',
      desk_location: 'Bâtiment B • 4e Étage • Zone Design System • Desk 4B-16',
      presence_status: 'available',
      presence_label: 'Au bureau Paris (Disponible)',
      timezone: 'Europe/Paris (UTC+1)',
      working_hours: '09:30 - 18:30',
      email: 'elodie.petit@corp.internal',
      phone: '+33 1 42 68 57 31',
      cost_center: 'CC-210-ENG-AI',
      hire_date: '2023-01-10',
      avatar_color: '#e37400',
      badges: ['Accessibility Advocate (a11y)', 'Design System Lead', 'Zero-XSS Reviewer'],
      skills: ['Design Systems', 'Web Security (CSP / Trusted Types)', 'TypeScript', 'Accessibility WCAG AAA'],
      projects: ['Moma-bis Omnibox & OneBox Cards', 'Interactive Org Chart Renderer', 'Connector Studio UI'],
      groups: ['moma-core-team@corp.internal', 'ux-accessibility@corp.internal', 'all-paris@corp.internal'],
      bio: 'Conçoit l’expérience utilisateur Moma-bis : rapidité clavier (raccourci / et go/), cartes OneBox et rendu DOM sécurisé.',
      role: 'employee',
    },
    {
      ldap: 'karimz',
      full_name: 'Karim Ziani',
      title: 'Data Connectors & Search Engineer',
      level: 'L5 (SWE III)',
      department: 'Engineering',
      team: 'Enterprise AI & Search Platform',
      manager_ldap: 'jassouline',
      office: 'Paris - 8 Rue de Londres (Bâtiment B, 4e)',
      desk_location: 'Bâtiment B • 4e Étage • Zone AI Lab • Desk 4B-18',
      presence_status: 'available',
      presence_label: 'Au bureau Paris (Disponible)',
      timezone: 'Europe/Paris (UTC+1)',
      working_hours: '09:00 - 18:00',
      email: 'karim.ziani@corp.internal',
      phone: '+33 1 42 68 58 65',
      cost_center: 'CC-210-ENG-AI',
      hire_date: '2024-04-02',
      avatar_color: '#188038',
      badges: ['Search Quality', 'Connector SDK Lead'],
      skills: ['Vertex AI Search Connectors', 'ServiceNow API', 'SharePoint Graph API', 'ACL Graph Sync', 'SAP OData'],
      projects: ['SharePoint / Confluence / Jira Connector Sync', 'Real-time ACL Trimming Indexer', 'Custom Tool Webhook SDK'],
      groups: ['moma-core-team@corp.internal', 'connectors-wg@corp.internal', 'all-paris@corp.internal'],
      bio: 'Développe le SDK de connecteurs permettant aux entreprises clientes de brancher leurs propres outils (SAP, SharePoint, Jira, APIs internes).',
      role: 'employee',
    },
    {
      ldap: 'lucasv',
      full_name: 'Lucas Vasseur',
      title: 'Cloud Security Engineer (IAM & Secrets)',
      level: 'L5 (Security SWE)',
      department: 'Security',
      team: 'Zero-Trust & Identity (BeyondCorp)',
      manager_ldap: 'sophiel',
      office: 'Zurich - Europaallee 36',
      desk_location: 'Europaallee Bât. C • 3e Étage • SOC Zone • Desk 3C-06',
      presence_status: 'available',
      presence_label: 'Au bureau Zurich (Disponible)',
      timezone: 'Europe/Zurich (UTC+1)',
      working_hours: '08:00 - 17:00',
      email: 'lucas.vasseur@corp.internal',
      phone: '+41 44 668 19 22',
      cost_center: 'CC-305-SEC',
      hire_date: '2023-09-18',
      avatar_color: '#c5221f',
      badges: ['On-Call Security', 'KMS & Hardware Key Specialist'],
      skills: ['Cloud KMS', 'FIDO2 / WebAuthn Titan Keys', 'Audit Logging', 'Vulnerability Management'],
      projects: ['Hardware Security Key Enforcement', 'Secret Manager Rotation', 'Moma Security Audit Trail'],
      groups: ['security-champions@corp.internal', 'cert-oncall@corp.internal'],
      bio: 'Spécialiste authentification forte (clés FIDO2 Titan), rotation des secrets KMS et journalisation d’audit.',
      role: 'security_admin',
    },
    {
      ldap: 'camilled',
      full_name: 'Camille Garnier',
      title: 'IT Support & Fleet Specialist (TechStop)',
      level: 'L4 (Corp Eng)',
      department: 'IT Operations',
      team: 'Corp Eng & TechStop',
      manager_ldap: 'marcdu',
      office: 'Paris - 8 Rue de Londres (TechStop 1er)',
      desk_location: 'Bâtiment A • 1er Étage • Kiosque TechStop • Desk 1A-05',
      presence_status: 'available',
      presence_label: 'Au comptoir TechStop Paris',
      timezone: 'Europe/Paris (UTC+1)',
      working_hours: '08:30 - 17:30',
      email: 'camille.garnier@corp.internal',
      phone: '+33 1 42 68 52 19',
      cost_center: 'CC-410-CORP-IT',
      hire_date: '2025-10-06',
      avatar_color: '#00838f',
      badges: ['Noogler', 'Customer Delight 99%', 'Mac & Linux Certified'],
      skills: ['Endpoint Management', 'Zero-Trust Access Troubleshooting', 'Hardware Refresh', 'ServiceNow Fulfillment'],
      projects: ['Laptop Refresh Q4', 'Loaner Chromebook Pool', 'Onboarding Day-1 IT Setup'],
      groups: ['techstop-paris@corp.internal', 'noogler-mentors@corp.internal', 'all-paris@corp.internal'],
      bio: 'Point de contact privilégié au TechStop de Paris pour l’accompagnement matériel, l’accès BeyondCorp et le programme de renouvellement.',
      role: 'employee',
    },
  ];

  for (const u of seedUsers) {
    const ephemeralPass = crypto.randomBytes(16).toString('hex');
    const { hash, salt } = hashPassword(ephemeralPass);
    insertUser.run(
      u.ldap,
      u.full_name,
      u.title,
      u.level,
      u.department,
      u.team,
      u.manager_ldap,
      u.office,
      u.desk_location,
      u.presence_status,
      u.presence_label,
      u.timezone,
      u.working_hours,
      u.email,
      u.phone,
      u.cost_center,
      u.hire_date,
      u.avatar_color,
      JSON.stringify(u.badges),
      JSON.stringify(u.skills),
      JSON.stringify(u.projects),
      JSON.stringify(u.groups),
      u.bio,
      u.role,
      hash,
      salt
    );
  }

  // 2. Seed Pluggable Enterprise Connectors
  const insertConnector = db.prepare(`
    INSERT INTO connectors (
      connector_key, name, vendor, category, protocol, base_url,
      onebox_trigger, acl_mode, visibility_dept, enabled, is_custom, owner_ldap, last_sync_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const seedConnectors = [
    {
      connector_key: 'servicenow',
      name: 'ServiceNow ITSM & Catalogue IT',
      vendor: 'ServiceNow',
      category: 'ITSM & Support',
      protocol: 'REST Table API + OAuth 2.0 + ACL Sync',
      base_url: 'https://servicenow.corp.internal',
      onebox_trigger: 'it-, laptop, macbook, techstop, vpn',
      acl_mode: 'Identity-Aware ACL',
      visibility_dept: 'ALL',
      enabled: 1,
      is_custom: 0,
      owner_ldap: 'marcdu',
      last_sync_at: 'Il y a 2 min (Temps réel)',
    },
    {
      connector_key: 'atlassian',
      name: 'Atlassian Jira & Confluence Enterprise',
      vendor: 'Atlassian',
      category: 'Engineering & Wiki',
      protocol: 'Webhook + REST v3 + Crowd/OIDC Groups',
      base_url: 'https://atlassian.corp.internal',
      onebox_trigger: 'sre-, oncall, astreinte, architecture, moma',
      acl_mode: 'Space & Issue Permissions',
      visibility_dept: 'ALL',
      enabled: 1,
      is_custom: 0,
      owner_ldap: 'karimz',
      last_sync_at: 'Il y a 1 min (Webhook)',
    },
    {
      connector_key: 'sharepoint',
      name: 'Microsoft SharePoint & M365 (Entra ID)',
      vendor: 'Microsoft',
      category: 'Gestion Documentaire',
      protocol: 'Microsoft Graph API + Entra Group ACLs',
      base_url: 'https://sharepoint.corp.internal',
      onebox_trigger: 'télétravail, remote, hybride, charte',
      acl_mode: 'Entra ID Security Groups',
      visibility_dept: 'ALL',
      enabled: 1,
      is_custom: 0,
      owner_ldap: 'karimz',
      last_sync_at: 'Il y a 4 min (Delta Sync)',
    },
    {
      connector_key: 'workday',
      name: 'Workday SIRH & People Graph',
      vendor: 'Workday',
      category: 'SIRH & Organigramme',
      protocol: 'SCIM 2.0 + Workday REST API',
      base_url: 'https://workday.corp.internal',
      onebox_trigger: 'congés, rtt, holiday, vacances, noogler, salaire, grad',
      acl_mode: 'Role-Based (Employee / HRBP)',
      visibility_dept: 'ALL',
      enabled: 1,
      is_custom: 0,
      owner_ldap: 'nadiab',
      last_sync_at: 'Il y a 5 min (SCIM Sync)',
    },
    {
      connector_key: 'gitlab',
      name: 'GitLab Self-Hosted / GitHub Enterprise',
      vendor: 'GitLab / GitHub',
      category: 'Code, ADR & CI/CD',
      protocol: 'GraphQL + Webhook Push + Repo ACLs',
      base_url: 'https://gitlab.corp.internal',
      onebox_trigger: 'gemini, sdk, api, mr-, code',
      acl_mode: 'Repository Membership ACL',
      visibility_dept: 'ALL',
      enabled: 1,
      is_custom: 0,
      owner_ldap: 'jassouline',
      last_sync_at: 'Temps réel (Git Hook)',
    },
    {
      connector_key: 'sap-erp',
      name: 'SAP S/4HANA & Ariba Procurement',
      vendor: 'SAP',
      category: 'ERP, Achats & Finance',
      protocol: 'SAP OData v4 + Principal Propagation',
      base_url: 'https://sap.corp.internal',
      onebox_trigger: 'po-, sap, achat, commande, budget, fournisseur, note de frais',
      acl_mode: 'Cost-Center & Role ACL',
      visibility_dept: 'ALL',
      enabled: 1,
      is_custom: 0,
      owner_ldap: 'clairem',
      last_sync_at: 'Il y a 8 min (OData Batch)',
    },
    {
      connector_key: 'secops-vault',
      name: 'SecOps SIEM & Vault (Chronicle / Splunk)',
      vendor: 'Security Operations',
      category: 'Cybersécurité & Forensique',
      protocol: 'mTLS Push Connector + Strict RBAC',
      base_url: 'https://security.corp.internal',
      onebox_trigger: 'sec-, secops, kms, compromission, incident',
      acl_mode: 'Restricted (Security / Executive Only)',
      visibility_dept: 'Security',
      enabled: 1,
      is_custom: 0,
      owner_ldap: 'sophiel',
      last_sync_at: 'Temps réel (SIEM Stream)',
    },
  ];

  for (const c of seedConnectors) {
    insertConnector.run(
      c.connector_key,
      c.name,
      c.vendor,
      c.category,
      c.protocol,
      c.base_url,
      c.onebox_trigger,
      c.acl_mode,
      c.visibility_dept,
      c.enabled,
      c.is_custom,
      c.owner_ldap,
      c.last_sync_at
    );
  }

  // 3. Seed Moma OneBox Structured Real-Time Cards
  const insertOneBox = db.prepare(`
    INSERT INTO onebox_cards (
      connector_key, trigger_keywords, card_title, card_subtitle, badge_text,
      fields_json, action_label, action_go_link, visibility_dept
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const seedOneBoxes = [
    {
      connector_key: 'servicenow',
      trigger_keywords: 'laptop, macbook, renouvellement, techstop, matériel, ordinateur',
      card_title: 'OneBox ServiceNow — Éligibilité Renouvellement Poste & TechStop',
      card_subtitle: 'Données temps réel extraites de ServiceNow Asset Management (CMDB)',
      badge_text: 'ServiceNow Live OneBox',
      fields: [
        { label: 'Statut Parc Actuel', value: 'Éligible au renouvellement 36 mois (MacBook Pro M4 / Linux)' },
        { label: 'Stock TechStop Paris', value: '14 MacBook Pro 16" M4 Max & 9 ThinkPad Linux disponibles' },
        { label: 'Délai Zero-Touch MDM', value: 'Retrait immédiat au 1er étage ou livraison 48h' },
      ],
      action_label: 'Commander sur go/new-laptop',
      action_go_link: 'go/new-laptop',
      visibility_dept: 'ALL',
    },
    {
      connector_key: 'workday',
      trigger_keywords: 'congés, rtt, vacances, holiday, solde, télétravail, perks',
      card_title: 'OneBox Workday SIRH — Solde Congés, RTT & Budget Télétravail',
      card_subtitle: 'Synthèse temps réel via le connecteur Workday REST / SCIM 2.0',
      badge_text: 'Workday Live OneBox',
      fields: [
        { label: 'Solde Congés Payés 2026', value: '18.5 jours acquis disponibles' },
        { label: 'Solde RTT 2026', value: '6.0 jours disponibles (clôture le 31 déc.)' },
        { label: 'Enveloppe Télétravail (WFH)', value: '500 € TTC disponibles (Code note de frais : WFH-EQUIP)' },
      ],
      action_label: 'Poser un congé sur go/holiday',
      action_go_link: 'go/holiday',
      visibility_dept: 'ALL',
    },
    {
      connector_key: 'atlassian',
      trigger_keywords: 'oncall, astreinte, incident, p0, sre',
      card_title: 'OneBox PagerDuty / Jira SRE — Rotation d’Astreinte en Cours',
      card_subtitle: 'Interrogation directe de l’API d’astreinte Enterprise Platform',
      badge_text: 'On-Call Live OneBox',
      fields: [
        { label: 'Ingénieur Primary On-Call', value: 'Thomas Richard (@thomasr) — Londres (UTC+0)' },
        { label: 'Secondary / Escalation', value: 'Jordan Assouline (@jassouline) — Paris (UTC+1)' },
        { label: 'SLO Search & Connectors (30j)', value: '99.97% (Budget d’erreur restant : 84%)' },
      ],
      action_label: 'Ouvrir le portail go/oncall',
      action_go_link: 'go/oncall',
      visibility_dept: 'ALL',
    },
    {
      connector_key: 'sap-erp',
      trigger_keywords: 'sap, po-, achat, commande, budget, fournisseur, note de frais, erp',
      card_title: 'OneBox SAP S/4HANA & Ariba — Commandes & Budget Département',
      card_subtitle: 'Connecteur OData v4 SAP ERP avec propagation d’identité',
      badge_text: 'SAP ERP Live OneBox',
      fields: [
        { label: 'Dernière Commande (PO)', value: 'PO-2026-8841 — Licences Cloud & Serveurs GPU (Approuvée)' },
        { label: 'Workflow Validation Achats', value: '< 5 000 € : Manager L6+ | > 5 000 € : Direction FinOps' },
        { label: 'Délai Remboursement Notes de Frais', value: 'Virement SEPA automatique sous 5 jours ouvrés' },
      ],
      action_label: 'Ouvrir SAP Ariba (go/sap)',
      action_go_link: 'go/sap',
      visibility_dept: 'ALL',
    },
  ];

  for (const ob of seedOneBoxes) {
    insertOneBox.run(
      ob.connector_key,
      ob.trigger_keywords,
      ob.card_title,
      ob.card_subtitle,
      ob.badge_text,
      JSON.stringify(ob.fields),
      ob.action_label,
      ob.action_go_link,
      ob.visibility_dept
    );
  }

  // 4. Seed "Whatis" Enterprise Acronyms Glossary (Iconic Moma feature)
  const insertAcronym = db.prepare(`
    INSERT INTO acronyms (
      term, expansion, definition, category, related_go_link, author_ldap, upvotes, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const seedAcronyms = [
    {
      term: 'OKR',
      expansion: 'Objectives and Key Results',
      definition: 'Cadre de définition d’objectifs trimestriels et annuels utilisé dans toute l’entreprise : un Objectif ambitieux couplé à 3-5 Résultats Clés mesurables.',
      category: 'Strategy & Culture',
      related_go_link: 'go/okrs',
      author_ldap: 'clairem',
      upvotes: 142,
    },
    {
      term: 'GRAD',
      expansion: 'Googler Reviews and Development (Évaluation Annuelle)',
      definition: 'Processus d’évaluation de la performance, de feedback continu et de calibration salariale/promotions piloté dans Workday.',
      category: 'People & RH',
      related_go_link: 'go/perks',
      author_ldap: 'nadiab',
      upvotes: 98,
    },
    {
      term: 'SLO',
      expansion: 'Service Level Objective',
      definition: 'Cible de fiabilité ou de latence d’un service (ex: 99.95% de disponibilité et <150ms P99 sur Moma Search), associée à un budget d’erreur.',
      category: 'Engineering & SRE',
      related_go_link: 'go/oncall',
      author_ldap: 'thomasr',
      upvotes: 116,
    },
    {
      term: 'IAP',
      expansion: 'Identity-Aware Proxy (BeyondCorp Zero-Trust)',
      definition: 'Passerelle d’accès Zero-Trust qui vérifie l’identité de l’utilisateur et le certificat du poste à chaque requête HTTP, remplaçant le VPN.',
      category: 'IT & Security',
      related_go_link: 'go/vpn',
      author_ldap: 'sophiel',
      upvotes: 89,
    },
    {
      term: 'LGTM',
      expansion: 'Looks Good To Me',
      definition: 'Approbation formelle d’une revue de code (Merge Request GitLab / Pull Request GitHub) ou d’un Design Doc d’architecture.',
      category: 'Engineering & SRE',
      related_go_link: 'go/architecture',
      author_ldap: 'jassouline',
      upvotes: 204,
    },
    {
      term: 'CMDB',
      expansion: 'Configuration Management Database (ServiceNow)',
      definition: 'Référentiel central ServiceNow recensant tous les actifs matériels (MacBook, serveurs), logiciels et leurs dépendances.',
      category: 'IT & Security',
      related_go_link: 'go/techstop',
      author_ldap: 'marcdu',
      upvotes: 64,
    },
    {
      term: 'PO',
      expansion: 'Purchase Order (Bon de Commande SAP Ariba)',
      definition: 'Numéro de commande officiel généré par SAP S/4HANA & Ariba après validation budgétaire pour tout achat fournisseur.',
      category: 'Finance & Achats',
      related_go_link: 'go/sap',
      author_ldap: 'clairem',
      upvotes: 77,
    },
    {
      term: 'NOOGLER',
      expansion: 'New Employee / Nouvel Arrivant',
      definition: 'Terme interne désignant tout nouveau collaborateur durant ses 90 premiers jours d’intégration (parcours go/noogler).',
      category: 'People & RH',
      related_go_link: 'go/noogler',
      author_ldap: 'nadiab',
      upvotes: 185,
    },
  ];

  for (const acr of seedAcronyms) {
    insertAcronym.run(
      acr.term,
      acr.expansion,
      acr.definition,
      acr.category,
      acr.related_go_link,
      acr.author_ldap,
      acr.upvotes,
      '2026-10-28'
    );
  }

  // 5. Seed Pending Approvals & Action Center Items ("My Moma" Personalized Widget)
  const insertApproval = db.prepare(`
    INSERT INTO approvals (
      approval_key, connector_key, source_tool, title, requester_ldap, approver_ldap, amount_or_scope, status, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)
  `);

  const seedApprovals = [
    {
      approval_key: 'PO-2026-8904',
      connector_key: 'sap-erp',
      source_tool: 'SAP Ariba Procurement',
      title: 'Achat Licences Connecteur Vertex AI Search & Quota GPU Q4',
      requester_ldap: 'karimz',
      approver_ldap: 'jassouline',
      amount_or_scope: '4 200 € HT (CC-210-ENG-AI)',
      created_at: 'Il y a 25 min',
    },
    {
      approval_key: 'MR-418',
      connector_key: 'gitlab',
      source_tool: 'GitLab Enterprise',
      title: 'feat(onebox): Ajout du routeur temps réel Moma OneBox & Whatis',
      requester_ldap: 'elodiep',
      approver_ldap: 'jassouline',
      amount_or_scope: '+412 / -18 lignes (Checks CI OK)',
      created_at: 'Il y a 1h',
    },
    {
      approval_key: 'WD-VAC-912',
      connector_key: 'workday',
      source_tool: 'Workday Absence',
      title: 'Demande de Congés Payés (23 déc. — 2 janv.)',
      requester_ldap: 'thomasr',
      approver_ldap: 'jassouline',
      amount_or_scope: '7 jours ouvrés (Solde restant : 11.5j)',
      created_at: 'Hier, 17:10',
    },
    {
      approval_key: 'IAM-SEC-309',
      connector_key: 'secops-vault',
      source_tool: 'BeyondCorp IAM',
      title: 'Élévation temporaire Break-Glass Production (2h)',
      requester_ldap: 'thomasr',
      approver_ldap: 'sophiel',
      amount_or_scope: 'Rôle: roles/run.admin (Audit SIEM actif)',
      created_at: 'Il y a 10 min',
    },
  ];

  for (const ap of seedApprovals) {
    insertApproval.run(
      ap.approval_key,
      ap.connector_key,
      ap.source_tool,
      ap.title,
      ap.requester_ldap,
      ap.approver_ldap,
      ap.amount_or_scope,
      ap.created_at
    );
  }

  // 6. Seed Daily Meetings ("My Moma" Up Next Calendar)
  const insertMeeting = db.prepare(`
    INSERT INTO meetings (
      owner_ldap, time_slot, title, room_and_floor, meet_go_link, attendees_json
    ) VALUES (?, ?, ?, ?, ?, ?)
  `);

  const seedMeetings = [
    {
      owner_ldap: 'jassouline',
      time_slot: '11:00 - 11:45',
      title: 'Revue d’Architecture Moma-bis & Connecteurs Outils Clients',
      room_and_floor: 'Paris Bât. B • 4e • Salle Haussmann (Visio hybride)',
      meet_go_link: 'go/architecture',
      attendees: ['clairem', 'karimz', 'elodiep', 'sophiel'],
    },
    {
      owner_ldap: 'jassouline',
      time_slot: '14:00 - 14:30',
      title: '1:1 Hebdo SRE & Latence Indexation (<150ms SLO)',
      room_and_floor: 'Google Meet / Visio Londres-Paris',
      meet_go_link: 'go/oncall',
      attendees: ['thomasr'],
    },
    {
      owner_ldap: 'jassouline',
      time_slot: '16:00 - 17:00',
      title: 'Démo Client : Intégration SAP, ServiceNow & SharePoint dans Moma',
      room_and_floor: 'Paris Bât. A • 6e • Auditorium Eiffel',
      meet_go_link: 'go/gemini-sandbox',
      attendees: ['clairem', 'marcdu', 'nadiab'],
    },
  ];

  for (const m of seedMeetings) {
    insertMeeting.run(
      m.owner_ldap,
      m.time_slot,
      m.title,
      m.room_and_floor,
      m.meet_go_link,
      JSON.stringify(m.attendees)
    );
  }

  // 7. Seed Campus Cafeteria & Micro-Kitchen Menus
  const insertMenu = db.prepare(`
    INSERT INTO campus_menus (
      campus_key, campus_name, cafe_name, chef_special, vegetarian_option, barista_status, crowd_level
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  const seedMenus = [
    {
      campus_key: 'Paris',
      campus_name: 'Campus Paris — 8 Rue de Londres',
      cafe_name: 'Café Saint-Lazare (RDC) & Micro-Kitchen 4B',
      chef_special: 'Pavé de saumon rôti au miso, riz noir vénéré & broccolini',
      vegetarian_option: 'Risotto aux cèpes frais, parmesan 24 mois & noisettes torréfiées',
      barista_status: 'Barista ouvert (08:30 - 16:30) • Oat Flat White dispo',
      crowd_level: 'Affluence faible (Attente ~2 min)',
    },
    {
      campus_key: 'Zurich',
      campus_name: 'Campus Zurich — Europaallee 36',
      cafe_name: 'Restaurant Limmat & Alpine barista',
      chef_special: 'Zürcher Geschnetzeltes traditionnel & Rösti croustillant',
      vegetarian_option: 'Spätzli maison au gruyère d’alpage & oignons caramélisés',
      barista_status: 'Barista ouvert (08:00 - 16:00)',
      crowd_level: 'Affluence modérée (Attente ~5 min)',
    },
    {
      campus_key: 'London',
      campus_name: 'Campus London — 6 Pancras Square',
      cafe_name: 'King’s Cross Kitchen (Floor 5)',
      chef_special: 'Tikka Masala rôti au four tandoor, riz basmati & naan à l’ail',
      vegetarian_option: 'Courge butternut rôtie, houmous de pois chiches & grenade',
      barista_status: 'Barista ouvert (08:30 - 17:00)',
      crowd_level: 'Affluence faible (Attente ~3 min)',
    },
  ];

  for (const cm of seedMenus) {
    insertMenu.run(
      cm.campus_key,
      cm.campus_name,
      cm.cafe_name,
      cm.chef_special,
      cm.vegetarian_option,
      cm.barista_status,
      cm.crowd_level
    );
  }

  // 8. Seed go/links
  const insertGoLink = db.prepare(`
    INSERT INTO go_links (
      slug, target_url, title, description, category, owner_ldap, hits, is_verified, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const seedGoLinks = [
    {
      slug: 'oncall',
      target_url: 'https://oncall.corp.internal/rotations/enterprise-platform',
      title: 'Portail d’Astreinte SRE & SecOps (On-Call)',
      description: 'Planning d’astreinte primaire/secondaire, escalade P0/P1 et procédure d’alerte Incident Commander.',
      category: 'Engineering & SRE',
      owner_ldap: 'thomasr',
      hits: 4820,
      is_verified: 1,
    },
    {
      slug: 'vpn',
      target_url: 'https://beyondcorp.corp.internal/access-check',
      title: 'Accès Distant Zero-Trust (BeyondCorp / Remplacement VPN)',
      description: 'Diagnostic du certificat machine, clé de sécurité FIDO2 Titan et accès aux applications internes sans VPN classique.',
      category: 'IT & Security',
      owner_ldap: 'sophiel',
      hits: 6390,
      is_verified: 1,
    },
    {
      slug: 'techstop',
      target_url: 'https://servicenow.corp.internal/techstop-appointment',
      title: 'TechStop (ServiceNow) — Support IT, Prêt Matériel & Rendez-vous',
      description: 'Prendre rendez-vous au comptoir TechStop (Paris, Zurich, Londres), commander un chargeur ou remplacer un poste.',
      category: 'IT & Security',
      owner_ldap: 'marcdu',
      hits: 5140,
      is_verified: 1,
    },
    {
      slug: 'new-laptop',
      target_url: 'https://servicenow.corp.internal/fleet/refresh-2026',
      title: 'Portail de Renouvellement Poste de Travail (MacBook Pro M4 / Linux)',
      description: 'Vérifier votre éligibilité au renouvellement à 36 mois dans ServiceNow et commander votre nouvelle station de travail.',
      category: 'IT & Security',
      owner_ldap: 'camilled',
      hits: 3290,
      is_verified: 1,
    },
    {
      slug: 'okrs',
      target_url: 'https://sharepoint.corp.internal/sites/strategy/okrs-2026-q4',
      title: 'OKRs Entreprise & Équipes — Q4 2026',
      description: 'Objectifs et résultats clés (Objectives & Key Results) de l’entreprise, de la DSI et des équipes Engineering.',
      category: 'Company & Strategy',
      owner_ldap: 'clairem',
      hits: 7120,
      is_verified: 1,
    },
    {
      slug: 'perks',
      target_url: 'https://workday.corp.internal/benefits-and-perks',
      title: 'Avantages Collaborateurs, Télétravail & Budget Équipement (500 €)',
      description: 'Politique de travail hybride (3j bureau / 2j télétravail), remboursement écran/chaise ergonomique et subventions.',
      category: 'People & RH',
      owner_ldap: 'nadiab',
      hits: 5890,
      is_verified: 1,
    },
    {
      slug: 'holiday',
      target_url: 'https://workday.corp.internal/time-off/calendar-2026',
      title: 'Workday Congés, RTT & Jours Fériés 2026',
      description: 'Poser des congés payés, RTT, consulter les jours de fermeture par pays (France, Suisse, UK) et le solde annuel.',
      category: 'People & RH',
      owner_ldap: 'nadiab',
      hits: 4410,
      is_verified: 1,
    },
    {
      slug: 'sap',
      target_url: 'https://sap.corp.internal/ariba-procurement',
      title: 'SAP S/4HANA & Ariba — Commandes d’Achat (PO) & Notes de Frais',
      description: 'Créer une demande d’achat fournisseur, suivre un bon de commande PO-* ou soumettre une note de frais.',
      category: 'Company & Strategy',
      owner_ldap: 'clairem',
      hits: 3680,
      is_verified: 1,
    },
    {
      slug: 'whatis',
      target_url: 'https://moma.corp.internal/whatis-glossary',
      title: 'Whatis — Décodeur d’Acronymes & Glossaire Interne Collaboratif',
      description: 'Dictionnaire collaboratif de tous les acronymes techniques, RH et financiers de l’entreprise (OKR, GRAD, SLO, IAP, PO...).',
      category: 'Company & Strategy',
      owner_ldap: 'jassouline',
      hits: 6150,
      is_verified: 1,
    },
    {
      slug: 'noogler',
      target_url: 'https://sharepoint.corp.internal/sites/onboarding/noogler-guide',
      title: 'Guide d’Onboarding Nouveaux Arrivants (30-60-90 jours)',
      description: 'Checklist des 2 premières semaines : configuration clé Titan, accès Moma-bis, buddy engineering et formations sécurité.',
      category: 'People & RH',
      owner_ldap: 'nadiab',
      hits: 2780,
      is_verified: 1,
    },
    {
      slug: 'sec-incident',
      target_url: 'https://security.corp.internal/ir-playbook-p0',
      title: 'Déclarer un Incident de Sécurité ou Phishing (CERT 24/7)',
      description: 'Formulaire d’alerte immédiate en cas de suspicion de compromission, perte de matériel ou campagne de phishing ciblé.',
      category: 'IT & Security',
      owner_ldap: 'sophiel',
      hits: 1940,
      is_verified: 1,
    },
    {
      slug: 'gemini-sandbox',
      target_url: 'https://gitlab.corp.internal/ai-platform/gemini-3-8-workbench',
      title: 'Workbench Interne Gemini 3.8 Flash & Connecteurs RAG',
      description: 'Environnement homologué pour tester les prompts, l’API Interactions (@google/genai) et les connecteurs d’outils.',
      category: 'Engineering & SRE',
      owner_ldap: 'jassouline',
      hits: 3960,
      is_verified: 1,
    },
    {
      slug: 'architecture',
      target_url: 'https://atlassian.corp.internal/wiki/spaces/ENG/moma-bis-blueprint',
      title: 'Blueprint Architecture Moma-bis, OneBox & Connecteurs Tiers',
      description: 'Spécification technique de la recherche fédérée avec filtrage ACL, modules OneBox temps réel et résolution DNS go/.',
      category: 'Engineering & SRE',
      owner_ldap: 'jassouline',
      hits: 2510,
      is_verified: 1,
    },
    {
      slug: 'cafeteria',
      target_url: 'https://workplace.corp.internal/microkitchens-and-menus',
      title: 'Menus Cafétéria & Micro-Kitchens (Paris / Zurich / Londres)',
      description: 'Menus du jour par campus, options végétariennes, allergènes et horaires du Barista.',
      category: 'Workplace & Life',
      owner_ldap: 'marcdu',
      hits: 8450,
      is_verified: 1,
    },
  ];

  for (const g of seedGoLinks) {
    insertGoLink.run(
      g.slug,
      g.target_url,
      g.title,
      g.description,
      g.category,
      g.owner_ldap,
      g.hits,
      g.is_verified,
      '2026-09-15T10:00:00Z',
      '2026-10-28T08:30:00Z'
    );
  }

  // 9. Seed Documents linked to Third-Party Connectors
  const insertDoc = db.prepare(`
    INSERT INTO documents (
      doc_code, connector_key, title, summary, content, source_system, category,
      owner_ldap, go_link, tags_json, visibility_dept, min_role, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const seedDocs = [
    {
      doc_code: 'DOC-IT-001',
      connector_key: 'servicenow',
      title: 'Accès Distant Zero-Trust (BeyondCorp) — pourquoi il n’y a plus de VPN',
      summary: 'Guide complet pour accéder aux outils internes depuis l’extérieur sans VPN traditionnel grâce à BeyondCorp IAP et aux clés FIDO2 Titan.',
      content: `Chez nous, comme chez Google, le VPN d'entreprise classique a été remplacé par l'architecture Zero-Trust BeyondCorp (accessible via go/vpn). L'accès aux applications internes (Moma-bis, GitLab, Jira, ServiceNow, SAP) dépend de l'identité vérifiée du collaborateur et du score de confiance du terminal (certificat MDM + chiffrement FileVault/LUKS + clé matérielle FIDO2 Titan). En cas d'erreur de certificat lors d'un déplacement, exécutez l'outil de diagnostic sur go/vpn ou ouvrez un ticket auprès de go/techstop.`,
      source_system: 'ServiceNow Knowledge Base',
      category: 'IT & Security',
      owner_ldap: 'sophiel',
      go_link: 'go/vpn',
      tags: ['vpn', 'beyondcorp', 'zero-trust', 'accès distant', 'télétravail', 'certificat', 'titan', 'iap'],
      visibility_dept: 'ALL',
      min_role: 'employee',
      updated_at: '2026-10-24',
    },
    {
      doc_code: 'DOC-IT-002',
      connector_key: 'servicenow',
      title: 'Politique de Renouvellement Matériel (MacBook Pro M4 / Linux Workstation)',
      summary: 'Critères d’éligibilité (36 mois), procédure de commande dans ServiceNow via go/new-laptop et transfert Zero-Touch au TechStop.',
      content: `Tout collaborateur dont l'ordinateur portable a plus de 36 mois (ou dont le rôle d'ingénierie nécessite 64 Go+ de RAM unifiée) est éligible au programme de renouvellement automatique via go/new-laptop (connecté à ServiceNow Asset Management / CMDB). Les profils standard disponibles sont : MacBook Pro 14" ou 16" (M4 Pro / M4 Max), station Linux Debian Enterprise (ThinkPad P1) ou Chromebook Enterprise. La livraison s'effectue au TechStop (go/techstop) ou à domicile sous 5 jours ouvrés.`,
      source_system: 'ServiceNow Knowledge Base',
      category: 'IT & Security',
      owner_ldap: 'marcdu',
      go_link: 'go/new-laptop',
      tags: ['laptop', 'macbook', 'matériel', 'ordinateur', 'techstop', 'renouvellement', 'linux', 'cmdb'],
      visibility_dept: 'ALL',
      min_role: 'employee',
      updated_at: '2026-10-20',
    },
    {
      doc_code: 'DOC-HR-001',
      connector_key: 'sharepoint',
      title: 'Politique de Télétravail Hybride, Équipement Domicile (500 €) & Work From Anywhere',
      summary: 'Règles du modèle hybride (3 jours sur site / 2 jours à distance), remboursement de 500 € pour le bureau à domicile et 4 semaines WFA par an.',
      content: `Notre modèle de travail hybride (publié sur SharePoint Intranet RH) prévoit 3 jours de présence au bureau par semaine et 2 jours de télétravail. En complément, chaque collaborateur bénéficie de 4 semaines de "Work From Anywhere" (WFA) par année civile après déclaration sur go/perks. Un budget d'équipement ergonomique à domicile de 500 € TTC (écran 4K, chaise ergonomique, clavier) est remboursé sur note de frais SAP avec le code analytique WFH-EQUIP.`,
      source_system: 'Microsoft SharePoint (Intranet RH)',
      category: 'People & RH',
      owner_ldap: 'nadiab',
      go_link: 'go/perks',
      tags: ['télétravail', 'remote', 'hybride', 'équipement', 'remboursement', 'perks', 'rh', 'bureau'],
      visibility_dept: 'ALL',
      min_role: 'employee',
      updated_at: '2026-10-18',
    },
    {
      doc_code: 'DOC-HR-002',
      connector_key: 'workday',
      title: 'Calendrier des Congés Payés, RTT & Fermetures Annuelles 2026 (Workday)',
      summary: 'Fonctionnement des 25 jours de CP, 12 RTT, report annuel et saisie dans Workday via go/holiday.',
      content: `Les collaborateurs basés en France disposent de 25 jours ouvrés de congés payés et de 12 jours de RTT par an (soit 37 jours au total), synchronisés en temps réel depuis Workday SIRH. Les demandes de congés se déposent sur go/holiday. Le solde non pris au 31 mai peut être reporté jusqu'à 5 jours ou placé sur le Compte Épargne Temps (CET).`,
      source_system: 'Workday SIRH',
      category: 'People & RH',
      owner_ldap: 'nadiab',
      go_link: 'go/holiday',
      tags: ['congés', 'rtt', 'vacances', 'jours fériés', 'holiday', 'cet', 'rh', 'workday'],
      visibility_dept: 'ALL',
      min_role: 'employee',
      updated_at: '2026-10-12',
    },
    {
      doc_code: 'DOC-ENG-001',
      connector_key: 'atlassian',
      title: 'Architecture de Référence Moma-bis : Index Unifié, OneBox & Connecteurs Outils Clients',
      summary: 'Comment Moma a été conçu chez Google (Index fédéré ACL + OneBox temps réel + go/links) et comment brancher les outils propres d’un client.',
      content: `L'architecture de Google Moma repose sur 4 composants découplés que nous répliquons ici pour tout SI client : (1) Un SDK de Connecteurs Pluggables (Content + Identity ACL Sync) capable d'indexer des outils non-Google comme Microsoft SharePoint, Confluence, Jira, ServiceNow, Workday, GitLab ou SAP S/4HANA dans un schéma d'item universel ; (2) Le routeur "Moma OneBox" qui intercepte les requêtes structurées (numéro de ticket, commande SAP PO-*, solde de congés Workday, astreinte On-Call, ou acronyme Whatis) et affiche une carte interactive temps réel au-dessus des résultats ; (3) Le moteur AI Overview (Gemini 3.8 Flash via @google/genai) ancré uniquement sur les documents autorisés par les ACLs de l'utilisateur ; (4) Le résolveur DNS/HTTP go/links et le graphe d'annuaire Teams.`,
      source_system: 'Atlassian Confluence (Architecture)',
      category: 'Architecture & Engineering',
      owner_ldap: 'jassouline',
      go_link: 'go/architecture',
      tags: ['moma', 'architecture', 'onebox', 'connecteurs', 'gemini', 'go links', 'acl', 'client', 'sharepoint', 'sap'],
      visibility_dept: 'ALL',
      min_role: 'employee',
      updated_at: '2026-10-28',
    },
    {
      doc_code: 'DOC-ENG-002',
      connector_key: 'atlassian',
      title: 'Procédure d’Astreinte SRE (On-Call) & Gestion des Incidents P0 / P1',
      summary: 'Runbook Confluence pour les ingénieurs d’astreinte : temps de réponse SLA (5 min en P0), salon d’incident et post-mortem sans blâme.',
      content: `Lorsqu'une alerte P0 est déclenchée, l'ingénieur en astreinte primaire sur go/oncall dispose de 5 minutes pour acquitter la notification PagerDuty/Jira. En cas de non-réponse, l'escalade automatique contacte l'astreinte secondaire puis le manager d'ingénierie. Tout incident P0/P1 fait l'objet d'un Post-Mortem "Blameless" dans Confluence sous 72 heures avec actions préventives suivies dans Jira.`,
      source_system: 'Atlassian Confluence (SRE)',
      category: 'Architecture & Engineering',
      owner_ldap: 'thomasr',
      go_link: 'go/oncall',
      tags: ['oncall', 'astreinte', 'sre', 'incident', 'p0', 'post-mortem', 'slo', 'alerte'],
      visibility_dept: 'ALL',
      min_role: 'employee',
      updated_at: '2026-10-25',
    },
    {
      doc_code: 'DOC-ENG-003',
      connector_key: 'gitlab',
      title: 'Standard d’Intégration Gemini 3.8 Flash & SDK Connecteurs Custom (@google/genai)',
      summary: 'Guide GitLab interne : comment utiliser gemini-3.8-flash (client.interactions.create) et déclarer un nouveau connecteur métier dans Moma-bis.',
      content: `Tous les projets internes d'IA générative utilisent le SDK @google/genai (>= 2.3.0) via client.interactions.create({ model: 'gemini-3.8-flash', input: ... }). Pour intégrer un outil métier spécifique au client (ex: ERP interne, CRM Salesforce, Zendesk, API REST maison), utilisez l'onglet "Connecteurs & Outils Client" de Moma-bis : déclarez l'URL de base, le protocole d'authentification, le préfixe OneBox et le groupe ACL autorisé.`,
      source_system: 'GitLab Enterprise Wiki',
      category: 'Architecture & Engineering',
      owner_ldap: 'jassouline',
      go_link: 'go/gemini-sandbox',
      tags: ['gemini', 'ia', 'sdk', 'interactions', 'genai', 'connecteur', 'api', 'flash', 'gitlab'],
      visibility_dept: 'ALL',
      min_role: 'employee',
      updated_at: '2026-10-27',
    },
    {
      doc_code: 'DOC-FIN-001',
      connector_key: 'sap-erp',
      title: 'Procédure d’Achats, Commandes Fournisseurs (PO) & Notes de Frais dans SAP Ariba',
      summary: 'Seuils d’approbation budgétaire, création d’un Purchase Order (PO-*) dans SAP S/4HANA et remboursement des notes de frais sous 5 jours.',
      content: `Toute dépense externe (logiciel SaaS, prestation, matériel spécifique) supérieure à 1 000 € HT doit faire l'objet d'une demande d'achat (Purchase Requisition) sur go/sap (SAP Ariba), générant un numéro de bon de commande PO-2026-XXXX. Les notes de frais collaborateurs (déplacements, repas clients, budget télétravail 500 € WFH-EQUIP) sont remboursées par virement SEPA sous 5 jours ouvrés après scan du justificatif.`,
      source_system: 'SAP S/4HANA & Ariba',
      category: 'Finance & Achats',
      owner_ldap: 'clairem',
      go_link: 'go/sap',
      tags: ['sap', 'achat', 'commande', 'po', 'fournisseur', 'note de frais', 'budget', 'ariba', 'finance'],
      visibility_dept: 'ALL',
      min_role: 'employee',
      updated_at: '2026-10-21',
    },
    {
      doc_code: 'DOC-SEC-001',
      connector_key: 'secops-vault',
      title: '[CONFIDENTIEL SECOPS] Runbook de Réponse aux Incidents Cyber & Rotation KMS d’Urgence',
      summary: 'Procédure restreinte aux équipes Sécurité & Direction : révocation massive des sessions BFF, rotation des clés KMS et isolation BeyondCorp.',
      content: `DOCUMENT RESTREINT (ACL : Security / Executive Admins uniquement). En cas de compromission avérée d'un jeton ou d'un poste d'administration : (1) Déclencher la procédure d'isolation réseau immédiate sur la console BeyondCorp IAP ; (2) Exécuter la rotation forcée des clés maîtresses Cloud KMS et invalider toutes les sessions actives du BFF ; (3) Conserver les journaux d'audit immuables dans le SIEM SecOps.`,
      source_system: 'SecOps Vault (ACL Restricted)',
      category: 'Security Restricted',
      owner_ldap: 'sophiel',
      go_link: 'go/sec-incident',
      tags: ['secops', 'confidentiel', 'kms', 'compromission', 'forensique', 'incident', 'sécurité'],
      visibility_dept: 'Security',
      min_role: 'security_admin',
      updated_at: '2026-10-26',
    },
    {
      doc_code: 'DOC-HR-004',
      connector_key: 'workday',
      title: '[CONFIDENTIEL RH] Grille de Rémunération & Calibration Annuelle GRAD 2026',
      summary: 'Document Workday réservé à People Ops & Direction : barèmes de rémunération L4 à L9, enveloppes d’actions gratuites (RSU) et calibration.',
      content: `DOCUMENT RESTREINT (ACL : People Ops / Executive Admins uniquement). Ce guide détaille les fourchettes de salaire de base, les bonus cibles (15% à 30%) et les attributions annuelles d'actions (Equity Refresh) pour les niveaux L4 à L9 lors des comités de calibration GRAD du quatrième trimestre 2026.`,
      source_system: 'Workday Compensation Vault (ACL Restricted)',
      category: 'HR Restricted',
      owner_ldap: 'nadiab',
      go_link: 'go/okrs',
      tags: ['salaire', 'rémunération', 'grad', 'rsu', 'bonus', 'calibration', 'rh'],
      visibility_dept: 'People Ops',
      min_role: 'hr_manager',
      updated_at: '2026-10-22',
    },
  ];

  for (const d of seedDocs) {
    insertDoc.run(
      d.doc_code,
      d.connector_key,
      d.title,
      d.summary,
      d.content,
      d.source_system,
      d.category,
      d.owner_ldap,
      d.go_link,
      JSON.stringify(d.tags),
      d.visibility_dept,
      d.min_role,
      d.updated_at
    );
  }

  // 10. Seed Tickets linked to Connectors
  const insertTicket = db.prepare(`
    INSERT INTO tickets (
      ticket_key, connector_key, title, status, priority, system_name, requester_ldap, assignee_ldap, summary, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const seedTickets = [
    {
      ticket_key: 'IT-4092',
      connector_key: 'servicenow',
      title: 'Déploiement du domaine de recherche DNS interne "go.corp.internal" sur tous les réseaux',
      status: 'En cours',
      priority: 'P1 - Haute',
      system_name: 'ServiceNow ITSM',
      requester_ldap: 'jassouline',
      assignee_ldap: 'marcdu',
      summary: 'Configuration DHCP Option 119 et résolveur CoreDNS pour permettre la résolution native de http://go/<alias> sur tous les sous-réseaux.',
      updated_at: '2026-10-28 09:15',
    },
    {
      ticket_key: 'SRE-1184',
      connector_key: 'atlassian',
      title: 'Optimisation du cache d’indexation ACL multi-connecteurs (< 80ms P95)',
      status: 'Résolu',
      priority: 'P2 - Normale',
      system_name: 'Atlassian Jira',
      requester_ldap: 'karimz',
      assignee_ldap: 'thomasr',
      summary: 'Mise en cache des groupes d’appartenance Entra ID / LDAP avec invalidation par webhook lors des changements d’équipe Workday.',
      updated_at: '2026-10-27 17:40',
    },
    {
      ticket_key: 'IT-4105',
      connector_key: 'servicenow',
      title: 'Commande MacBook Pro 16" M4 Max (64 Go) — Renouvellement 36 mois',
      status: 'Prêt au TechStop',
      priority: 'P3 - Standard',
      system_name: 'ServiceNow ITSM',
      requester_ldap: 'elodiep',
      assignee_ldap: 'camilled',
      summary: 'Le poste est pré-enrôlé dans MDM Zero-Touch et disponible au comptoir TechStop Paris (1er étage).',
      updated_at: '2026-10-28 08:50',
    },
    {
      ticket_key: 'PO-8841',
      connector_key: 'sap-erp',
      title: 'Validation Commande SAP Ariba — Serveurs d’inférence & Licences Enterprise',
      status: 'Approuvé',
      priority: 'P2 - Normale',
      system_name: 'SAP S/4HANA Ariba',
      requester_ldap: 'jassouline',
      assignee_ldap: 'clairem',
      summary: 'Bon de commande PO-8841 validé sur le centre de coût CC-210-ENG-AI.',
      updated_at: '2026-10-28 09:30',
    },
  ];

  for (const t of seedTickets) {
    insertTicket.run(
      t.ticket_key,
      t.connector_key,
      t.title,
      t.status,
      t.priority,
      t.system_name,
      t.requester_ldap,
      t.assignee_ldap,
      t.summary,
      t.updated_at
    );
  }

  // 11. Seed Announcements
  const insertAnnouncement = db.prepare(`
    INSERT INTO announcements (
      title, summary, category, severity, author_ldap, go_link, published_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  const seedAnnouncements = [
    {
      title: 'Nouveau : Studio de Connecteurs, Moma OneBox & Glossaire Whatis disponibles',
      summary: 'Branchez vos outils métiers (SharePoint, Jira, ServiceNow, SAP, Workday), utilisez les opérateurs owner:/source: et décodez les acronymes via go/whatis.',
      category: 'Plateforme Moma-bis',
      severity: 'info',
      author_ldap: 'jassouline',
      go_link: 'go/architecture',
      published_at: 'Aujourd’hui, 09:30',
    },
    {
      title: 'Campagne de renouvellement matériel Q4 2026 ouverte (ServiceNow)',
      summary: 'Les collaborateurs équipés avant octobre 2023 peuvent commander leur nouveau MacBook Pro M4 ou station Linux sur go/new-laptop.',
      category: 'Corp IT',
      severity: 'success',
      author_ldap: 'marcdu',
      go_link: 'go/new-laptop',
      published_at: 'Hier, 14:30',
    },
    {
      title: 'Clôture des congés Workday & Notes de frais SAP de fin d’année',
      summary: 'Pensez à saisir vos congés de décembre sur go/holiday (Workday) et vos notes de frais WFH-EQUIP sur go/sap avant le 15 novembre.',
      category: 'RH & Finance',
      severity: 'warning',
      author_ldap: 'nadiab',
      go_link: 'go/holiday',
      published_at: '26 Oct. 2026',
    },
  ];

  for (const a of seedAnnouncements) {
    insertAnnouncement.run(
      a.title,
      a.summary,
      a.category,
      a.severity,
      a.author_ldap,
      a.go_link,
      a.published_at
    );
  }
}

export function canUserAccessByDept(user, visibilityDept, minRole = 'employee') {
  if (!user) return false;
  if (visibilityDept === 'ALL' && minRole === 'employee') {
    return true;
  }
  if (user.role === 'admin' && user.department === 'Executive') {
    return true;
  }
  if (visibilityDept === 'Security' && (user.department === 'Security' || user.role === 'security_admin')) {
    return true;
  }
  if (visibilityDept === 'People Ops' && (user.department === 'People Ops' || user.role === 'hr_manager')) {
    return true;
  }
  if (visibilityDept === user.department) {
    return true;
  }
  return false;
}

export function canUserAccessDocument(user, doc) {
  if (!user || !doc) return false;
  return canUserAccessByDept(user, doc.visibility_dept, doc.min_role);
}

export function formatUserProfile(row, revealPii = false) {
  if (!row) return null;
  return {
    id: row.id,
    ldap: row.ldap,
    fullName: row.full_name,
    title: row.title,
    level: row.level,
    department: row.department,
    team: row.team,
    managerLdap: row.manager_ldap,
    office: row.office,
    deskLocation: row.desk_location,
    presenceStatus: row.presence_status,
    presenceLabel: row.presence_label,
    timezone: row.timezone,
    workingHours: row.working_hours,
    email: revealPii ? row.email : maskEmail(row.email),
    phone: revealPii ? row.phone : maskPhone(row.phone),
    piiMasked: !revealPii,
    costCenter: row.cost_center,
    hireDate: row.hire_date,
    avatarColor: row.avatar_color,
    badges: JSON.parse(row.badges_json || '[]'),
    skills: JSON.parse(row.skills_json || '[]'),
    projects: JSON.parse(row.projects_json || '[]'),
    groups: JSON.parse(row.groups_json || '[]'),
    bio: row.bio,
    role: row.role,
  };
}

export function getUserByLdap(ldap, revealPii = false) {
  const stmt = db.prepare('SELECT * FROM users WHERE ldap = ? AND active = 1');
  const row = stmt.get(String(ldap || '').trim().toLowerCase());
  return formatUserProfile(row, revealPii);
}

/**
 * Resolves an enterprise user from an IAP / Reverse-Proxy identity header
 * (e.g. "accounts.google.com:jordan.assouline@corp.internal" or "jassouline").
 */
export function getUserByIdentity(rawIdentity, revealPii = false) {
  if (!rawIdentity || typeof rawIdentity !== 'string') return null;
  const cleaned = rawIdentity.trim().toLowerCase().replace(/^accounts\.google\.com:/, '');
  if (!cleaned) return null;
  if (cleaned.includes('@')) {
    const byEmail = db.prepare('SELECT * FROM users WHERE LOWER(email) = ? AND active = 1').get(cleaned);
    if (byEmail) return formatUserProfile(byEmail, revealPii);
    const localPart = cleaned.split('@')[0].replace(/[^a-z0-9_-]/g, '');
    return getUserByLdap(localPart, revealPii);
  }
  return getUserByLdap(cleaned, revealPii);
}

export function listAllUsers(searchQuery = '', departmentFilter = '') {
  const q = String(searchQuery || '').trim().toLowerCase();
  const dept = String(departmentFilter || '').trim();

  let rows;
  if (q && dept) {
    const like = `%${q}%`;
    rows = db.prepare(`
      SELECT * FROM users
      WHERE active = 1
        AND department = ?
        AND (
          LOWER(ldap) LIKE ?
          OR LOWER(full_name) LIKE ?
          OR LOWER(title) LIKE ?
          OR LOWER(team) LIKE ?
          OR LOWER(office) LIKE ?
          OR LOWER(skills_json) LIKE ?
          OR LOWER(badges_json) LIKE ?
          OR LOWER(groups_json) LIKE ?
        )
      ORDER BY full_name ASC
    `).all(dept, like, like, like, like, like, like, like, like);
  } else if (q) {
    const like = `%${q}%`;
    rows = db.prepare(`
      SELECT * FROM users
      WHERE active = 1
        AND (
          LOWER(ldap) LIKE ?
          OR LOWER(full_name) LIKE ?
          OR LOWER(title) LIKE ?
          OR LOWER(department) LIKE ?
          OR LOWER(team) LIKE ?
          OR LOWER(office) LIKE ?
          OR LOWER(skills_json) LIKE ?
          OR LOWER(badges_json) LIKE ?
          OR LOWER(groups_json) LIKE ?
        )
      ORDER BY full_name ASC
    `).all(like, like, like, like, like, like, like, like, like);
  } else if (dept) {
    rows = db.prepare(`
      SELECT * FROM users
      WHERE active = 1 AND department = ?
      ORDER BY full_name ASC
    `).all(dept);
  } else {
    rows = db.prepare('SELECT * FROM users WHERE active = 1 ORDER BY id ASC').all();
  }

  return rows.map((r) => formatUserProfile(r, false));
}

export function getOrgChartForUser(ldap, revealPii = false) {
  const target = getUserByLdap(ldap, revealPii);
  if (!target) return null;

  const managementChain = [];
  let currentManagerLdap = target.managerLdap;
  const visited = new Set([target.ldap]);
  while (currentManagerLdap && !visited.has(currentManagerLdap)) {
    visited.add(currentManagerLdap);
    const mgr = getUserByLdap(currentManagerLdap, false);
    if (!mgr) break;
    managementChain.unshift(mgr);
    currentManagerLdap = mgr.managerLdap;
  }

  let peers = [];
  if (target.managerLdap) {
    const peerRows = db.prepare(`
      SELECT * FROM users
      WHERE active = 1 AND manager_ldap = ? AND ldap != ?
      ORDER BY full_name ASC
    `).all(target.managerLdap, target.ldap);
    peers = peerRows.map((r) => formatUserProfile(r, false));
  }

  const reportRows = db.prepare(`
    SELECT * FROM users
    WHERE active = 1 AND manager_ldap = ?
    ORDER BY full_name ASC
  `).all(target.ldap);
  const directReports = reportRows.map((r) => formatUserProfile(r, false));

  const ownedGoLinks = db.prepare(`
    SELECT * FROM go_links
    WHERE owner_ldap = ?
    ORDER BY hits DESC
  `).all(target.ldap);

  const authoredDocs = db.prepare(`
    SELECT doc_code, title, category, go_link, visibility_dept, updated_at
    FROM documents
    WHERE owner_ldap = ? AND visibility_dept = 'ALL'
    ORDER BY updated_at DESC
  `).all(target.ldap);

  return {
    profile: target,
    managementChain,
    peers,
    directReports,
    ownedGoLinks,
    authoredDocs,
  };
}

/**
 * Connectors & Custom Enterprise Tool Integration APIs
 */
export function listConnectors() {
  const rows = db.prepare('SELECT * FROM connectors ORDER BY is_custom DESC, id ASC').all();
  const docCounts = db.prepare('SELECT connector_key, COUNT(*) AS cnt FROM documents GROUP BY connector_key').all();
  const ticketCounts = db.prepare('SELECT connector_key, COUNT(*) AS cnt FROM tickets GROUP BY connector_key').all();
  const oneboxCounts = db.prepare('SELECT connector_key, COUNT(*) AS cnt FROM onebox_cards GROUP BY connector_key').all();

  const docMap = new Map(docCounts.map((r) => [r.connector_key, r.cnt]));
  const ticketMap = new Map(ticketCounts.map((r) => [r.connector_key, r.cnt]));
  const obMap = new Map(oneboxCounts.map((r) => [r.connector_key, r.cnt]));

  return rows.map((r) => ({
    connectorKey: r.connector_key,
    name: r.name,
    vendor: r.vendor,
    category: r.category,
    protocol: r.protocol,
    baseUrl: r.base_url,
    oneboxTrigger: r.onebox_trigger,
    aclMode: r.acl_mode,
    visibilityDept: r.visibility_dept,
    enabled: Boolean(r.enabled),
    isCustom: Boolean(r.is_custom),
    ownerLdap: r.owner_ldap,
    lastSyncAt: r.last_sync_at,
    stats: {
      documents: docMap.get(r.connector_key) || 0,
      tickets: ticketMap.get(r.connector_key) || 0,
      oneboxes: obMap.get(r.connector_key) || 0,
    },
  }));
}

export function toggleConnectorState(connectorKey, currentUser) {
  if (!currentUser) {
    throw new Error('Authentification requise.');
  }
  const cleanKey = String(connectorKey || '').trim().toLowerCase();
  const existing = db.prepare('SELECT * FROM connectors WHERE connector_key = ?').get(cleanKey);
  if (!existing) {
    throw new Error('Connecteur introuvable.');
  }
  const nextState = existing.enabled ? 0 : 1;
  db.prepare('UPDATE connectors SET enabled = ?, last_sync_at = ? WHERE connector_key = ?').run(
    nextState,
    nextState ? 'Synchronisé à l’instant' : 'Désactivé (Hors index)',
    cleanKey
  );
  recordAuditLog({
    actorLdap: currentUser.ldap,
    action: 'CONNECTOR_TOGGLE',
    targetType: 'connector',
    targetKey: cleanKey,
    metadata: { enabled: Boolean(nextState) },
  });
  return listConnectors().find((c) => c.connectorKey === cleanKey);
}

export function registerCustomToolConnector(payload, currentUser) {
  if (!currentUser) {
    throw new Error('Authentification requise.');
  }
  const rawKey = String(payload.connectorKey || payload.name || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-_]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 32);

  if (!rawKey || rawKey.length < 2) {
    throw new Error('Identifiant du connecteur invalide (minimum 2 caractères alphanumériques).');
  }

  const name = String(payload.name || '').trim();
  const vendor = String(payload.vendor || 'Outil Interne Client').trim();
  const category = String(payload.category || 'Outil Métier Interne').trim();
  const protocol = String(payload.protocol || 'REST API + Webhook + OAuth 2.0').trim();
  const baseUrlRaw = String(payload.baseUrl || `https://${rawKey}.corp.internal`).trim();
  const oneboxTrigger = String(payload.oneboxTrigger || rawKey).trim().toLowerCase();
  const visibilityDept = String(payload.visibilityDept || 'ALL').trim();
  const sampleTitle = String(payload.sampleTitle || `Guide & Données temps réel — ${name}`).trim();
  const sampleContent = String(
    payload.sampleContent ||
      `Outil interne ${name} intégré au moteur fédéré WhatsMomat. Accessible via le raccourci go/${rawKey}.`
  ).trim();
  const oneboxMetricLabel = String(payload.oneboxMetricLabel || 'Statut Intégration Live').trim();
  const oneboxMetricValue = String(
    payload.oneboxMetricValue || 'Connecté en temps réel (Webhook & Index ACL actifs)'
  ).trim();

  if (name.length < 2 || name.length > 90) {
    throw new Error('Le nom de l’outil doit contenir entre 2 et 90 caractères.');
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(baseUrlRaw);
  } catch {
    throw new Error('L’URL de base de l’outil est invalide (ex: https://mon-outil.corp.internal).');
  }
  if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
    throw new Error('Le protocole de l’URL doit être https:// ou http://.');
  }

  const allowedDepts = ['ALL', 'Engineering', 'Security', 'IT Operations', 'People Ops', 'Executive'];
  const safeDept = allowedDepts.includes(visibilityDept) ? visibilityDept : 'ALL';

  const existing = db.prepare('SELECT * FROM connectors WHERE connector_key = ?').get(rawKey);
  if (existing) {
    throw new Error(`Un connecteur avec la clé "${rawKey}" existe déjà.`);
  }

  db.prepare(`
    INSERT INTO connectors (
      connector_key, name, vendor, category, protocol, base_url,
      onebox_trigger, acl_mode, visibility_dept, enabled, is_custom, owner_ldap, last_sync_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, 'Synchronisé à l’instant (Custom SDK)')
  `).run(
    rawKey,
    name,
    vendor,
    category,
    protocol,
    parsedUrl.toString(),
    oneboxTrigger,
    safeDept === 'ALL' ? 'Identity-Aware (Tous les collaborateurs)' : `ACL Restreinte (${safeDept})`,
    safeDept,
    currentUser.ldap
  );

  const oneboxFields = [
    { label: oneboxMetricLabel, value: oneboxMetricValue },
    { label: 'Protocole & Connecteur', value: `${protocol} (${parsedUrl.host})` },
    { label: 'Propriétaire Intégration', value: `@${currentUser.ldap} (${currentUser.department})` },
  ];
  db.prepare(`
    INSERT INTO onebox_cards (
      connector_key, trigger_keywords, card_title, card_subtitle, badge_text,
      fields_json, action_label, action_go_link, visibility_dept
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    rawKey,
    `${rawKey}, ${oneboxTrigger}, ${name.toLowerCase()}`,
    `OneBox ${name} — Vue Temps Réel`,
    `Données fédérées en direct depuis ${parsedUrl.origin}`,
    `${vendor} OneBox`,
    JSON.stringify(oneboxFields),
    `Ouvrir go/${rawKey}`,
    `go/${rawKey}`,
    safeDept
  );

  const docCode = `CUST-${rawKey.toUpperCase().slice(0, 8)}-01`;
  const tags = oneboxTrigger
    .split(/[,;\s]+/)
    .map((t) => t.trim())
    .filter(Boolean);
  if (!tags.includes(rawKey)) tags.push(rawKey);

  db.prepare(`
    INSERT INTO documents (
      doc_code, connector_key, title, summary, content, source_system, category,
      owner_ldap, go_link, tags_json, visibility_dept, min_role, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'employee', ?)
  `).run(
    docCode,
    rawKey,
    sampleTitle,
    sampleContent.slice(0, 180),
    sampleContent,
    `${name} (${vendor})`,
    category,
    currentUser.ldap,
    `go/${rawKey}`,
    JSON.stringify(tags),
    safeDept,
    new Date().toISOString().slice(0, 10)
  );
  const createdDoc = db.prepare('SELECT * FROM documents WHERE doc_code = ?').get(docCode);
  syncDocumentFts(createdDoc);

  const existingGo = db.prepare('SELECT * FROM go_links WHERE slug = ?').get(rawKey);
  if (!existingGo) {
    const nowIso = new Date().toISOString();
    db.prepare(`
      INSERT INTO go_links (
        slug, target_url, title, description, category, owner_ldap, hits, is_verified, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'Engineering & SRE', ?, 1, 1, ?, ?)
    `).run(
      rawKey,
      parsedUrl.toString(),
      `${name} — Portail Outil Interne`,
      `Accès direct à l’outil ${name} (${vendor}) intégré dans WhatsMomat par @${currentUser.ldap}.`,
      currentUser.ldap,
      nowIso,
      nowIso
    );
  }

  recordAuditLog({
    actorLdap: currentUser.ldap,
    action: 'CONNECTOR_REGISTER',
    targetType: 'connector',
    targetKey: rawKey,
    metadata: { vendor, visibilityDept: safeDept },
  });

  return listConnectors().find((c) => c.connectorKey === rawKey);
}

/**
 * External Push / Webhook REST Ingestion API (/api/v1/ingest)
 * Allows real enterprise IT tools (Jira, ServiceNow, SharePoint, GitLab CI, SAP, Python scripts)
 * to push ACL-tagged documents, ITSM tickets, and live OneBox metrics into WhatsMomat.
 */
export function ingestExternalData(payload, actorLdap = 'system-webhook', clientIp = '127.0.0.1') {
  const rawConnectorKey = String(payload?.connectorKey || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-_]+/g, '-');
  if (!rawConnectorKey || rawConnectorKey.length < 2) {
    throw new Error('Le champ connectorKey est requis pour l’ingestion (ex: servicenow, sharepoint, custom-crm).');
  }

  const connectorRow = db.prepare('SELECT * FROM connectors WHERE connector_key = ?').get(rawConnectorKey);
  if (!connectorRow) {
    throw new Error(`Connecteur "${rawConnectorKey}" inconnu. Enregistrez-le d’abord dans le Connector Studio.`);
  }

  const allowedDepts = ['ALL', 'Engineering', 'Security', 'IT Operations', 'People Ops', 'Executive'];
  const allowedRoles = ['employee', 'hr_manager', 'security_admin', 'admin'];
  const today = new Date().toISOString().slice(0, 10);

  let upsertedDocs = 0;
  let upsertedTickets = 0;
  let updatedOneBox = false;

  if (Array.isArray(payload.documents)) {
    for (const rawDoc of payload.documents.slice(0, 100)) {
      const docCode = String(rawDoc.docCode || '')
        .trim()
        .toUpperCase()
        .replace(/[^A-Z0-9-_]/g, '')
        .slice(0, 36);
      const title = String(rawDoc.title || '').trim().slice(0, 180);
      const content = String(rawDoc.content || '').trim().slice(0, 8000);
      if (!docCode || !title || !content) continue;

      const summary = String(rawDoc.summary || content.slice(0, 180)).trim().slice(0, 280);
      const sourceSystem = String(rawDoc.sourceSystem || connectorRow.name).trim().slice(0, 90);
      const category = String(rawDoc.category || connectorRow.category || 'Enterprise Docs').trim().slice(0, 60);
      const ownerLdap = String(rawDoc.ownerLdap || connectorRow.owner_ldap || actorLdap)
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9_-]/g, '') || 'jassouline';
      const goLink = rawDoc.goLink ? String(rawDoc.goLink).trim().slice(0, 60) : null;
      const tagsArr = Array.isArray(rawDoc.tags)
        ? rawDoc.tags.map((t) => String(t).trim().toLowerCase()).filter(Boolean).slice(0, 15)
        : [rawConnectorKey];
      const safeDept = allowedDepts.includes(rawDoc.visibilityDept)
        ? rawDoc.visibilityDept
        : connectorRow.visibility_dept || 'ALL';
      const safeMinRole = allowedRoles.includes(rawDoc.minRole) ? rawDoc.minRole : 'employee';

      const existingDoc = db.prepare('SELECT id FROM documents WHERE doc_code = ?').get(docCode);
      if (existingDoc) {
        db.prepare(`
          UPDATE documents
          SET connector_key = ?, title = ?, summary = ?, content = ?, source_system = ?,
              category = ?, owner_ldap = ?, go_link = ?, tags_json = ?, visibility_dept = ?, min_role = ?, updated_at = ?
          WHERE doc_code = ?
        `).run(
          rawConnectorKey,
          title,
          summary,
          content,
          sourceSystem,
          category,
          ownerLdap,
          goLink,
          JSON.stringify(tagsArr),
          safeDept,
          safeMinRole,
          today,
          docCode
        );
      } else {
        db.prepare(`
          INSERT INTO documents (
            doc_code, connector_key, title, summary, content, source_system, category,
            owner_ldap, go_link, tags_json, visibility_dept, min_role, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          docCode,
          rawConnectorKey,
          title,
          summary,
          content,
          sourceSystem,
          category,
          ownerLdap,
          goLink,
          JSON.stringify(tagsArr),
          safeDept,
          safeMinRole,
          today
        );
      }
      const savedDoc = db.prepare('SELECT * FROM documents WHERE doc_code = ?').get(docCode);
      syncDocumentFts(savedDoc);
      upsertedDocs += 1;
    }
  }

  if (Array.isArray(payload.tickets)) {
    for (const rawTicket of payload.tickets.slice(0, 100)) {
      const ticketKey = String(rawTicket.ticketKey || '')
        .trim()
        .toUpperCase()
        .replace(/[^A-Z0-9-_]/g, '')
        .slice(0, 32);
      const title = String(rawTicket.title || '').trim().slice(0, 160);
      if (!ticketKey || !title) continue;
      const status = String(rawTicket.status || 'Ouvert').trim().slice(0, 48);
      const priority = String(rawTicket.priority || 'P2 - Normale').trim().slice(0, 32);
      const systemName = String(rawTicket.systemName || connectorRow.name).trim().slice(0, 80);
      const requesterLdap = String(rawTicket.requesterLdap || actorLdap).trim().toLowerCase().slice(0, 32);
      const assigneeLdap = String(rawTicket.assigneeLdap || connectorRow.owner_ldap).trim().toLowerCase().slice(0, 32);
      const summary = String(rawTicket.summary || title).trim().slice(0, 350);

      const existingTicket = db.prepare('SELECT id FROM tickets WHERE ticket_key = ?').get(ticketKey);
      if (existingTicket) {
        db.prepare(`
          UPDATE tickets
          SET connector_key = ?, title = ?, status = ?, priority = ?, system_name = ?,
              requester_ldap = ?, assignee_ldap = ?, summary = ?, updated_at = ?
          WHERE ticket_key = ?
        `).run(
          rawConnectorKey,
          title,
          status,
          priority,
          systemName,
          requesterLdap,
          assigneeLdap,
          summary,
          today,
          ticketKey
        );
      } else {
        db.prepare(`
          INSERT INTO tickets (
            ticket_key, connector_key, title, status, priority, system_name,
            requester_ldap, assignee_ldap, summary, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          ticketKey,
          rawConnectorKey,
          title,
          status,
          priority,
          systemName,
          requesterLdap,
          assigneeLdap,
          summary,
          today
        );
      }
      upsertedTickets += 1;
    }
  }

  if (payload.oneboxCard && typeof payload.oneboxCard === 'object') {
    const ob = payload.oneboxCard;
    const cardTitle = String(ob.cardTitle || `OneBox ${connectorRow.name}`).trim().slice(0, 140);
    const cardSubtitle = String(ob.cardSubtitle || `Synchronisé via API /api/v1/ingest (${today})`).trim().slice(0, 180);
    const badgeText = String(ob.badgeText || `${connectorRow.vendor} Live`).trim().slice(0, 48);
    const triggerKeywords = String(ob.triggerKeywords || connectorRow.onebox_trigger || rawConnectorKey)
      .trim()
      .toLowerCase()
      .slice(0, 200);
    const fields = Array.isArray(ob.fields)
      ? ob.fields
          .slice(0, 6)
          .map((f) => ({
            label: String(f.label || '').trim().slice(0, 60),
            value: String(f.value || '').trim().slice(0, 160),
          }))
          .filter((f) => f.label && f.value)
      : [];
    const actionLabel = String(ob.actionLabel || `Ouvrir go/${rawConnectorKey}`).trim().slice(0, 60);
    const actionGoLink = String(ob.actionGoLink || `go/${rawConnectorKey}`).trim().slice(0, 60);
    const safeDept = allowedDepts.includes(ob.visibilityDept)
      ? ob.visibilityDept
      : connectorRow.visibility_dept || 'ALL';

    if (fields.length > 0) {
      const existingOb = db.prepare('SELECT id FROM onebox_cards WHERE connector_key = ?').get(rawConnectorKey);
      if (existingOb) {
        db.prepare(`
          UPDATE onebox_cards
          SET trigger_keywords = ?, card_title = ?, card_subtitle = ?, badge_text = ?,
              fields_json = ?, action_label = ?, action_go_link = ?, visibility_dept = ?
          WHERE id = ?
        `).run(
          triggerKeywords,
          cardTitle,
          cardSubtitle,
          badgeText,
          JSON.stringify(fields),
          actionLabel,
          actionGoLink,
          safeDept,
          existingOb.id
        );
      } else {
        db.prepare(`
          INSERT INTO onebox_cards (
            connector_key, trigger_keywords, card_title, card_subtitle, badge_text,
            fields_json, action_label, action_go_link, visibility_dept
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          rawConnectorKey,
          triggerKeywords,
          cardTitle,
          cardSubtitle,
          badgeText,
          JSON.stringify(fields),
          actionLabel,
          actionGoLink,
          safeDept
        );
      }
      updatedOneBox = true;
    }
  }

  db.prepare('UPDATE connectors SET last_sync_at = ? WHERE connector_key = ?').run(
    `Ingéré via API (${new Date().toISOString().slice(11, 19)} UTC)`,
    rawConnectorKey
  );

  recordAuditLog({
    actorLdap,
    action: 'CONNECTOR_INGEST',
    targetType: 'connector',
    targetKey: rawConnectorKey,
    metadata: { upsertedDocs, upsertedTickets, updatedOneBox },
    clientIp,
  });

  return {
    connectorKey: rawConnectorKey,
    upsertedDocs,
    upsertedTickets,
    updatedOneBox,
  };
}

/**
 * Whatis Acronym Glossary APIs
 */
export function listAcronyms(searchQuery = '', categoryFilter = '') {
  const q = String(searchQuery || '')
    .trim()
    .toLowerCase()
    .replace(/^(whatis|define)[:\s]+/i, '');
  const cat = String(categoryFilter || '').trim();
  const hasCat = Boolean(cat && cat.toUpperCase() !== 'ALL');

  let rows;
  if (q && hasCat) {
    const like = `%${q}%`;
    rows = db.prepare(`
      SELECT * FROM acronyms
      WHERE category = ?
        AND (LOWER(term) LIKE ? OR LOWER(expansion) LIKE ? OR LOWER(definition) LIKE ?)
      ORDER BY upvotes DESC, term ASC
    `).all(cat, like, like, like);
  } else if (q) {
    const like = `%${q}%`;
    rows = db.prepare(`
      SELECT * FROM acronyms
      WHERE LOWER(term) LIKE ? OR LOWER(expansion) LIKE ? OR LOWER(definition) LIKE ?
      ORDER BY upvotes DESC, term ASC
    `).all(like, like, like);
  } else if (hasCat) {
    rows = db.prepare(`
      SELECT * FROM acronyms
      WHERE category = ?
      ORDER BY upvotes DESC, term ASC
    `).all(cat);
  } else {
    rows = db.prepare('SELECT * FROM acronyms ORDER BY upvotes DESC, term ASC').all();
  }
  return rows.map((a) => ({
    ...a,
    acronym: a.term,
    full_expansion: a.expansion,
    go_link: a.related_go_link,
    owner_ldap: a.author_ldap,
  }));
}

export function createAcronym(payload, currentUser) {
  if (!currentUser) {
    throw new Error('Authentification requise.');
  }
  const rawTerm = payload.term || payload.acronym || '';
  const rawExpansion = payload.expansion || payload.fullExpansion || '';
  const rawDef = payload.definition || '';
  const rawCat = payload.category || 'Engineering & SRE';
  const rawGo = payload.relatedGoLink || payload.goLink || '';

  const cleanTerm = String(rawTerm)
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9-_/]/g, '')
    .slice(0, 24);
  if (cleanTerm.length < 2) {
    throw new Error('L’acronyme doit comporter entre 2 et 24 caractères (ex: OKR, SLA, FINOPS).');
  }
  const cleanExpansion = String(rawExpansion).trim();
  const cleanDef = String(rawDef).trim();
  const cleanCat = String(rawCat).trim();
  const cleanGo = String(rawGo).trim() || null;

  if (cleanExpansion.length < 3 || cleanDef.length < 5) {
    throw new Error('Veuillez renseigner la signification complète et la définition.');
  }

  const existing = db.prepare('SELECT * FROM acronyms WHERE term = ?').get(cleanTerm);
  const nowDate = new Date().toISOString().slice(0, 10);
  if (existing) {
    db.prepare(`
      UPDATE acronyms
      SET expansion = ?, definition = ?, category = ?, related_go_link = ?, updated_at = ?, upvotes = upvotes + 1
      WHERE term = ?
    `).run(cleanExpansion, cleanDef, cleanCat, cleanGo, nowDate, cleanTerm);
  } else {
    db.prepare(`
      INSERT INTO acronyms (term, expansion, definition, category, related_go_link, author_ldap, upvotes, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, ?)
    `).run(cleanTerm, cleanExpansion, cleanDef, cleanCat, cleanGo, currentUser.ldap, nowDate);
  }
  const saved = db.prepare('SELECT * FROM acronyms WHERE term = ?').get(cleanTerm);
  return {
    ...saved,
    acronym: saved.term,
    full_expansion: saved.expansion,
    go_link: saved.related_go_link,
    owner_ldap: saved.author_ldap,
  };
}

/**
 * Actionable Approvals & Quick Ticket Creation ("My Moma" Actions)
 */
export function actOnApproval(approvalKey, decision, currentUser) {
  if (!currentUser) {
    throw new Error('Authentification requise.');
  }
  const cleanKey = String(approvalKey || '').trim();
  const existing = db.prepare('SELECT * FROM approvals WHERE approval_key = ?').get(cleanKey);
  if (!existing) {
    throw new Error('Demande d’approbation introuvable.');
  }
  if (existing.approver_ldap !== currentUser.ldap && currentUser.role !== 'admin') {
    const forbiddenErr = new Error(
      `Accès refusé : seule la personne désignée (@${existing.approver_ldap}) ou un administrateur peut traiter la demande ${cleanKey}.`
    );
    forbiddenErr.statusCode = 403;
    throw forbiddenErr;
  }
  const normDecision = String(decision || '').trim().toLowerCase();
  const nextStatus = normDecision.startsWith('approv') ? 'approved' : 'rejected';
  db.prepare('UPDATE approvals SET status = ? WHERE approval_key = ?').run(nextStatus, cleanKey);
  recordAuditLog({
    actorLdap: currentUser.ldap,
    action: 'APPROVAL_DECISION',
    targetType: 'approval',
    targetKey: cleanKey,
    metadata: { decision: nextStatus.toUpperCase(), requesterLdap: existing.requester_ldap },
  });
  const updated = db.prepare('SELECT * FROM approvals WHERE approval_key = ?').get(cleanKey);
  return {
    ...updated,
    source_system: updated.source_tool,
    amount_or_impact: updated.amount_or_scope,
    status: String(updated.status || '').toUpperCase(),
    can_act: true,
  };
}

export function createQuickTicket(payload, currentUser) {
  if (!currentUser) {
    throw new Error('Authentification requise.');
  }
  const cleanTitle = String(payload.title || '').trim();
  const cleanSummary = String(payload.summary || '').trim();
  if (cleanTitle.length < 4) {
    throw new Error('Le titre du ticket doit contenir au moins 4 caractères.');
  }
  const rawSys = String(payload.systemName || payload.connectorKey || 'ServiceNow ITSM').trim();
  const prio = String(payload.priority || 'P2 - Normale').trim();
  const isJira = rawSys.toLowerCase().includes('jira') || rawSys.toLowerCase().includes('atlassian');
  const isSap = rawSys.toLowerCase().includes('sap');
  const connectorKey = isJira ? 'atlassian' : isSap ? 'sap-erp' : 'servicenow';
  const sysLabel = isJira ? 'Atlassian Jira' : isSap ? 'SAP S/4HANA Ariba' : 'ServiceNow ITSM';
  const randomNum = 4200 + Math.floor(Math.random() * 700);
  const ticketKey = isJira ? `SRE-${randomNum}` : isSap ? `PO-${randomNum}` : `IT-${randomNum}`;
  const assignee = isJira ? 'thomasr' : isSap ? 'clairem' : 'camilled';

  db.prepare(`
    INSERT INTO tickets (
      ticket_key, connector_key, title, status, priority, system_name, requester_ldap, assignee_ldap, summary, updated_at
    ) VALUES (?, ?, ?, 'Nouveau (Créé depuis Moma)', ?, ?, ?, ?, ?, 'À l’instant')
  `).run(
    ticketKey,
    connectorKey,
    cleanTitle,
    prio,
    sysLabel,
    currentUser.ldap,
    assignee,
    cleanSummary || `Ticket ouvert directement depuis le portail Moma-bis par @${currentUser.ldap}.`
  );

  const savedTicket = db.prepare('SELECT * FROM tickets WHERE ticket_key = ?').get(ticketKey);
  return {
    ...savedTicket,
    source_system: savedTicket.system_name,
  };
}

/**
 * Instant Predictive Omnibox Typeahead (Live Dropdown as user types)
 */
export function getOmniboxTypeahead(rawQuery, currentUser) {
  const q = String(rawQuery || '').trim().toLowerCase();
  const operatorHints = [
    { token: 'whatis:GRAD', desc: 'Décoder un acronyme interne via go/whatis' },
    { token: 'owner:sophiel', desc: 'Filtrer par propriétaire @ldap' },
    { token: 'source:servicenow', desc: 'Filtrer par outil / connecteur' },
    { token: 'type:documents', desc: 'Filtrer par type de ressource' },
  ];

  if (!q) {
    return { suggestions: [], operatorHints };
  }

  const suggestions = [];
  const cleanSlug = q.replace(/^go\//, '');

  // 1. Matching go/links
  const goMatches = db.prepare(`
    SELECT slug, title, category, hits FROM go_links
    WHERE LOWER(slug) LIKE ? OR LOWER(title) LIKE ?
    ORDER BY hits DESC LIMIT 3
  `).all(`%${cleanSlug}%`, `%${cleanSlug}%`);
  for (const g of goMatches) {
    suggestions.push({
      type: 'golink',
      kind: 'golink',
      badge: `go/${g.slug}`,
      title: g.title,
      label: `go/${g.slug}`,
      subtitle: `Raccourci direct (${g.hits} visites)`,
      sublabel: `${g.title} (${g.hits} visites)`,
      value: `go/${g.slug}`,
      queryValue: `go/${g.slug}`,
      slug: g.slug,
    });
  }

  // 2. Matching Whatis Acronyms
  const whatisTerm = q.replace(/^(whatis|define)[:\s]+/i, '');
  const acrMatches = db.prepare(`
    SELECT term, expansion, definition FROM acronyms
    WHERE LOWER(term) LIKE ? OR LOWER(expansion) LIKE ?
    ORDER BY upvotes DESC LIMIT 2
  `).all(`%${whatisTerm}%`, `%${whatisTerm}%`);
  for (const a of acrMatches) {
    suggestions.push({
      type: 'whatis',
      kind: 'whatis',
      badge: `whatis:${a.term}`,
      title: `${a.term} — ${a.expansion}`,
      label: `${a.term} (${a.expansion})`,
      subtitle: a.definition.slice(0, 90) + '...',
      sublabel: a.definition.slice(0, 90),
      value: `whatis:${a.term}`,
      queryValue: `whatis:${a.term}`,
    });
  }

  // 3. Matching People (@ldap)
  const personTerm = q.replace(/^who\//, '').replace(/^@/, '');
  const peopleMatches = db.prepare(`
    SELECT ldap, full_name, title, department, office FROM users
    WHERE active = 1 AND (LOWER(ldap) LIKE ? OR LOWER(full_name) LIKE ? OR LOWER(skills_json) LIKE ?)
    LIMIT 3
  `).all(`%${personTerm}%`, `%${personTerm}%`, `%${personTerm}%`);
  for (const p of peopleMatches) {
    suggestions.push({
      type: 'person',
      kind: 'person',
      badge: `@${p.ldap}`,
      title: `${p.full_name} — ${p.title}`,
      label: `${p.full_name} (@${p.ldap})`,
      subtitle: `${p.department} • ${p.office}`,
      sublabel: `${p.title} • ${p.office}`,
      value: p.full_name,
      queryValue: p.full_name,
      ldap: p.ldap,
    });
  }

  // 4. Matching ACL-authorized Documents
  const enabledConnectors = new Set(
    db.prepare('SELECT connector_key FROM connectors WHERE enabled = 1').all().map((c) => c.connector_key)
  );
  const allDocs = db.prepare('SELECT * FROM documents ORDER BY updated_at DESC').all();
  let docAdded = 0;
  for (const d of allDocs) {
    if (docAdded >= 3) break;
    if (!enabledConnectors.has(d.connector_key)) continue;
    if (!canUserAccessDocument(currentUser, d)) continue;
    if (
      d.title.toLowerCase().includes(q) ||
      d.tags_json.toLowerCase().includes(q) ||
      d.doc_code.toLowerCase().includes(q)
    ) {
      suggestions.push({
        type: 'document',
        kind: 'document',
        badge: d.doc_code,
        title: d.title,
        label: d.title,
        subtitle: `${d.source_system} • Owner @${d.owner_ldap}`,
        sublabel: `${d.source_system} • @${d.owner_ldap}`,
        value: d.title,
        queryValue: d.title,
      });
      docAdded += 1;
    }
  }

  return { suggestions: suggestions.slice(0, 9), operatorHints };
}

export function listGoLinks(searchQuery = '', categoryFilter = '') {
  const q = String(searchQuery || '').trim().toLowerCase().replace(/^go\//, '');
  const cat = String(categoryFilter || '').trim();

  if (q && cat) {
    const like = `%${q}%`;
    return db.prepare(`
      SELECT * FROM go_links
      WHERE category = ?
        AND (LOWER(slug) LIKE ? OR LOWER(title) LIKE ? OR LOWER(description) LIKE ? OR LOWER(owner_ldap) LIKE ?)
      ORDER BY hits DESC
    `).all(cat, like, like, like, like);
  }
  if (q) {
    const like = `%${q}%`;
    return db.prepare(`
      SELECT * FROM go_links
      WHERE LOWER(slug) LIKE ? OR LOWER(title) LIKE ? OR LOWER(description) LIKE ? OR LOWER(owner_ldap) LIKE ?
      ORDER BY hits DESC
    `).all(like, like, like, like);
  }
  if (cat) {
    return db.prepare(`
      SELECT * FROM go_links
      WHERE category = ?
      ORDER BY hits DESC
    `).all(cat);
  }
  return db.prepare('SELECT * FROM go_links ORDER BY hits DESC').all();
}

export function resolveGoLink(slug) {
  const cleanSlug = String(slug || '')
    .trim()
    .toLowerCase()
    .replace(/^go\//, '');
  if (!/^[a-z0-9-_]{2,40}$/.test(cleanSlug)) {
    return null;
  }
  const existing = db.prepare('SELECT * FROM go_links WHERE slug = ?').get(cleanSlug);
  if (!existing) return null;

  db.prepare('UPDATE go_links SET hits = hits + 1 WHERE slug = ?').run(cleanSlug);
  return db.prepare('SELECT * FROM go_links WHERE slug = ?').get(cleanSlug);
}

export function createOrUpdateGoLink({ slug, targetUrl, title, description, category }, currentUser) {
  if (!currentUser) {
    throw new Error('Authentication required.');
  }
  const cleanSlug = String(slug || '')
    .trim()
    .toLowerCase()
    .replace(/^go\//, '');
  if (!/^[a-z0-9-_]{2,40}$/.test(cleanSlug)) {
    throw new Error('Alias go/ invalide : utilisez uniquement 2 à 40 caractères alphanumériques, tirets ou underscores.');
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(String(targetUrl || '').trim());
  } catch {
    throw new Error('URL cible invalide.');
  }
  if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
    throw new Error('Seuls les protocoles https:// et http:// sont autorisés pour un lien go/.');
  }

  const cleanTitle = String(title || '').trim();
  const cleanDesc = String(description || '').trim();
  const cleanCat = String(category || 'Engineering & SRE').trim();

  if (cleanTitle.length < 3 || cleanTitle.length > 120) {
    throw new Error('Le titre doit contenir entre 3 et 120 caractères.');
  }
  if (cleanDesc.length < 5 || cleanDesc.length > 350) {
    throw new Error('La description doit contenir entre 5 et 350 caractères.');
  }

  const allowedCategories = [
    'Engineering & SRE',
    'IT & Security',
    'People & RH',
    'Company & Strategy',
    'Workplace & Life',
  ];
  const safeCategory = allowedCategories.includes(cleanCat) ? cleanCat : 'Engineering & SRE';

  const existing = db.prepare('SELECT * FROM go_links WHERE slug = ?').get(cleanSlug);
  const nowIso = new Date().toISOString();

  if (existing) {
    if (existing.owner_ldap !== currentUser.ldap && currentUser.role !== 'admin') {
      throw new Error(`Accès refusé : le raccourci go/${cleanSlug} appartient à @${existing.owner_ldap}.`);
    }
    db.prepare(`
      UPDATE go_links
      SET target_url = ?, title = ?, description = ?, category = ?, updated_at = ?
      WHERE slug = ?
    `).run(parsedUrl.toString(), cleanTitle, cleanDesc, safeCategory, nowIso, cleanSlug);
  } else {
    db.prepare(`
      INSERT INTO go_links (
        slug, target_url, title, description, category, owner_ldap, hits, is_verified, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, 1, 0, ?, ?)
    `).run(cleanSlug, parsedUrl.toString(), cleanTitle, cleanDesc, safeCategory, currentUser.ldap, nowIso, nowIso);
  }

  recordAuditLog({
    actorLdap: currentUser.ldap,
    action: existing ? 'GOLINK_UPDATE' : 'GOLINK_CREATE',
    targetType: 'golink',
    targetKey: cleanSlug,
    metadata: { targetUrl: parsedUrl.toString(), category: safeCategory },
  });

  return db.prepare('SELECT * FROM go_links WHERE slug = ?').get(cleanSlug);
}

export function deleteGoLink(slug, currentUser) {
  if (!currentUser) {
    throw new Error('Authentication required.');
  }
  const cleanSlug = String(slug || '')
    .trim()
    .toLowerCase()
    .replace(/^go\//, '');
  const existing = db.prepare('SELECT * FROM go_links WHERE slug = ?').get(cleanSlug);
  if (!existing) {
    throw new Error('Lien go/ introuvable.');
  }
  if (existing.owner_ldap !== currentUser.ldap && currentUser.role !== 'admin') {
    throw new Error(`Suppression refusée : seul @${existing.owner_ldap} ou un administrateur peut supprimer go/${cleanSlug}.`);
  }
  db.prepare('DELETE FROM go_links WHERE slug = ?').run(cleanSlug);
  recordAuditLog({
    actorLdap: currentUser.ldap,
    action: 'GOLINK_DELETE',
    targetType: 'golink',
    targetKey: cleanSlug,
    metadata: { previousOwner: existing.owner_ldap },
  });
  return { deleted: cleanSlug };
}

/**
 * Parses Moma search operators from a query string:
 * - owner:<ldap>
 * - source:<connectorKey>
 * - type:<documents|people|golinks|tickets|whatis>
 * - whatis:<term> / define:<term>
 */
function parseMomaQueryOperators(rawQuery) {
  let remaining = String(rawQuery || '').trim();
  const filters = {
    owner: null,
    source: null,
    type: null,
    whatisTerm: null,
  };

  const ownerMatch = remaining.match(/\bowner:([a-z0-9_-]+)/i);
  if (ownerMatch) {
    filters.owner = ownerMatch[1].toLowerCase();
    remaining = remaining.replace(ownerMatch[0], '').trim();
  }

  const sourceMatch = remaining.match(/\bsource:([a-z0-9_-]+)/i);
  if (sourceMatch) {
    filters.source = sourceMatch[1].toLowerCase();
    remaining = remaining.replace(sourceMatch[0], '').trim();
  }

  const typeMatch = remaining.match(/\btype:([a-z0-9_-]+)/i);
  if (typeMatch) {
    filters.type = typeMatch[1].toLowerCase();
    remaining = remaining.replace(typeMatch[0], '').trim();
  }

  const whatisMatch = remaining.match(/^(?:whatis|define)[:\s]+([a-z0-9_-]+)/i);
  if (whatisMatch) {
    filters.whatisTerm = whatisMatch[1].toUpperCase();
    remaining = whatisMatch[1];
  }

  return { cleanQuery: remaining, filters };
}

/**
 * Federated Enterprise Search with:
 * - Operator Parsing (owner:, source:, type:, whatis:)
 * - Whatis Acronym Decoder OneBox
 * - Active Connector Filtering
 * - Query-time ACL Trimming
 * - Moma OneBox Real-Time Structured Cards
 * - Documents, People (Teams), go/links, and IT/ERP Tickets
 */
export function executeFederatedSearch(rawQuery, currentUser, facet = 'all') {
  const { cleanQuery, filters } = parseMomaQueryOperators(rawQuery);
  const query = cleanQuery;
  const normalized = query.toLowerCase();

  if (filters.type) {
    if (filters.type.startsWith('doc')) facet = 'documents';
    else if (filters.type.startsWith('peop') || filters.type.startsWith('pers')) facet = 'people';
    else if (filters.type.startsWith('go')) facet = 'golinks';
    else if (filters.type.startsWith('tick')) facet = 'tickets';
  }

  const allConnectors = db.prepare('SELECT * FROM connectors').all();
  const enabledConnectors = new Set(allConnectors.filter((c) => c.enabled === 1).map((c) => c.connector_key));
  const connectorNameMap = new Map(allConnectors.map((c) => [c.connector_key, c.name]));

  // Check if user typed an explicit go/ command
  let exactGoMatch = null;
  if (normalized.startsWith('go/')) {
    const slugCandidate = normalized.slice(3).trim();
    if (slugCandidate) {
      exactGoMatch = db.prepare('SELECT * FROM go_links WHERE slug = ?').get(slugCandidate) || null;
    }
  } else if (/^[a-z0-9-_]{2,40}$/.test(normalized)) {
    exactGoMatch = db.prepare('SELECT * FROM go_links WHERE slug = ?').get(normalized) || null;
  }

  // Check if query matches a "Whatis" Acronym
  const whatisCandidates = [];
  if (filters.whatisTerm || normalized.length >= 2) {
    const candidateTerm = filters.whatisTerm || normalized.toUpperCase();
    const exactAcr = db.prepare('SELECT * FROM acronyms WHERE term = ?').get(candidateTerm);
    if (exactAcr) {
      whatisCandidates.push(exactAcr);
    } else if (normalized.length >= 3) {
      const partialAcrs = db.prepare(`
        SELECT * FROM acronyms
        WHERE LOWER(term) LIKE ? OR LOWER(expansion) LIKE ?
        ORDER BY upvotes DESC LIMIT 2
      `).all(`%${normalized}%`, `%${normalized}%`);
      whatisCandidates.push(...partialAcrs);
    }
  }

  const stopWords = new Set([
    'le', 'la', 'les', 'de', 'des', 'du', 'un', 'une', 'et', 'ou', 'en', 'au', 'aux',
    'pour', 'par', 'sur', 'dans', 'avec', 'sans', 'comment', 'quel', 'quelle', 'quels',
    'est', 'sont', 'avoir', 'faire', 'mon', 'ma', 'mes', 'nos', 'qui', 'que', 'quoi',
  ]);
  const tokens = normalized
    .replace(/^go\//, '')
    .split(/[^a-z0-9àâäéèêëîïôöùûüç_-]+/i)
    .map((t) => t.trim())
    .filter((t) => t.length >= 2 && !stopWords.has(t));

  // 0. Evaluate Moma OneBox Live Modules
  const allOneBoxes = db.prepare('SELECT * FROM onebox_cards').all();
  const matchedOneBoxes = [];

  // Inject Whatis OneBox card if an acronym matched!
  for (const acr of whatisCandidates) {
    matchedOneBoxes.push({
      oneboxKey: `whatis-${acr.term.toLowerCase()}`,
      connectorKey: 'whatis-glossary',
      connectorName: 'Moma Whatis (Glossaire Interne)',
      cardTitle: `Whatis « ${acr.term} » — ${acr.expansion}`,
      cardSubtitle: `Définition officielle validée par la communauté (${acr.upvotes} votes • @${acr.author_ldap})`,
      badgeText: 'Whatis Acronym OneBox',
      fields: [
        { label: 'Signification complète', value: acr.expansion },
        { label: 'Définition Métier & IT', value: acr.definition },
        { label: 'Domaine', value: `${acr.category} (${acr.related_go_link || 'go/whatis'})` },
      ],
      actionLabel: `Ouvrir ${acr.related_go_link || 'go/whatis'}`,
      actionGoLink: acr.related_go_link || 'go/whatis',
    });
  }

  if (query || filters.source) {
    for (const ob of allOneBoxes) {
      if (!enabledConnectors.has(ob.connector_key)) continue;
      if (filters.source && !ob.connector_key.includes(filters.source)) continue;
      if (!canUserAccessByDept(currentUser, ob.visibility_dept)) continue;
      const triggerHaystack = `${ob.trigger_keywords} ${ob.card_title} ${ob.connector_key}`.toLowerCase();
      let matched = Boolean(filters.source && ob.connector_key.includes(filters.source));
      if (!matched && normalized) {
        matched = triggerHaystack.includes(normalized);
      }
      if (!matched) {
        for (const tok of tokens) {
          if (triggerHaystack.includes(tok)) {
            matched = true;
            break;
          }
        }
      }
      if (matched) {
        matchedOneBoxes.push({
          oneboxKey: `${ob.connector_key}-${ob.id}`,
          connectorKey: ob.connector_key,
          connectorName: connectorNameMap.get(ob.connector_key) || ob.connector_key,
          cardTitle: ob.card_title,
          cardSubtitle: ob.card_subtitle,
          badgeText: ob.badge_text,
          fields: JSON.parse(ob.fields_json || '[]'),
          actionLabel: ob.action_label,
          actionGoLink: ob.action_go_link,
        });
      }
    }
  }

  // 1. Search Documents with SQLite FTS5 BM25 ranking + Connector status check + Operator filters + strict ACL trimming
  const ftsScoreByDocCode = new Map();
  if (tokens.length > 0) {
    const ftsTokens = tokens
      .map((t) => t.replace(/[^\p{L}\p{N}]/gu, ''))
      .filter((t) => t.length >= 2);
    if (ftsTokens.length > 0) {
      const ftsMatchExpr = ftsTokens.map((t) => `"${t}"*`).join(' OR ');
      try {
        const ftsRows = db
          .prepare('SELECT doc_code, bm25(documents_fts) AS rank FROM documents_fts WHERE documents_fts MATCH ?')
          .all(ftsMatchExpr);
        for (const r of ftsRows) {
          // SQLite bm25() returns negative scores where lower (more negative) is more relevant
          const boost = Math.max(4, Math.round(Math.abs(Number(r.rank) || 1) * 10));
          ftsScoreByDocCode.set(r.doc_code, boost);
        }
      } catch {
        // Fallback smoothly if FTS expression encounters an edge-case token
      }
    }
  }

  const allDocs = db.prepare('SELECT * FROM documents ORDER BY updated_at DESC').all();
  let aclFilteredOutCount = 0;
  let disabledConnectorSkippedCount = 0;
  const matchedDocs = [];

  for (const doc of allDocs) {
    if (filters.owner && doc.owner_ldap.toLowerCase() !== filters.owner) continue;
    if (filters.source && !doc.connector_key.toLowerCase().includes(filters.source)) continue;

    const haystack = `${doc.doc_code} ${doc.title} ${doc.summary} ${doc.content} ${doc.source_system} ${doc.category} ${doc.go_link || ''} ${doc.tags_json}`.toLowerCase();
    let score = 0;
    if (!query && (filters.owner || filters.source || filters.type)) {
      score = 5;
    } else if (!query) {
      score = 1;
    } else {
      if (ftsScoreByDocCode.has(doc.doc_code)) {
        score += ftsScoreByDocCode.get(doc.doc_code);
      }
      if (haystack.includes(normalized)) score += 10;
      for (const tok of tokens) {
        if (doc.title.toLowerCase().includes(tok)) score += 5;
        if (doc.tags_json.toLowerCase().includes(tok)) score += 4;
        if (haystack.includes(tok)) score += 2;
      }
    }

    if (score > 0) {
      if (!enabledConnectors.has(doc.connector_key)) {
        disabledConnectorSkippedCount += 1;
        continue;
      }
      if (canUserAccessDocument(currentUser, doc)) {
        matchedDocs.push({
          docCode: doc.doc_code,
          connectorKey: doc.connector_key,
          title: doc.title,
          summary: doc.summary,
          content: doc.content,
          sourceSystem: doc.source_system,
          category: doc.category,
          ownerLdap: doc.owner_ldap,
          goLink: doc.go_link,
          tags: JSON.parse(doc.tags_json || '[]'),
          visibilityDept: doc.visibility_dept,
          updatedAt: doc.updated_at,
          score,
        });
      } else {
        aclFilteredOutCount += 1;
      }
    }
  }
  matchedDocs.sort((a, b) => b.score - a.score);

  // 2. Search People (Teams directory)
  const allUsers = db.prepare('SELECT * FROM users WHERE active = 1').all();
  const matchedPeople = [];
  for (const u of allUsers) {
    if (filters.owner && u.ldap.toLowerCase() !== filters.owner) continue;
    const haystack = `${u.ldap} ${u.full_name} ${u.title} ${u.department} ${u.team} ${u.office} ${u.skills_json} ${u.badges_json} ${u.projects_json} ${u.groups_json} ${u.bio}`.toLowerCase();
    let score = 0;
    if (!query && filters.owner) {
      score = 10;
    } else if (!query) {
      score = 1;
    } else {
      if (haystack.includes(normalized)) score += 8;
      for (const tok of tokens) {
        if (u.full_name.toLowerCase().includes(tok) || u.ldap.toLowerCase().includes(tok)) score += 6;
        if (u.skills_json.toLowerCase().includes(tok) || u.team.toLowerCase().includes(tok)) score += 4;
        if (haystack.includes(tok)) score += 2;
      }
    }
    if (score > 0) {
      matchedPeople.push({ ...formatUserProfile(u, false), score });
    }
  }
  matchedPeople.sort((a, b) => b.score - a.score);

  // 3. Search go/links
  const allGoLinks = db.prepare('SELECT * FROM go_links ORDER BY hits DESC').all();
  const matchedGoLinks = [];
  for (const g of allGoLinks) {
    if (filters.owner && g.owner_ldap.toLowerCase() !== filters.owner) continue;
    const haystack = `go/${g.slug} ${g.slug} ${g.title} ${g.description} ${g.category} ${g.owner_ldap}`.toLowerCase();
    let score = 0;
    if (!query && filters.owner) {
      score = 5;
    } else if (!query) {
      score = 1;
    } else {
      if (g.slug === normalized.replace(/^go\//, '')) score += 20;
      if (haystack.includes(normalized)) score += 8;
      for (const tok of tokens) {
        if (g.slug.includes(tok)) score += 6;
        if (haystack.includes(tok)) score += 2;
      }
    }
    if (score > 0) {
      matchedGoLinks.push({ ...g, score });
    }
  }
  matchedGoLinks.sort((a, b) => b.score - a.score || b.hits - a.hits);

  // 4. Search IT, SRE & ERP Tickets
  const allTickets = db.prepare('SELECT * FROM tickets ORDER BY id DESC').all();
  const matchedTickets = [];
  for (const t of allTickets) {
    if (!enabledConnectors.has(t.connector_key)) continue;
    if (filters.owner && t.assignee_ldap.toLowerCase() !== filters.owner && t.requester_ldap.toLowerCase() !== filters.owner) {
      continue;
    }
    if (filters.source && !t.connector_key.toLowerCase().includes(filters.source)) continue;

    const haystack = `${t.ticket_key} ${t.title} ${t.status} ${t.system_name} ${t.summary} ${t.assignee_ldap}`.toLowerCase();
    let score = 0;
    if (!query && (filters.owner || filters.source)) {
      score = 5;
    } else if (!query) {
      score = 1;
    } else {
      if (haystack.includes(normalized)) score += 8;
      for (const tok of tokens) {
        if (haystack.includes(tok)) score += 3;
      }
    }
    if (score > 0) {
      matchedTickets.push({ ...t, score });
    }
  }
  matchedTickets.sort((a, b) => b.score - a.score);

  return {
    query: rawQuery,
    appliedFilters: filters,
    operators: {
      owner: filters.owner,
      source: filters.source,
      type: filters.type,
      whatis: filters.whatisTerm,
    },
    acronyms: whatisCandidates.map((a) => ({
      ...a,
      acronym: a.term,
      full_expansion: a.expansion,
      go_link: a.related_go_link,
      owner_ldap: a.author_ldap,
    })),
    facet,
    exactGoMatch,
    oneBoxCards: matchedOneBoxes,
    aclTrimmedCount: aclFilteredOutCount,
    disabledConnectorSkippedCount,
    counts: {
      total: matchedDocs.length + matchedPeople.length + matchedGoLinks.length + matchedTickets.length,
      documents: matchedDocs.length,
      people: matchedPeople.length,
      goLinks: matchedGoLinks.length,
      tickets: matchedTickets.length,
    },
    documents: facet === 'all' || facet === 'documents' ? matchedDocs : [],
    people: facet === 'all' || facet === 'people' ? matchedPeople : [],
    goLinks: facet === 'all' || facet === 'golinks' ? matchedGoLinks : [],
    tickets: facet === 'all' || facet === 'tickets' ? matchedTickets : [],
  };
}

export function getDashboardWidgets(currentUser) {
  const announcements = db.prepare('SELECT * FROM announcements ORDER BY id ASC').all();
  const topGoLinks = db.prepare('SELECT * FROM go_links ORDER BY hits DESC LIMIT 8').all();
  const connectors = listConnectors();
  const enabledKeys = new Set(connectors.filter((c) => c.enabled).map((c) => c.connectorKey));

  const recentTickets = db
    .prepare('SELECT * FROM tickets ORDER BY id DESC')
    .all()
    .filter((t) => enabledKeys.has(t.connector_key))
    .slice(0, 4);

  const allDocs = db.prepare('SELECT * FROM documents ORDER BY updated_at DESC').all();
  const accessibleDocs = allDocs
    .filter((d) => enabledKeys.has(d.connector_key) && canUserAccessDocument(currentUser, d))
    .slice(0, 6)
    .map((d) => ({
      docCode: d.doc_code,
      connectorKey: d.connector_key,
      title: d.title,
      summary: d.summary,
      content: d.content,
      sourceSystem: d.source_system,
      category: d.category,
      ownerLdap: d.owner_ldap,
      goLink: d.go_link,
      visibilityDept: d.visibility_dept,
      updatedAt: d.updated_at,
    }));

  // Personalized "My Moma" Widgets:
  // 1. Pending Approvals filtered strictly to current user (approver or requester) or Platform/Exec Admin
  const userLdap = currentUser?.ldap || '';
  const isAdmin = currentUser?.role === 'admin';
  const pendingApprovals = db
    .prepare('SELECT * FROM approvals ORDER BY id ASC')
    .all()
    .filter(
      (ap) =>
        enabledKeys.has(ap.connector_key) &&
        (isAdmin || ap.approver_ldap === userLdap || ap.requester_ldap === userLdap)
    )
    .map((ap) => ({
      ...ap,
      source_system: ap.source_tool,
      amount_or_impact: ap.amount_or_scope,
      summary: `${ap.title} (${ap.amount_or_scope})`,
      status: String(ap.status || 'pending').toUpperCase(),
      can_act: isAdmin || ap.approver_ldap === userLdap,
    }));

  // 2. Daily Meetings filtered to meetings owned by or involving current user
  const rawMeetings = db.prepare('SELECT * FROM meetings ORDER BY id ASC').all();
  const meetings = rawMeetings
    .map((m) => {
      const [startTime = '', endTime = ''] = String(m.time_slot || '').split(' - ');
      const attendees = JSON.parse(m.attendees_json || '[]');
      return {
        id: m.id,
        ownerLdap: m.owner_ldap,
        timeSlot: m.time_slot,
        start_time: startTime,
        end_time: endTime,
        title: m.title,
        roomAndFloor: m.room_and_floor,
        room: m.room_and_floor,
        meetGoLink: m.meet_go_link,
        video_link: m.meet_go_link,
        attendees,
      };
    })
    .filter((m) => !userLdap || m.ownerLdap === userLdap || m.attendees.includes(userLdap));

  // 3. Campus Cafeteria Menu matching current user's office city
  let campusKey = 'Paris';
  if (currentUser && currentUser.office) {
    if (currentUser.office.includes('Zurich')) campusKey = 'Zurich';
    else if (currentUser.office.includes('London')) campusKey = 'London';
  }
  const rawMenu = db.prepare('SELECT * FROM campus_menus WHERE campus_key = ?').get(campusKey);
  const campusMenu = rawMenu
    ? {
        ...rawMenu,
        campus: rawMenu.campus_name,
        main_dish: rawMenu.chef_special,
        vegetarian_dish: rawMenu.vegetarian_option,
        barista_special: rawMenu.barista_status,
        crowd_status: rawMenu.crowd_level,
      }
    : null;
  const allCampusMenus = db.prepare('SELECT * FROM campus_menus ORDER BY id ASC').all();

  return {
    announcements,
    topGoLinks,
    recentTickets,
    accessibleDocs,
    connectors,
    approvals: pendingApprovals,
    pendingApprovals,
    meetings,
    campusMenu,
    allCampusMenus,
  };
}

