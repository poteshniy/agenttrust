import Database from 'better-sqlite3';
import { mkdirSync } from 'fs';

mkdirSync('/opt/agenttrust/data', { recursive: true });

const db = new Database('/opt/agenttrust/data/agenttrust.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash TEXT NOT NULL,
    score INTEGER NOT NULL,
    level TEXT NOT NULL,
    findings TEXT NOT NULL,
    content_size INTEGER,
    tx_hash TEXT,
    payer TEXT,
    amount TEXT,
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_hash ON scans(hash);

  CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY,
    count INTEGER DEFAULT 1,
    window_start INTEGER DEFAULT (unixepoch())
  );
`);

// Save scan result
export function saveScan({ hash, score, level, findings, content_size, tx_hash, payer, amount }) {
  const stmt = db.prepare(`
    INSERT OR IGNORE INTO scans (hash, score, level, findings, content_size, tx_hash, payer, amount)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  return stmt.run(hash, score, level, JSON.stringify(findings), content_size, tx_hash, payer, amount);
}

// Get cached scan by hash
export function getScan(hash) {
  const row = db.prepare('SELECT * FROM scans WHERE hash = ?').get(hash);
  if (!row) return null;
  return { ...row, findings: JSON.parse(row.findings) };
}

// Rate limit: max `limit` requests per `windowSecs`
export function checkRateLimit(key, limit, windowSecs) {
  const now = Math.floor(Date.now() / 1000);
  const row = db.prepare('SELECT * FROM rate_limits WHERE key = ?').get(key);

  if (!row || now - row.window_start > windowSecs) {
    db.prepare('INSERT OR REPLACE INTO rate_limits (key, count, window_start) VALUES (?, 1, ?)').run(key, now);
    return { allowed: true, count: 1 };
  }

  if (row.count >= limit) {
    return { allowed: false, count: row.count };
  }

  db.prepare('UPDATE rate_limits SET count = count + 1 WHERE key = ?').run(key);
  return { allowed: true, count: row.count + 1 };
}

export default db;
