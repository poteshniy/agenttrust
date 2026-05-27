import { SiweMessage } from 'siwe';
import { createHash, randomBytes } from 'crypto';
import { getAddress } from 'viem';
import db from '../db.js';

db.exec(`
  CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT PRIMARY KEY,
    created_at INTEGER DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    address TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()),
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_address ON sessions(address);
`);

export function generateNonce() {
  const nonce = randomBytes(16).toString('hex');
  db.prepare('INSERT INTO nonces (nonce) VALUES (?)').run(nonce);
  db.prepare('DELETE FROM nonces WHERE created_at < ?').run(Math.floor(Date.now()/1000) - 600);
  return nonce;
}

export async function verifySiwe(message, signature) {
  try {
    console.log('[siwe] message:', JSON.stringify(message).slice(0, 200));
    // Normalize message to handle address format
    // Ensure address is in EIP-55 checksum format
    const parsed = JSON.parse(typeof message === 'string' && message.startsWith('{') ? message : '{}');
    // Fix address to EIP-55 checksum format
    const fixedMessage = message.replace(/(0x[0-9a-fA-F]{40})/g, (addr) => getAddress(addr));
    const siweMessage = new SiweMessage(fixedMessage);
    const result = await siweMessage.verify({ signature });
    if (!result.success) return { error: 'Invalid signature' };
    const nonce = db.prepare('SELECT * FROM nonces WHERE nonce = ?').get(siweMessage.nonce);
    if (!nonce) return { error: 'Invalid or expired nonce' };
    db.prepare('DELETE FROM nonces WHERE nonce = ?').run(siweMessage.nonce);
    const token = randomBytes(32).toString('hex');
    const expiresAt = Math.floor(Date.now()/1000) + 86400;
    db.prepare('INSERT INTO sessions (token, address, expires_at) VALUES (?, ?, ?)').run(token, siweMessage.address.toLowerCase(), expiresAt);
    console.log('[siwe] success, token:', token.slice(0,8), 'address:', siweMessage.address);
    return { token, address: siweMessage.address.toLowerCase() };
  } catch(e) {
    return { error: e.message };
  }
}

export function verifySession(token) {
  if (!token) return null;
  return db.prepare('SELECT * FROM sessions WHERE token = ? AND expires_at > ?').get(token, Math.floor(Date.now()/1000)) || null;
}

export function deleteSession(token) {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
}
