import { createHash } from 'crypto';
import db from '../db.js';

// Create table for endpoint reputation
db.exec(`
  CREATE TABLE IF NOT EXISTS endpoint_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    url_hash TEXT NOT NULL,
    score INTEGER NOT NULL,
    badge TEXT NOT NULL,
    x402_version INTEGER,
    has_bazaar INTEGER DEFAULT 0,
    has_resource INTEGER DEFAULT 0,
    has_info INTEGER DEFAULT 0,
    has_schema INTEGER DEFAULT 0,
    pay_to TEXT,
    network TEXT,
    amount TEXT,
    issues TEXT,
    on_chain TEXT,
    created_at INTEGER DEFAULT (unixepoch())
  );
  CREATE INDEX IF NOT EXISTS idx_endpoint_url ON endpoint_checks(url_hash);
`);

export async function checkEndpointReputation(url) {
  const issues = [];
  let score = 100;
  let x402Version = null;
  let hasBazaar = false;
  let hasResource = false;
  let hasInfo = false;
  let hasSchema = false;
  let payTo = null;
  let network = null;
  let amount = null;

  try {
    // Fetch the endpoint
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
      signal: AbortSignal.timeout(10000)
    });

    if (res.status !== 402) {
      // Try GET
      const resGet = await fetch(url, { signal: AbortSignal.timeout(5000) });
      if (resGet.status !== 402) {
        issues.push('endpoint does not return 402');
        score -= 50;
        return buildResult(url, score, issues, {});
      }
    }

    // Parse payment-required header
    const header = res.headers.get('payment-required');
    if (!header) {
      issues.push('missing PAYMENT-REQUIRED header');
      score -= 30;
      return buildResult(url, score, issues, {});
    }

    let challenge;
    try {
      challenge = JSON.parse(Buffer.from(header, 'base64').toString());
    } catch {
      issues.push('invalid base64 in PAYMENT-REQUIRED header');
      score -= 30;
      return buildResult(url, score, issues, {});
    }

    // Check x402Version
    x402Version = challenge.x402Version;
    if (x402Version !== 2) {
      issues.push(`x402Version is ${x402Version}, expected 2`);
      score -= 20;
    }

    // Check resource
    hasResource = !!(challenge.resource?.url);
    if (!hasResource) {
      issues.push('missing resource.url');
      score -= 15;
    }

    // Check accepts
    const accepts = challenge.accepts?.[0];
    if (!accepts) {
      issues.push('missing accepts[]');
      score -= 20;
    } else {
      payTo = accepts.payTo;
      network = accepts.network;
      amount = accepts.amount;

      if (!network?.startsWith('eip155:')) {
        issues.push('network not in CAIP-2 format');
        score -= 10;
      }
      if (!accepts.extra?.name || !accepts.extra?.version) {
        issues.push('missing EIP-712 domain in extra');
        score -= 5;
      }
    }

    // Check extensions.bazaar
    const bazaar = challenge.extensions?.bazaar;
    hasBazaar = !!bazaar;
    if (!hasBazaar) {
      issues.push('missing extensions.bazaar');
      score -= 15;
    } else {
      hasInfo = !!(bazaar.info?.input?.method);
      hasSchema = !!(bazaar.schema || bazaar.info?.output);
      if (!bazaar.name || !bazaar.description) {
        issues.push('missing bazaar.name or bazaar.description');
        score -= 5;
      }
      if (!hasInfo) {
        issues.push('missing bazaar.info.input.method');
        score -= 5;
      }
    }

  } catch (e) {
    issues.push(`fetch error: ${e.message}`);
    score -= 40;
  }

  score = Math.max(0, score);

  // On-chain bonus
  let onChain = null;
  if (payTo) {
    onChain = await getOnChainStats(payTo);
    if (onChain?.indexed) {
      score = Math.min(100, score + 5); // bonus for being indexed
      if (onChain.calls_30d > 10) score = Math.min(100, score + 5);
      if (onChain.payer_count_30d > 1) score = Math.min(100, score + 5);
    }
  }

  return buildResult(url, score, issues, { x402Version, hasResource, hasBazaar, hasInfo, hasSchema, payTo, network, amount, onChain });
}

function buildResult(url, score, issues, meta) {
  const badge = score >= 80 ? 'TRUSTED' : score >= 50 ? 'UNVERIFIED' : 'SUSPICIOUS';
  const urlHash = createHash('sha256').update(url).digest('hex');

  // Save to DB
  const stmt = db.prepare(`
    INSERT INTO endpoint_checks (url, url_hash, score, badge, x402_version, has_bazaar, has_resource, has_info, has_schema, pay_to, network, amount, issues, on_chain)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(url, urlHash, score, badge, meta.x402Version || null, meta.hasBazaar ? 1 : 0, meta.hasResource ? 1 : 0, meta.hasInfo ? 1 : 0, meta.hasSchema ? 1 : 0, meta.payTo || null, meta.network || null, meta.amount || null, JSON.stringify(issues), meta.onChain ? JSON.stringify(meta.onChain) : null);

  const { onChain, ...rest } = meta;
  return { url, score, badge, issues, ...rest, on_chain: onChain || null, checked_at: new Date().toISOString() };
}

export function getEndpointHistory(url) {
  const urlHash = createHash('sha256').update(url).digest('hex');
  return db.prepare('SELECT * FROM endpoint_checks WHERE url_hash = ? ORDER BY created_at DESC LIMIT 10').all(urlHash)
    .map(r => ({ ...r, issues: JSON.parse(r.issues || '[]'), on_chain: r.on_chain ? JSON.parse(r.on_chain) : null }));
}

export async function getOnChainStats(payTo) {
  if (!payTo) return null;
  try {
    const url = `https://api.cdp.coinbase.com/platform/v2/x402/discovery/merchant?payTo=${payTo}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return null;
    const data = await res.json();
    const resources = data.resources || [];
    if (resources.length === 0) return null;
    const r = resources[0];
    return {
      indexed: true,
      last_updated: r.lastUpdated,
      payer_count_30d: r.quality?.l30DaysUniquePayers || 0,
      calls_30d: r.quality?.l30DaysTotalCalls || 0,
      last_called: r.quality?.lastCalledAt || null,
    };
  } catch {
    return null;
  }
}
