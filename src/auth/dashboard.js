import db from '../db.js';
import { getOnChainStats } from '../reputation/endpoint.js';

export async function getDashboardData(address) {
  // Get all endpoint checks for this address (case insensitive)
  const endpoints = db.prepare(`
    SELECT url, score, badge, created_at, issues, on_chain,
    has_bazaar, has_resource, has_info, has_schema, network, amount
    FROM endpoint_checks 
    WHERE lower(pay_to) = lower(?) 
    GROUP BY url 
    ORDER BY created_at DESC
  `).all(address);

  // Get scan history for skills submitted by this payer
  const scans = db.prepare(`
    SELECT hash, score, level, created_at, content_size
    FROM scans
    WHERE payer = ?
    ORDER BY created_at DESC
    LIMIT 20
  `).all(address);

  // Get on-chain stats from CDP
  const onChain = await getOnChainStats(address);

  // Check if verified provider
  const verified = db.prepare(`
    SELECT * FROM sessions WHERE address = ? LIMIT 1
  `).get(address);

  return {
    address,
    endpoints: endpoints.map(e => ({
      ...e,
      issues: e.issues ? JSON.parse(e.issues) : [],
      on_chain: e.on_chain ? JSON.parse(e.on_chain) : null
    })),
    scans,
    on_chain: onChain,
    stats: {
      endpoints_count: endpoints.length,
      trusted_count: endpoints.filter(e => e.badge === 'TRUSTED').length,
      avg_score: endpoints.length > 0 
        ? Math.round(endpoints.reduce((s, e) => s + e.score, 0) / endpoints.length) 
        : 0,
      scans_count: scans.length
    }
  };
}
