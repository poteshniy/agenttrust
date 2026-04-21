import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { createHash } from 'crypto';
import { scan } from './scanner/engine.js';
import { getReputation } from './reputation/oracle.js';

const app = new Hono();
const PORT = process.env.PORT || 3402;
const WALLET = process.env.PAYMENT_ADDRESS || '0x0000000000000000000000000000000000000000';
const PRICE = {
  scan:   process.env.PRICE_SCAN   || '0.015',
  trust:  process.env.PRICE_TRUST  || '0.010',
  verify: process.env.PRICE_VERIFY || '0.005',
  report: process.env.PRICE_REPORT || '0.050',
};

const hashRegistry = new Map();

function x402(c, price, description) {
  c.status(402);
  c.header('X-Payment-Required', 'true');
  c.header('X-Payment-Amount', price);
  c.header('X-Payment-Currency', 'USDC');
  c.header('X-Payment-Network', 'base');
  c.header('X-Payment-Recipient', WALLET);
  c.header('X-Payment-Description', description);
  c.header('WWW-Authenticate', `x402 scheme="USDC" amount="${price}" recipient="${WALLET}" network="base"`);
  return c.json({ error: 'Payment Required', payment: { amount: price, currency: 'USDC', network: 'base', recipient: WALLET }, description });
}

function paid(c) { return c.req.header('X-Payment') || c.req.header('Authorization'); }
function sha256(text) { return createHash('sha256').update(text).digest('hex'); }

function buildReport(content, result, skillId) {
  const now = new Date().toISOString();
  return {
    report_id: sha256(content + now).slice(0, 16),
    skill_id: skillId || 'unknown',
    generated_at: now,
    summary: {
      score: result.score,
      level: result.level,
      verdict: result.score === 0 ? 'No threats detected. Safe to install.' : result.level === 'CRITICAL' ? 'Critical threats found. Do NOT install.' : result.level === 'HIGH' ? 'High severity issues. Review before installing.' : 'Low-medium issues. Use with caution.',
      lines_scanned: content.split('\n').length,
      rules_checked: 40,
      findings_total: result.findings.length,
      breakdown: { critical: result.crits, high: result.highs, medium: result.mediums, low: result.lows },
      categories: result.categories,
    },
    findings: result.findings.map(f => ({
      id: f.id,
      severity: f.sev >= 90 ? 'CRITICAL' : f.sev >= 70 ? 'HIGH' : f.sev >= 40 ? 'MEDIUM' : 'LOW',
      category: f.cat,
      description: f.desc,
      line: f.line,
      evidence: f.match,
      recommendation: ({ exfiltration: 'Remove all external HTTP calls.', credentials: 'Never access credential files.', backdoor: 'Remove all shell execution patterns.', injection: 'Remove prompt override patterns.', privilege: 'Remove all sudo/chmod calls.', wallet: 'Never access wallet files or seed phrases.', network: 'Audit all outbound connections.', filesystem: 'Restrict file access to skill directory only.', obfuscation: 'All skill logic must be readable.', supply_chain: 'Pin all dependencies to specific versions.', privacy: 'Skills must not collect PII.', suspicious: 'Review this pattern carefully.' })[f.cat] || 'Review and remove this pattern.',
    })),
    payment: { charged: PRICE.report, currency: 'USDC', recipient: WALLET },
  };
}

app.get('/health', (c) => c.json({ status: 'ok', service: 'AgentTrust', version: '0.2.0', pricing: PRICE, payment_address: WALLET, timestamp: new Date().toISOString() }));

app.get('/', (c) => c.json({ name: 'AgentTrust', version: '0.2.0', endpoints: { 'POST /v1/scan': `$${PRICE.scan} USDC`, 'GET /v1/trust/:address': `$${PRICE.trust} USDC`, 'POST /v1/verify': `$${PRICE.verify} USDC`, 'POST /v1/report': `$${PRICE.report} USDC` }, payment: { address: WALLET, network: 'base' } }));

app.get('/v1/scan', (c) => x402(c, PRICE.scan, 'Scan SKILL.md for threats — 40 rules'));
app.post('/v1/scan', async (c) => {
  if (!paid(c)) return x402(c, PRICE.scan, 'Scan SKILL.md for threats — 40 rules');
  const body = await c.req.json().catch(() => ({}));
  const content = body.content || body.skill || '';
  if (!content) return c.json({ error: 'content field required' }, 400);
  const result = scan(content);
  const hash = sha256(content);
  hashRegistry.set(hash, { hash, level: result.level, score: result.score, registered_at: new Date().toISOString() });
  return c.json({ ok: true, ...result, hash, charged: PRICE.scan, currency: 'USDC', scanned_at: new Date().toISOString() });
});

app.get('/v1/trust', (c) => x402(c, PRICE.trust, 'Agent reputation lookup'));
app.get('/v1/trust/:address', (c) => {
  if (!paid(c)) return x402(c, PRICE.trust, 'Agent reputation lookup');
  const rep = getReputation(c.req.param('address'));
  if (rep.error) return c.json(rep, 400);
  return c.json({ ok: true, ...rep, charged: PRICE.trust, currency: 'USDC' });
});

app.get('/v1/verify', (c) => x402(c, PRICE.verify, 'Verify skill hash integrity'));
app.post('/v1/verify', async (c) => {
  if (!paid(c)) return x402(c, PRICE.verify, 'Verify skill hash integrity');
  const body = await c.req.json().catch(() => ({}));
  const content = body.content || '';
  const expected = body.hash || '';
  if (!content && !expected) return c.json({ error: 'content or hash required' }, 400);
  const hash = content ? sha256(content) : expected;
  const record = hashRegistry.get(hash);
  if (!record) return c.json({ ok: true, verified: false, hash, message: 'Hash not found. Skill has not been scanned by AgentTrust.', charged: PRICE.verify, currency: 'USDC' });
  return c.json({ ok: true, verified: true, hash, level: record.level, score: record.score, registered_at: record.registered_at, message: `Verified. Last scan: ${record.level} (score: ${record.score}/100)`, charged: PRICE.verify, currency: 'USDC' });
});

app.get('/v1/report', (c) => x402(c, PRICE.report, 'Full security audit report'));
app.post('/v1/report', async (c) => {
  if (!paid(c)) return x402(c, PRICE.report, 'Full security audit report');
  const body = await c.req.json().catch(() => ({}));
  const content = body.content || body.skill || '';
  const skillId = body.skill_id || body.name || 'unknown';
  if (!content) return c.json({ error: 'content field required' }, 400);
  const result = scan(content);
  const hash = sha256(content);
  hashRegistry.set(hash, { hash, level: result.level, score: result.score, registered_at: new Date().toISOString() });
  return c.json({ ok: true, ...buildReport(content, result, skillId) });
});

serve({ fetch: app.fetch, port: PORT });
console.log(`\n  AgentTrust v0.2.0 on port ${PORT} | wallet: ${WALLET}\n`);
