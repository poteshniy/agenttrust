import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { createHash } from 'crypto';
import { paymentMiddleware, x402ResourceServer } from '@x402/hono';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { HTTPFacilitatorClient } from '@x402/core/server';
import { scan } from './scanner/engine.js';
import { freeScan } from './free_scan.js';
import { getReputation } from './reputation/oracle.js';

const app = new Hono();
const PORT = process.env.PORT || 3402;
const PUBLIC_URL = process.env.PUBLIC_URL || 'http://62.238.11.249:3402';
const WALLET = process.env.PAYMENT_ADDRESS || '0x0000000000000000000000000000000000000000';
const NETWORK = 'eip155:8453';

const hashRegistry = new Map();

// Trust Cloudflare proxy — rewrite http to https in URL
app.use('*', async (c, next) => {
  const proto = c.req.header('x-forwarded-proto');
  if (proto === 'https' && c.req.url.startsWith('http://')) {
    const newUrl = c.req.url.replace('http://', 'https://');
    const newReq = new Request(newUrl, c.req.raw);
    c.req.raw = newReq;
  }
  await next();
});
function sha256(t) { return createHash('sha256').update(t).digest('hex'); }

import { generateJwt } from '@coinbase/cdp-sdk/auth';

const facilitatorClient = new HTTPFacilitatorClient({
  url: 'https://api.cdp.coinbase.com/platform/v2/x402',
  createAuthHeaders: async () => {
    const makeToken = async (path, method = 'POST') => generateJwt({
      apiKeyId: process.env.CDP_KEY_NAME,
      apiKeySecret: process.env.CDP_PRIVATE_KEY,
      requestMethod: method,
      requestHost: 'api.cdp.coinbase.com',
      requestPath: '/platform/v2/x402/' + path,
    });
    const [verify, settle, supported] = await Promise.all([
      makeToken('verify', 'POST'), makeToken('settle', 'POST'), makeToken('supported', 'GET')
    ]);
    return {
      verify:    { Authorization: 'Bearer ' + verify },
      settle:    { Authorization: 'Bearer ' + settle },
      supported: { Authorization: 'Bearer ' + supported },
    };
  },
});

const server = new x402ResourceServer(facilitatorClient)
  .register(NETWORK, new ExactEvmScheme())
;

app.use(
  paymentMiddleware(
    {
      'POST /v1/scan': {
        accepts: [{ scheme: 'exact', price: '$0.015', network: NETWORK, payTo: WALLET }],
        description: 'Scan any OpenClaw SKILL.md for malware, prompt injection, exfiltration, and 37 other threat patterns. Returns risk score 0-100 and detailed findings.',
        mimeType: 'application/json',
        extensions: {
          bazaar: { discoverable: true, category: 'security', tags: ['security', 'scanner', 'ai-agents', 'openclaw', 'x402'] }
        },
        outputSchema: {
          input: {
            method: 'POST',
            bodyType: 'json',
            body: { content: '# My Skill\n## Description\nSkill content here' },
            schema: {
              type: 'object',
              properties: { content: { type: 'string', description: 'Full SKILL.md content to scan' } },
              required: ['content']
            }
          },
          output: { ok: true, score: 0, level: 'SAFE', findings: [], hash: 'sha256_of_content', charged: '0.015', currency: 'USDC' }
        },
      },
      'GET /v1/trust': {
        accepts: [{ scheme: 'exact', price: '$0.010', network: NETWORK, payTo: WALLET }],
        description: 'Agent reputation lookup by wallet address. Returns trust score, incidents, audits.',
        mimeType: 'application/json',
      },
      'POST /v1/verify': {
        accepts: [{ scheme: 'exact', price: '$0.005', network: NETWORK, payTo: WALLET }],
        description: 'Verify a skill has been previously scanned by AgentTrust. Returns cached result by SHA256 hash.',
        mimeType: 'application/json',
      },
      'POST /v1/report': {
        accepts: [{ scheme: 'exact', price: '$0.050', network: NETWORK, payTo: WALLET }],
        description: 'Full security audit report with per-finding recommendations and remediation steps.',
        mimeType: 'application/json',
      },
    },
    server,
  ),
);

app.use(async (c, next) => {
  if (c.req.header('x-forwarded-proto')) {
    // rewrite url to use forwarded proto
    const url = new URL(c.req.url);
    url.protocol = c.req.header('x-forwarded-proto') + ':';
    c.req.raw = new Request(url.toString(), c.req.raw);
  }
  await next();
});

app.get('/health', (c) => c.json({
  status: 'ok', service: 'AgentTrust', version: '0.4.0',
  payment_address: WALLET, network: NETWORK,
  timestamp: new Date().toISOString(),
}));

app.get('/', (c) => c.json({
  name: 'AgentTrust',
  description: 'Security Scanner + Reputation Oracle for AI Agent Skills',
  version: '0.4.0',
  endpoints: {
    'POST /v1/scan':   '$0.015 USDC',
    'GET  /v1/trust':  '$0.010 USDC',
    'POST /v1/verify': '$0.005 USDC',
    'POST /v1/report': '$0.050 USDC',
  },
  payment: { address: WALLET, network: 'base', currency: 'USDC' },
}));

app.post('/v1/scan', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const content = body.content || body.skill || '';
  if (!content) return c.json({ error: 'content field required' }, 400);
  const result = scan(content);
  const hash = sha256(content);
  hashRegistry.set(hash, { hash, level: result.level, score: result.score, registered_at: new Date().toISOString() });
  return c.json({ ok: true, ...result, hash, charged: '0.015', currency: 'USDC', scanned_at: new Date().toISOString() });
});

app.get('/v1/trust', async (c) => {
  const address = c.req.query('address');
  if (!address) return c.json({ error: 'address query param required' }, 400);
  const rep = getReputation(address);
  if (rep.error) return c.json(rep, 400);
  return c.json({ ok: true, ...rep, charged: '0.010', currency: 'USDC' });
});

app.get('/v1/trust/:address', (c) => {
  const rep = getReputation(c.req.param('address'));
  if (rep.error) return c.json(rep, 400);
  return c.json({ ok: true, ...rep });
});

app.post('/v1/verify', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const content = body.content || '';
  const expected = body.hash || '';
  if (!content && !expected) return c.json({ error: 'content or hash required' }, 400);
  const hash = content ? sha256(content) : expected;
  const record = hashRegistry.get(hash);
  if (!record) return c.json({ ok: true, verified: false, hash, message: 'Hash not found. Skill has not been scanned by AgentTrust.', charged: '0.005', currency: 'USDC' });
  return c.json({ ok: true, verified: true, hash, level: record.level, score: record.score, registered_at: record.registered_at, charged: '0.005', currency: 'USDC' });
});

app.post('/v1/report', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const content = body.content || body.skill || '';
  const skillId = body.skill_id || 'unknown';
  if (!content) return c.json({ error: 'content field required' }, 400);
  const result = scan(content);
  const hash = sha256(content);
  hashRegistry.set(hash, { hash, level: result.level, score: result.score, registered_at: new Date().toISOString() });
  const recs = { exfiltration:'Remove all external HTTP calls.', credentials:'Never access credential files.', backdoor:'Remove all shell execution patterns.', injection:'Remove prompt override patterns.', privilege:'Remove all sudo/chmod calls.', wallet:'Never access wallet files.', network:'Audit all outbound connections.', filesystem:'Restrict file access to skill directory.', obfuscation:'All skill logic must be readable.', supply_chain:'Pin all dependencies.', privacy:'Skills must not collect PII.', suspicious:'Review this pattern carefully.' };
  return c.json({ ok: true, report_id: hash.slice(0,16), skill_id: skillId, generated_at: new Date().toISOString(),
    summary: { score: result.score, level: result.level, findings_total: result.findings.length, breakdown: { critical: result.crits, high: result.highs, medium: result.mediums, low: result.lows } },
    findings: result.findings.map(f => ({ id: f.id, severity: f.sev>=90?'CRITICAL':f.sev>=70?'HIGH':f.sev>=40?'MEDIUM':'LOW', category: f.cat, description: f.desc, line: f.line, evidence: f.match, recommendation: recs[f.cat]||'Review.' })),
    payment: { charged: '0.050', currency: 'USDC' }
  });
});


app.get('/v1/scan', (c) => {
  const payload = {
    x402Version: 2,
    error: 'Payment required',
    resource: { url: 'https://agenttrust.uk/v1/scan', description: 'Scan any OpenClaw SKILL.md for malware, prompt injection, exfiltration, and 37 other threat patterns. Returns risk score 0-100 and detailed findings.', mimeType: 'application/json' },
    accepts: [{ scheme: 'exact', network: NETWORK, amount: '15000', asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', payTo: WALLET, maxTimeoutSeconds: 300, extra: { name: 'USD Coin', version: '2' } }],
    extensions: { bazaar: { discoverable: true, category: 'security', tags: ['security','scanner','ai-agents','openclaw','x402'] } },
    outputSchema: {
      input: { method: 'POST', bodyType: 'json', body: { content: '# My Skill' }, schema: { type: 'object', properties: { content: { type: 'string', description: 'Full SKILL.md content to scan' } }, required: ['content'] } },
      output: { ok: true, score: 0, level: 'SAFE', findings: [], hash: 'sha256_of_content' }
    }
  };
  c.status(402);
  c.header('payment-required', Buffer.from(JSON.stringify(payload)).toString('base64'));
  return c.json(payload);
});

app.get('/v1/scan/free', (c) => c.json({ info: 'POST /v1/scan/free - free 5-rule scan, max 50 lines', upgrade: 'POST /v1/scan - full 40 rules, $0.015 USDC' }));

app.post('/v1/scan/free', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const content = body.content || body.skill || '';
  if (!content) return c.json({ error: 'content field required' }, 400);
  const result = freeScan(content);
  return c.json({ ok: true, free: true, ...result, scanned_at: new Date().toISOString() });
});

serve({ fetch: app.fetch, port: PORT });
console.log(`\n  AgentTrust v0.4.0 on port ${PORT} | wallet: ${WALLET}\n`);
