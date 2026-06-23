import '/opt/agenttrust/src/cdp_tap.js';
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { createHash } from 'crypto';
import { saveScan, getScan, checkRateLimit } from './db.js';
import { paymentMiddleware, x402ResourceServer } from '@x402/hono';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { HTTPFacilitatorClient } from '@x402/core/server';
import { scan } from './scanner/engine.js';
import { freeScan } from './free_scan.js';
import { scanMCP } from './scanner/mcp.js';
import { getReputation } from './reputation/oracle.js';
import { checkEndpointReputation, getEndpointHistory } from './reputation/endpoint.js';
import { generateNonce, verifySiwe, verifySession, deleteSession } from './auth/siwe.js';
import { getDashboardData } from './auth/dashboard.js';
import { generateBadge } from './reputation/badge.js';
import { signScanResult, hashInput, getJWKS, MAPPING_ID, getMappingHash } from './jws.js';
import { BUILDER_CODE, declareBuilderCodeExtension } from '@x402/extensions/builder-code';
const BC_EXT = { [BUILDER_CODE]: declareBuilderCodeExtension('bc_6sh5sk4l') };

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
  .register(NETWORK, new ExactEvmScheme());

app.use(
  paymentMiddleware(
    {
      'POST /v1/scan': {
        accepts: [{ scheme: 'exact', price: '$0.015', network: NETWORK, payTo: WALLET }],
        description: 'Scan any OpenClaw SKILL.md for malware, prompt injection, exfiltration, and 37 other threat patterns. Returns risk score 0-100 and detailed findings.',
        mimeType: 'application/json',
        extensions: {
          ...BC_EXT,
          bazaar: {
            name: 'AgentTrust Security Scanner',
            description: 'Scan OpenClaw SKILL.md files for malware, prompt injection, data exfiltration, and 37 other threat patterns before installing.',
            info: {
              input: { type: 'http', method: 'POST', bodyType: 'json', body: { content: '# My Skill\n## Description\nSkill content here' } },
              output: { type: 'json', example: { ok: true, score: 0, level: 'SAFE', findings: [], hash: 'sha256_of_content' } }
            },
            schema: {
              '$schema': 'https://json-schema.org/draft/2020-12/schema',
              type: 'object',
              properties: {
                input: {
                  type: 'object',
                  properties: {
                    type: { const: 'http', type: 'string' },
                    method: { const: 'POST', type: 'string' },
                    bodyType: { const: 'json', type: 'string' },
                    body: { type: 'object', properties: { content: { type: 'string' } }, required: ['content'] }
                  },
                  required: ['type', 'method', 'bodyType', 'body']
                }
              },
              required: ['input']
            }
          }
        },
        outputSchema: {
          input: {
            method: 'POST', bodyType: 'json',
            body: { content: '# My Skill\n## Description\nSkill content here' },
            schema: { type: 'object', properties: { content: { type: 'string', description: 'Full SKILL.md content to scan' } }, required: ['content'] }
          },
          output: { ok: true, score: 0, level: 'SAFE', findings: [], hash: 'sha256_of_content', charged: '0.015', currency: 'USDC' }
        },
      },
      'POST /v1/scan/mcp': {
        accepts: [{ scheme: 'exact', price: '$0.015', network: NETWORK, payTo: WALLET }],
        description: 'Scan MCP server manifest for security threats: tool poisoning, shadowing, hidden unicode injection, credential harvesting, and 37 other patterns.',
        mimeType: 'application/json',
        extensions: {
          ...BC_EXT,
          bazaar: {
            name: 'AgentTrust MCP Scanner',
            description: 'Scan MCP server manifests for tool poisoning, prompt injection, hidden unicode, credential harvesting, and rug pull patterns before connecting.',
            info: {
              input: { type: 'http', method: 'POST', bodyType: 'json', body: { manifest: { name: 'my-server', tools: [] } } },
              output: { type: 'json', example: { ok: true, score: 0, level: 'SAFE', findings: [], v_gate: 'act' } }
            }
          }
        }
      },
      'GET /v1/trust': {
        accepts: [{ scheme: 'exact', price: '$0.010', network: NETWORK, payTo: WALLET }],
        extensions: { ...BC_EXT },
        description: 'Agent reputation lookup by wallet address. Returns trust score, incidents, audits.',
        mimeType: 'application/json',
      },
      'POST /v1/verify': {
        accepts: [{ scheme: 'exact', price: '$0.005', network: NETWORK, payTo: WALLET }],
        extensions: { ...BC_EXT },
        description: 'Verify a skill has been previously scanned by AgentTrust. Returns cached result by SHA256 hash.',
        mimeType: 'application/json',
      },
      'POST /v1/report': {
        accepts: [{ scheme: 'exact', price: '$0.050', network: NETWORK, payTo: WALLET }],
        extensions: { ...BC_EXT },
        description: 'Full security audit report with per-finding recommendations and remediation steps.',
        mimeType: 'application/json',
      },
    },
    server,
    { syncFacilitatorOnStart: false },
  ),
);

app.use(async (c, next) => {
  if (c.req.header('x-forwarded-proto')) {
    const url = new URL(c.req.url);
    url.protocol = c.req.header('x-forwarded-proto') + ':';
    c.req.raw = new Request(url.toString(), c.req.raw);
  }
  await next();
});

// ─── Auth ─────────────────────────────────────────────────────────────────────
app.get('/v1/auth/nonce', (c) => {
  const nonce = generateNonce();
  return c.json({ nonce });
});

app.post('/v1/auth/verify', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const { message, signature } = body;
  if (!message || !signature) return c.json({ error: 'message and signature required' }, 400);
  const result = await verifySiwe(message, signature);
  if (result.error) return c.json({ error: result.error }, 401);
  return c.json({ ok: true, token: result.token, address: result.address });
});

app.post('/v1/auth/logout', (c) => {
  const token = c.req.header('authorization')?.replace('Bearer ', '');
  if (token) deleteSession(token);
  return c.json({ ok: true });
});

app.get('/v1/auth/me', (c) => {
  const token = c.req.header('authorization')?.replace('Bearer ', '');
  const session = verifySession(token);
  if (!session) return c.json({ error: 'not authenticated' }, 401);
  return c.json({ ok: true, address: session.address });
});

// ─── Dashboard ────────────────────────────────────────────────────────────────
app.get('/v1/dashboard', async (c) => {
  const token = c.req.header('authorization')?.replace('Bearer ', '');
  const session = verifySession(token);
  if (!session) return c.json({ error: 'unauthorized — connect wallet first' }, 401);
  const data = await getDashboardData(session.address);
  return c.json({ ok: true, ...data });
});

// ─── Badge ────────────────────────────────────────────────────────────────────
app.get('/v1/badge', async (c) => {
  const url = c.req.query('url');
  if (!url) return c.text(generateBadge('UNVERIFIED', 50, ''), 200, { 'Content-Type': 'image/svg+xml' });
  const history = getEndpointHistory(url);
  let badge, score;
  if (history.length > 0 && Math.floor(Date.now()/1000) - history[0].created_at < 3600) {
    badge = history[0].badge; score = history[0].score;
  } else {
    const result = await checkEndpointReputation(url);
    badge = result.badge; score = result.score;
  }
  const svg = generateBadge(badge, score, url);
  return c.text(svg, 200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=3600' });
});

// ─── Reputation ───────────────────────────────────────────────────────────────
app.post('/v1/reputation', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const url = body.url || '';
  if (!url || !url.startsWith('https://')) return c.json({ error: 'valid https url required' }, 400);
  const result = await checkEndpointReputation(url);
  return c.json({ ok: true, ...result, charged: '0.010', currency: 'USDC' });
});

app.get('/v1/reputation', async (c) => {
  const url = c.req.query('url');
  const refresh = c.req.query('refresh');
  if (!url) return c.json({ error: 'url query param required' }, 400);
  const history = getEndpointHistory(url);
  if (history.length > 0 && !refresh) {
    const age = Math.floor(Date.now() / 1000) - history[0].created_at;
    if (age < 3600) {
      return c.json({ ok: true, ...history[0], history_count: history.length, cached: true, charged: '0.010', currency: 'USDC' });
    }
  }
  const result = await checkEndpointReputation(url);
  return c.json({ ok: true, ...result, history_count: (history.length + 1), charged: '0.010', currency: 'USDC' });
});

// ─── Scan (paid) ──────────────────────────────────────────────────────────────
app.get('/v1/scan', (c) => {
  const payload = {
    x402Version: 2,
    error: 'Payment required',
    resource: { url: 'https://agenttrust.uk/v1/scan', description: 'Scan any OpenClaw SKILL.md for malware, prompt injection, exfiltration, and 37 other threat patterns.', mimeType: 'application/json' },
    accepts: [{ scheme: 'exact', network: NETWORK, amount: '15000', asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', payTo: WALLET, maxTimeoutSeconds: 300, extra: { name: 'USD Coin', version: '2' } }],
    extensions: {
      bazaar: {
        name: 'AgentTrust Security Scanner',
        description: 'Scan OpenClaw SKILL.md files for malware, prompt injection, data exfiltration, and 37 other threat patterns before installing.',
        info: { input: { type: 'http', method: 'POST', bodyType: 'json', body: { content: '# My Skill' } }, output: { type: 'json', example: { ok: true, score: 0, level: 'SAFE' } } },
        schema: { '$schema': 'https://json-schema.org/draft/2020-12/schema', type: 'object', properties: { input: { type: 'object', properties: { type: { const: 'http', type: 'string' }, method: { const: 'POST', type: 'string' }, bodyType: { const: 'json', type: 'string' }, body: { type: 'object', properties: { content: { type: 'string' } }, required: ['content'] } }, required: ['type', 'method', 'bodyType', 'body'] } }, required: ['input'] }
      }
    }
  };
  c.status(402);
  c.header('payment-required', Buffer.from(JSON.stringify(payload)).toString('base64'));
  return c.json(payload);
});

app.post('/v1/scan', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const content = body.content || body.skill || '';
  if (!content) return c.json({ error: 'content field required' }, 400);
  const hash = sha256(content);
  const cached = getScan(hash);
  if (cached) {
    return c.json({ ok: true, score: cached.score, level: cached.level, findings: cached.findings, hash, charged: '0.015', currency: 'USDC', cached: true, scanned_at: new Date(cached.created_at * 1000).toISOString() });
  }
  const result = scan(content);
  hashRegistry.set(hash, { hash, level: result.level, score: result.score, registered_at: new Date().toISOString() });
  saveScan({ hash, score: result.score, level: result.level, findings: result.findings, content_size: content.length });
  const claimHash = hashInput(content);
  const receipt = signScanResult(result, claimHash, 'skill_scan');
  return c.json({
    ok: true, ...result, hash,
    v_gate: result.level === 'SAFE' && result.score === 0 ? 'act' : 'halt',
    v_recommendation: result.level === 'SAFE' && result.score === 0 ? 'confident_supported' : 'refuted',
    v_gate_mapping: MAPPING_ID,
    ...(receipt ? { receipt } : {}),
    charged: '0.015', currency: 'USDC', scanned_at: new Date().toISOString(),
  });
});

// ─── Scan free ────────────────────────────────────────────────────────────────
app.get('/v1/scan/free', (c) => c.json({ info: 'POST /v1/scan/free — free 5-rule scan, max 50 lines', upgrade: 'POST /v1/scan — full 40 rules, $0.015 USDC' }));

app.post('/v1/scan/free', async (c) => {
  const ip = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown';
  const rl = checkRateLimit('free:' + ip, 10, 3600);
  if (!rl.allowed) return c.json({ error: 'Rate limit exceeded. Max 10 free scans per hour.', retry_after: 3600 }, 429);
  const body = await c.req.json().catch(() => ({}));
  const content = body.content || body.skill || '';
  if (!content) return c.json({ error: 'content field required' }, 400);
  const result = freeScan(content);
  const claimHash = hashInput(content);
  const receipt = signScanResult(result, claimHash, 'skill_scan');
  return c.json({
    ok: true, free: true, ...result,
    v_gate: result.level === 'SAFE' && result.score === 0 ? 'act' : 'halt',
    v_recommendation: result.level === 'SAFE' && result.score === 0 ? 'confident_supported' : 'refuted',
    v_gate_mapping: MAPPING_ID,
    ...(receipt ? { receipt } : {}),
    scanned_at: new Date().toISOString(),
  });
});

// ─── MCP Scan (free) ──────────────────────────────────────────────────────────
app.post('/v1/scan/mcp/free', async (c) => {
  const ip = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown';
  const rl = checkRateLimit('mcp_free:' + ip, 10, 3600);
  if (!rl.allowed) return c.json({ error: 'Rate limit exceeded. Max 10 free scans per hour.', retry_after: 3600 }, 429);
  const body = await c.req.json().catch(() => ({}));
  const manifest = body.manifest || body;
  if (typeof manifest !== 'object' || Array.isArray(manifest)) {
    return c.json({ error: 'manifest must be a JSON object' }, 400);
  }
  const result = scanMCP(manifest, false);
  const claimHash = hashInput(JSON.stringify(manifest));
  const receipt = signScanResult(result, claimHash, 'mcp_scan');
  return c.json({
    ok: true, free: true, ...result,
    v_gate: result.level === 'SAFE' && result.score === 0 ? 'act' : 'halt',
    v_recommendation: result.level === 'SAFE' && result.score === 0 ? 'confident_supported' : 'refuted',
    v_gate_mapping: MAPPING_ID,
    ...(receipt ? { receipt } : {}),
    scanned_at: new Date().toISOString(),
  });
});

// ─── MCP Scan (paid) ──────────────────────────────────────────────────────────
app.get('/v1/scan/mcp', (c) => {
  const payload = {
    x402Version: 2,
    error: 'Payment required',
    resource: { url: 'https://agenttrust.uk/v1/scan/mcp', description: 'Full MCP server manifest security scan — 10 MCP-specific rules + 40 engine rules.', mimeType: 'application/json' },
    accepts: [{ scheme: 'exact', network: NETWORK, amount: '15000', asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', payTo: WALLET, maxTimeoutSeconds: 300, extra: { name: 'USD Coin', version: '2' } }],
  };
  c.status(402);
  c.header('payment-required', Buffer.from(JSON.stringify(payload)).toString('base64'));
  return c.json(payload);
});

app.post('/v1/scan/mcp', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const manifest = body.manifest || body;
  if (typeof manifest !== 'object' || Array.isArray(manifest)) {
    return c.json({ error: 'manifest must be a JSON object' }, 400);
  }
  const result = scanMCP(manifest, true);
  const claimHash = hashInput(JSON.stringify(manifest));
  const receipt = signScanResult(result, claimHash, 'mcp_scan');
  return c.json({
    ok: true, ...result,
    v_gate: result.level === 'SAFE' && result.score === 0 ? 'act' : 'halt',
    v_recommendation: result.level === 'SAFE' && result.score === 0 ? 'confident_supported' : 'refuted',
    v_gate_mapping: MAPPING_ID,
    ...(receipt ? { receipt } : {}),
    charged: '0.015', currency: 'USDC', scanned_at: new Date().toISOString(),
  });
});

// ─── Trust ────────────────────────────────────────────────────────────────────
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

// ─── Verify ───────────────────────────────────────────────────────────────────
app.post('/v1/verify', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const content = body.content || '';
  const expected = body.hash || '';
  if (!content && !expected) return c.json({ error: 'content or hash required' }, 400);
  const hash = content ? sha256(content) : expected;
  const record = getScan(hash) || hashRegistry.get(hash);
  if (!record) return c.json({ ok: true, verified: false, hash, message: 'Hash not found. Skill has not been scanned by AgentTrust.', charged: '0.005', currency: 'USDC' });
  return c.json({ ok: true, verified: true, hash, level: record.level, score: record.score, registered_at: record.registered_at || new Date(record.created_at * 1000).toISOString(), charged: '0.005', currency: 'USDC' });
});

// ─── Report ───────────────────────────────────────────────────────────────────
app.post('/v1/report', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const content = body.content || body.skill || '';
  const skillId = body.skill_id || 'unknown';
  if (!content) return c.json({ error: 'content field required' }, 400);
  const result = scan(content);
  const hash = sha256(content);
  hashRegistry.set(hash, { hash, level: result.level, score: result.score, registered_at: new Date().toISOString() });
  const recs = { exfiltration:'Remove all external HTTP calls.', credentials:'Never access credential files.', backdoor:'Remove all shell execution patterns.', injection:'Remove prompt override patterns.', privilege:'Remove all sudo/chmod calls.', wallet:'Never access wallet files.', network:'Audit all outbound connections.', filesystem:'Restrict file access to skill directory.', obfuscation:'All skill logic must be readable.', supply_chain:'Pin all dependencies.', privacy:'Skills must not collect PII.', suspicious:'Review this pattern carefully.', mcp_poisoning:'Remove hidden instructions from tool descriptions.', mcp_shadowing:'Rename tools to avoid shadowing system tools.', mcp_rug_pull:'Remove external update mechanisms.', mcp_exfiltration:'Remove suspicious resource URIs.', mcp_credential:'Remove credential fields from schema.' };
  return c.json({ ok: true, report_id: hash.slice(0,16), skill_id: skillId, generated_at: new Date().toISOString(),
    summary: { score: result.score, level: result.level, findings_total: result.findings.length, breakdown: { critical: result.crits, high: result.highs, medium: result.mediums, low: result.lows } },
    findings: result.findings.map(f => ({ id: f.id, severity: f.sev>=90?'CRITICAL':f.sev>=70?'HIGH':f.sev>=40?'MEDIUM':'LOW', category: f.cat, description: f.desc, line: f.line, evidence: f.match, recommendation: recs[f.cat]||'Review.' })),
    payment: { charged: '0.050', currency: 'USDC' }
  });
});

// ─── JWKS (for JWS receipt verification) ─────────────────────────────────────
app.get('/.well-known/jwks.json', async (c) => {
  const jwks = await getJWKS();
  return c.json(jwks, 200, { 'Cache-Control': 'public, max-age=3600' });
});

// ─── Well-known: mapping doc redirect ────────────────────────────────────────
app.get('/.well-known/agenttrust-mapping', (c) =>
  c.redirect('https://raw.githubusercontent.com/poteshniy/agenttrust/main/docs/mapping-v0.3.md', 301)
);



// ─── Composed Receipt (POST /v1/compose) ─────────────────────────────────────
app.post('/v1/compose', async (c) => {
  const ip = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown';
  const rl = checkRateLimit('compose:' + ip, 20, 3600);
  if (!rl.allowed) return c.json({ error: 'Rate limit exceeded' }, 429);
  const body = await c.req.json().catch(() => ({}));
  const { handleCompose } = await import('./compose.js');
  const result = await handleCompose(body);
  if (result.error) return c.json(result, 400);
  return c.json(result);
});

// ─── Unified Trust Gate ───────────────────────────────────────────────────────
app.post('/v1/gate', async (c) => {
  const ip = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown';
  const rl = checkRateLimit('gate:' + ip, 10, 3600);
  if (!rl.allowed) return c.json({ error: 'Rate limit exceeded. Max 10/hour.' }, 429);

  const body = await c.req.json().catch(() => ({}));
  const { skill, mcp, endpoint } = body;
  if (!skill && !mcp && !endpoint) {
    return c.json({ error: 'at least one of: skill, mcp, endpoint required' }, 400);
  }

  const results = {};
  const allFindings = [];
  let worstLevel = 'SAFE';
  const levelRank = { SAFE: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

  // Scan SKILL.md
  if (skill) {
    const r = freeScan(String(skill).slice(0, 4000));
    results.skill = { score: r.score, level: r.level, findings: r.findings, crits: r.crits };
    allFindings.push(...r.findings.map(f => ({ ...f, source: 'skill' })));
    if (levelRank[r.level] > levelRank[worstLevel]) worstLevel = r.level;
  }

  // Scan MCP manifest
  if (mcp && typeof mcp === 'object') {
    const r = scanMCP(mcp, false);
    results.mcp = { score: r.score, level: r.level, findings: r.findings, crits: r.crits };
    allFindings.push(...(r.findings || []).map(f => ({ ...f, source: 'mcp' })));
    if (levelRank[r.level] > levelRank[worstLevel]) worstLevel = r.level;
  }

  // Check endpoint reputation
  if (endpoint && typeof endpoint === 'string' && endpoint.startsWith('https://')) {
    try {
      const history = getEndpointHistory(endpoint);
      let rep;
      if (history.length > 0 && Math.floor(Date.now()/1000) - history[0].created_at < 3600) {
        rep = history[0];
      } else {
        rep = await checkEndpointReputation(endpoint);
      }
      results.endpoint = { score: rep.score, badge: rep.badge, issues: rep.issues || [] };
      if (rep.badge === 'SUSPICIOUS') {
        if (levelRank['CRITICAL'] > levelRank[worstLevel]) worstLevel = 'CRITICAL';
      } else if (rep.badge === 'UNVERIFIED') {
        if (levelRank['MEDIUM'] > levelRank[worstLevel]) worstLevel = 'MEDIUM';
      }
    } catch(e) {
      results.endpoint = { error: 'Could not check endpoint reputation' };
    }
  }

  const gate = worstLevel === 'SAFE' ? 'act' : 'halt';
  const recommendation = worstLevel === 'SAFE' ? 'confident_supported' :
    worstLevel === 'CRITICAL' ? 'refuted' : 'weak_supported';

  // Sign unified receipt
  const gateResult = { score: 0, level: worstLevel, crits: allFindings.filter(f=>f.sev>=90).length, findings: allFindings };
  const claimHash = hashInput(JSON.stringify({ skill: skill?.slice(0,100), mcp: mcp?.name, endpoint }));
  const receipt = signScanResult(gateResult, claimHash, 'unified_gate');

  return c.json({
    ok: true,
    v_gate: gate,
    v_recommendation: recommendation,
    v_gate_mapping: MAPPING_ID,
    worst_level: worstLevel,
    results,
    findings_total: allFindings.length,
    ...(receipt ? { receipt } : {}),
    checked_at: new Date().toISOString(),
  });
});

// ─── Health / Info ────────────────────────────────────────────────────────────
app.get('/health', (c) => c.json({
  status: 'ok', service: 'AgentTrust', version: '0.9.0',
  payment_address: WALLET, network: NETWORK,
  jws_enabled: !!process.env.AGENTTRUST_PRIVATE_KEY,
  mapping_id: MAPPING_ID,
  timestamp: new Date().toISOString(),
}));

app.get('/', (c) => c.json({
  name: 'AgentTrust',
  description: 'Security Scanner + Reputation Oracle for AI Agent Skills',
  version: '0.9.0',
  endpoints: {
    'POST /v1/scan':          '$0.015 USDC — full SKILL.md scan (40 rules)',
    'POST /v1/scan/free':     'free — SKILL.md scan (5 rules, max 50 lines)',
    'POST /v1/scan/mcp':      '$0.015 USDC — full MCP manifest scan',
    'POST /v1/scan/mcp/free': 'free — MCP manifest scan (3 rules)',
    'GET  /v1/reputation':    'free — x402 endpoint reputation',
    'GET  /v1/badge':         'free — SVG trust badge',
    'GET  /v1/trust/:addr':   '$0.010 USDC — wallet reputation',
    'POST /v1/verify':        '$0.005 USDC — verify scan hash',
    'POST /v1/report':        '$0.050 USDC — full audit report',
    'POST /v1/gate':          'free — unified ACT/HALT gate (skill + MCP + endpoint)',
  },
  jws: { mapping_id: MAPPING_ID, spec: 'draft-krausz-verification-state-00', jwks: 'https://agenttrust.uk/.well-known/jwks.json' },
  payment: { address: WALLET, network: 'base', currency: 'USDC' },
}));

serve({ fetch: app.fetch, port: PORT });
console.log(`\n  AgentTrust v0.9.0 on port ${PORT} | wallet: ${WALLET} | JWS: ${!!process.env.AGENTTRUST_PRIVATE_KEY}\n`);
