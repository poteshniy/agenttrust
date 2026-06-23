/**
 * AgentTrust /v1/compose endpoint
 * Produces verification.v0.3+composed JWS general serialization
 * Phase 1: two-signer (AgentOracle v_gate + AgentTrust v_gate_skill)
 * Per: github.com/TKCollective/agentoracle-receipt-spec PR #2
 */

import { createHash } from 'crypto';
import { sign as cryptoSign, createPublicKey } from 'crypto';

const MAPPING_ID = 'agenttrust-v0.3-2026-06-07';
const MAPPING_HASH = 'sha256-307db9faa364cfe149fb5120d0451175175de40d7433c44915bfec57acc16ec4';
const KID = 'agenttrust-ed25519-v1';
const TYP = 'application/vnd.verification.v0.3+composed+jws';

function b64url(input) {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return buf.toString('base64url');
}

function hashInput(content) {
  return 'sha256-' + createHash('sha256').update(content).digest('hex');
}

/**
 * JCS (RFC 8785) canonical JSON — recursive alphabetical key sort
 */
function jcs(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return JSON.stringify(value);
  }
  const keys = Object.keys(value).sort();
  const parts = keys.map(k => `${JSON.stringify(k)}:${jcs(value[k])}`);
  return `{${parts.join(',')}}`;
}

/**
 * Sign canonical payload with our Ed25519 key
 * Returns { protected, signature } for JWS general serialization
 */
function signComposed(canonicalPayloadB64) {
  const privKeyPem = process.env.AGENTTRUST_PRIVATE_KEY;
  if (!privKeyPem) return null;

  const header = { alg: 'EdDSA', kid: KID, typ: TYP };
  const protectedB64 = b64url(JSON.stringify(header));
  const sigInput = Buffer.from(`${protectedB64}.${canonicalPayloadB64}`);

  try {
    const sigBuf = cryptoSign(null, sigInput, privKeyPem);
    return {
      protected: protectedB64,
      signature: sigBuf.toString('base64url'),
    };
  } catch (err) {
    console.error('[compose] signing error:', err.message);
    return null;
  }
}

/**
 * Build the canonical composed payload
 * @param {object} params
 * @param {string} params.claim_hash - sha256-prefixed hash of the claim
 * @param {string} params.skill_hash - sha256-prefixed hash of skill content
 * @param {object} params.v_gate - AgentOracle gate result
 * @param {object} params.scanResult - AgentTrust scan result
 * @param {string|null} params.mycelium_trail_id - absent if trail fails
 */
export function buildComposedPayload({ claim_hash, skill_hash, v_gate, scanResult, mycelium_trail_id }) {
  // Derive AT verdict from scan result
  const atVerdict = (scanResult.level === 'SAFE' && scanResult.score === 0) ? 'act' : 'halt';

  // Build skill_results from scan findings
  const skillResults = scanResult.findings && scanResult.findings.length > 0
    ? [{ status: 'findings', count: scanResult.findings.length, level: scanResult.level }]
    : [{ status: 'clean' }];

  // Build v_gate_skill block (alphabetical for JCS)
  const v_gate_skill = {
    endpoint_results: [],
    issuer: 'agenttrust',
    mapping_id: MAPPING_ID,
    mcp_results: [],
    skill_results: skillResults,
    v_gate_mapping_hash: MAPPING_HASH,
    verdict: atVerdict,
  };

  // Determine composed decision (AND_PRESENT)
  const aoVerdict = v_gate?.verdict || 'halt';
  const composed_decision = (aoVerdict === 'act' && atVerdict === 'act') ? 'act' : 'halt';

  // Build full payload (JCS requires alphabetical key order)
  const payload = {
    composed_decision,
    composed_decision_rule: 'AND_PRESENT',
    envelope_kind: 'verification.v0.3+composed',
    receipt_version: '0.3.0-composed',
    signature_meta: {
      agentoracle_jwks_url: 'https://agentoracle.co/.well-known/jwks.json',
      agenttrust_jwks_url: 'https://agenttrust.uk/.well-known/jwks.json',
    },
    subject: {
      claim_hash,
      skill_hash,
    },
    v_gate_skill,
  };

  // Add mycelium_trail_id only if present (MUST be absent not null when trail fails)
  if (v_gate) {
    payload.v_gate = v_gate;
  }
  if (mycelium_trail_id) {
    payload.mycelium_trail_id = mycelium_trail_id;
  }

  return payload;
}

/**
 * Build JWS general serialization envelope
 * Phase 1: AT signature only (AO signature must come from AgentOracle)
 * For composed endpoint: AT signs, AO signature slot is provided by caller
 */
export function buildComposedJWS(payload, aoSignature = null) {
  // JCS canonical serialization
  const canonical = jcs(payload);
  const payloadB64 = b64url(canonical);

  // AT signature
  const atSig = signComposed(payloadB64);
  if (!atSig) return null;

  const signatures = [];

  // AO signature first (if provided)
  if (aoSignature) {
    signatures.push(aoSignature);
  }

  // AT signature
  signatures.push(atSig);

  return {
    payload: payloadB64,
    signatures,
  };
}

/**
 * Full compose handler for POST /v1/compose
 */
export async function handleCompose(body, scanFn, mcpScanFn) {
  const {
    skill,        // SKILL.md content (optional)
    mcp,          // MCP manifest (optional)
    claim_hash,   // sha256 of the claim being verified
    v_gate,       // AgentOracle gate result (optional, provided by caller)
    mycelium_trail_id, // optional trail anchor
  } = body;

  if (!claim_hash) {
    return { error: 'claim_hash required' };
  }

  // Run AT scan
  let scanResult = { score: 0, level: 'SAFE', findings: [] };
  let skill_hash = 'sha256-' + 'a'.repeat(64); // placeholder if no skill

  if (skill) {
    const content = String(skill).slice(0, 100000);
    skill_hash = hashInput(content);
    const { scan } = await import('./scanner/engine.js');
    scanResult = scan(content);
  }

  if (mcp && typeof mcp === 'object') {
    const { scanMCP } = await import('./scanner/mcp.js');
    const mcpResult = scanMCP(mcp, true);
    // Merge: take worst level
    const levelRank = { SAFE: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
    if (levelRank[mcpResult.level] > levelRank[scanResult.level]) {
      scanResult = { ...mcpResult, findings: [...(scanResult.findings || []), ...(mcpResult.findings || [])] };
    }
  }

  // Build payload
  const payload = buildComposedPayload({
    claim_hash,
    skill_hash,
    v_gate: v_gate || null,
    scanResult,
    mycelium_trail_id: mycelium_trail_id || null,
  });

  // Build JWS
  const jws = buildComposedJWS(payload, v_gate?.signature_block || null);

  if (!jws) {
    return { error: 'JWS signing failed — key not configured' };
  }

  return {
    ok: true,
    composed_decision: payload.composed_decision,
    composed_decision_rule: 'AND_PRESENT',
    envelope_kind: 'verification.v0.3+composed',
    payload,
    jws,
    at_scan: {
      score: scanResult.score,
      level: scanResult.level,
      findings: scanResult.findings?.length || 0,
    },
  };
}
