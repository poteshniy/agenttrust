/**
 * AgentTrust JWS Signing Utility
 * JSON serialization format matching draft-krausz-verification-state-00 fixtures
 * v_gate_mapping: agenttrust-v0.3-2026-06-07
 */

import { createHash, randomUUID, createPublicKey, sign as cryptoSign } from 'crypto';
import { readFileSync } from 'fs';

export const MAPPING_ID = 'agenttrust-v0.3-2026-06-07';
export const ISSUER = 'https://agenttrust.uk';
export const KID = 'agenttrust-ed25519-v1';
export const MAPPING_DOC_PATH = '/opt/agenttrust/docs/mapping-v0.3.md';

// Compute mapping doc hash once at startup
let _mappingHash = null;
export function getMappingHash() {
  if (_mappingHash) return _mappingHash;
  try {
    const content = readFileSync(MAPPING_DOC_PATH, 'utf8');
    _mappingHash = 'sha256-' + createHash('sha256').update(content).digest('hex');
    return _mappingHash;
  } catch {
    return process.env.MAPPING_HASH || 'sha256-pending';
  }
}

function b64url(input) {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return buf.toString('base64url');
}

// Derive recommendation from scan result
export function toRecommendation(level, score) {
  if (level === 'CRITICAL') return 'refuted';
  if (level === 'HIGH')     return 'refuted';
  if (level === 'MEDIUM')   return 'weak_supported';
  if (level === 'SAFE' && score === 0) return 'confident_supported';
  if (level === 'SAFE')     return 'weak_supported';
  return 'error';
}

export function toGate(recommendation) {
  return recommendation === 'confident_supported' ? 'act' : 'halt';
}

export function toVerdict(level) {
  return (level === 'SAFE') ? 'supported' : 'refuted';
}

export function toConfidence(level, score) {
  if (level === 'SAFE' && score === 0) return 0.95;
  if (level === 'SAFE') return 0.75;
  if (level === 'MEDIUM') return 0.40;
  return 0.00;
}

/**
 * Hash input content for claim binding
 */
export function hashInput(content) {
  return 'sha256-' + createHash('sha256').update(content).digest('hex');
}

/**
 * Sign a scan result and return JWS JSON serialization (matching fixture format)
 * @param {object} scanResult - result from scan() or scanMCP()
 * @param {string} inputHash - sha256-prefixed hash of input content
 * @param {string} scanType - 'skill_scan' | 'mcp_scan'
 * @returns {object|null} JWS JSON {protected, payload, signature} or null if no key
 */
export function signScanResult(scanResult, inputHash, scanType = 'skill_scan') {
  const privKeyPem = process.env.AGENTTRUST_PRIVATE_KEY;
  if (!privKeyPem) return null;

  const now = new Date();
  const validUntil = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000); // 90 days

  const recommendation = toRecommendation(scanResult.level, scanResult.score);
  const gate = toGate(recommendation);
  const mappingHash = getMappingHash();

  // JWS Header
  const header = {
    alg: 'EdDSA',
    kid: KID,
    typ: 'application/vnd.verification.v0.3+jws',
    cty: 'application/json',
  };

  // JWS Payload (matches fixture structure)
  const payload = {
    receipt_version: '0.3.0',
    mapping_id: MAPPING_ID,
    issuer: ISSUER,
    subject: {
      type: `verification.${scanType}`,
      claim_hash: inputHash,
    },
    evaluation_id: `at_${scanType}_${randomUUID().replace(/-/g, '').slice(0, 16)}`,
    issued_at: now.toISOString(),

    // Canonical input primitives (per IETF draft §4.2)
    v_verdict: toVerdict(scanResult.level),
    v_confidence: toConfidence(scanResult.level, scanResult.score),
    v_gate_threshold: 0.7,
    v_adversarial_result: 'not_checked',

    // Derived
    v_recommendation: recommendation,

    // Output
    v_gate: gate,

    // Binding
    v_gate_mapping: MAPPING_ID,
    v_gate_mapping_hash: mappingHash,

    // AgentTrust-specific provenance
    at_score: scanResult.score,
    at_level: scanResult.level,
    at_crits: scanResult.crits || 0,
    at_findings_count: (scanResult.findings || []).length,

    signature_meta: {
      jwks_uri: `${ISSUER}/.well-known/jwks.json`,
      valid_until: validUntil.toISOString(),
    },
  };

  try {
    const protectedB64 = b64url(JSON.stringify(header));
    const payloadB64 = b64url(JSON.stringify(payload));
    const sigInput = Buffer.from(`${protectedB64}.${payloadB64}`);

    const sigBuf = cryptoSign(null, sigInput, privKeyPem);

    return {
      protected: protectedB64,
      payload: payloadB64,
      signature: sigBuf.toString('base64url'),
    };
  } catch (err) {
    console.error('[jws] signing error:', err.message);
    return null;
  }
}

/**
 * Generate JWKS from env public key
 */
export function getJWKS() {
  const pubKeyPem = process.env.AGENTTRUST_PUBLIC_KEY;
  if (!pubKeyPem) return { keys: [] };
  try {
    const key = createPublicKey(pubKeyPem);
    const jwk = key.export({ format: 'jwk' });
    return { keys: [{ ...jwk, kid: KID, use: 'sig', alg: 'EdDSA' }] };
  } catch {
    return { keys: [] };
  }
}
