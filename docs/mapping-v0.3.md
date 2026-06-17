# AgentTrust Mapping Document
# ID: agenttrust-v0.3-2026-06-07
# Conforming implementation of draft-krausz-verification-state-01

## Overview

This document specifies how AgentTrust derives `v_recommendation` and `v_gate`
from scan primitives, per the `verification.*` constraint family
(draft-krausz-verification-state-01).

This mapping is **immutable after publication**. Future rule changes ship under
a new mapping ID.

## Canonical Inputs

| Field | Source | Description |
|---|---|---|
| `v_verdict` | derived | `supported` if level=SAFE, `refuted` otherwise |
| `v_confidence` | derived | 0.95 for SAFE, 0.0 for CRITICAL/HIGH, 0.5 for MEDIUM |
| `v_adversarial_result` | static | `not_checked` (adversarial probing not performed in v0.3) |

## Derived Fields (AgentTrust-specific)

| Field | Values | Description |
|---|---|---|
| `at_score` | 0–100 | Threat score (higher = more threats) |
| `at_level` | SAFE / MEDIUM / HIGH / CRITICAL | Human-readable threat level |
| `at_crits` | integer | Number of CRITICAL findings (sev ≥ 90) |

## Scoring Rules

### SKILL.md / Source Code
```
threat_score = crits×30 + highs×15 + mediums×7 + lows×2  (max 100)
level = CRITICAL if crits > 0
      | HIGH     if highs > 2
      | MEDIUM   if threat_score >= 15
      | SAFE     otherwise
```

### MCP Manifest
Same formula applied to MCP-specific rules (M001–M010) plus engine rules
applied to concatenated manifest text.

## Recommendation Mapping

| at_level | v_recommendation | v_gate |
|---|---|---|
| SAFE (score ≥ 90) | `confident_supported` | `act` |
| SAFE (score < 90) | `weak_supported` | `halt` |
| MEDIUM | `weak_supported` | `halt` |
| HIGH | `refuted` | `halt` |
| CRITICAL | `refuted` | `halt` |
| error | `error` | `halt` |

**Fail-closed mandate:** any ambiguous or error condition results in `halt`.
`un_probed_not_cleared` is not used in v0.3 because `v_adversarial_result`
is always `not_checked` — all non-SAFE results halt unconditionally.

## Threshold Rule

Confidence threshold for `confident_supported`: **0.90**

A SAFE scan with threat_score = 0 (no findings) yields confidence 0.95,
exceeding the threshold → `confident_supported` → `act`.

Any non-zero threat score or non-SAFE level yields confidence < threshold
or verdict = refuted → `halt`.

## JWS Envelope

- Algorithm: `EdDSA` (Ed25519)
- Key: published at `https://agenttrust.uk/.well-known/jwks.json`
- `kid`: `agenttrust-ed25519-v1`
- `typ`: `verification-receipt+jws`
- Receipt validity: 3600 seconds (`exp = iat + 3600`)

## Reference Implementation

- Live endpoint: `POST https://agenttrust.uk/v1/scan`
- MCP endpoint: `POST https://agenttrust.uk/v1/scan/mcp`
- GitHub: https://github.com/poteshniy/agenttrust
- Spec reference: draft-krausz-verification-state-01
  https://datatracker.ietf.org/doc/draft-krausz-verification-state/

## Changelog

- `agenttrust-v0.3-2026-06-07`: Initial publication. SKILL.md + MCP scanning.
  Adversarial probing not performed (v_adversarial_result = not_checked).
  All non-SAFE results halt.
