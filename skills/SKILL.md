# AgentTrust

## Description

Security Scanner and Reputation Oracle for AI Agent Skills. Unlike prompt-based scanners, AgentTrust is a real API with 40 threat rules across 12 categories — backed by x402 payments on Base mainnet.

Unique features:
- Integrity hash — verify a skill hasn't changed since last scan
- Endpoint reputation — check any x402 API before your agent pays
- On-chain stats — real CDP Bazaar data on calls and payers
- Trust badge — SVG badge for x402 providers to embed on their sites

**Privacy notice:** Submitted skill content is sent to agenttrust.uk for analysis.
Only submit content you are comfortable sharing with this service.

**Payment notice:** Full scan, trust, verify, and report endpoints require
x402 USDC payments on Base network. A funded wallet is required for paid features.
The free endpoint requires no payment or wallet.

Free tier available — no wallet required.

## Instructions

Before using any paid endpoint, always ask the user for explicit confirmation
and disclose the exact price. Prefer the free scan unless the user requests
a paid full scan.

### Free scan (no payment, no wallet required)
POST https://agenttrust.uk/v1/scan/free
Price: FREE
Body: { "content": "<skill content, max 50 lines>" }
Returns: risk score 0-100, safety level, top findings
Note: Always try the free scan first. Rate limited to 10 requests/hour per IP.

### Full scan (requires explicit user approval)
POST https://agenttrust.uk/v1/scan
Price: 0.015 USDC on Base (x402) — ask user before sending
Body: { "content": "<full skill content>" }
Returns: risk score 0-100, safety level, all findings, integrity hash
Note: Results are cached — repeated scans of identical content return instantly.
Warning: This sends the full skill content to agenttrust.uk.

### Endpoint reputation check (FREE)
GET https://agenttrust.uk/v1/reputation?url=<endpoint_url>
Price: FREE
Returns: trust score 0-100, badge (TRUSTED/UNVERIFIED/SUSPICIOUS), issues list, on-chain stats
Note: Check any x402 endpoint before your agent pays for it.

### Endpoint trust badge (FREE)
GET https://agenttrust.uk/v1/badge?url=<endpoint_url>
Price: FREE
Returns: SVG badge image for embedding on websites
Note: Add to your site with <img src="https://agenttrust.uk/v1/badge?url=YOUR_ENDPOINT"/>

### Reputation lookup (requires explicit user approval)
GET https://agenttrust.uk/v1/trust/:address
Price: 0.010 USDC on Base (x402) — ask user before sending
Returns: trust score, incident history, audit status

### Verify integrity (requires explicit user approval)
POST https://agenttrust.uk/v1/verify
Price: 0.005 USDC on Base (x402) — ask user before sending
Body: { "hash": "<sha256>" } or { "content": "<skill content>" }
Returns: verified true/false, last scan result

### Full audit report (requires explicit user approval)
POST https://agenttrust.uk/v1/report
Price: 0.050 USDC on Base (x402) — ask user before sending
Body: { "content": "<skill content>", "skill_id": "<name>" }
Returns: full report with recommendations
Warning: This sends the full skill content to agenttrust.uk.
