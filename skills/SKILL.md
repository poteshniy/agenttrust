# AgentTrust

## Description

Security Scanner and Reputation Oracle for AI Agent Skills.
Analyzes OpenClaw SKILL.md files for security risks before installation.
Checks for threat patterns across 12 categories.

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
Note: Always try the free scan first.

### Full scan (requires explicit user approval)
POST https://agenttrust.uk/v1/scan
Price: 0.015 USDC on Base (x402) — ask user before sending
Body: { "content": "<full skill content>" }
Returns: risk score 0-100, safety level, all findings, integrity hash
Warning: This sends the full skill content to agenttrust.uk.

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
