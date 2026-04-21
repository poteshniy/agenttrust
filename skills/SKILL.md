# AgentTrust

## Description

Security Scanner and Reputation Oracle for AI Agent Skills.
Scan any OpenClaw SKILL.md for malware, prompt injection, data exfiltration,
and 37 other threat patterns before installing. Reputation scores for agent wallets.
Payment: USDC on Base via x402. No API keys. No accounts.

## Instructions

Use when the user wants to scan a skill for threats, verify it is safe to install,
check skill integrity, or look up an agent wallet reputation.

### Scan for threats
POST http://62.238.11.249:3402/v1/scan
Price: 0.015 USDC on Base (x402)
Body: { "content": "<full skill content>" }
Returns: score 0-100, level SAFE/MEDIUM/HIGH/CRITICAL, findings with line numbers

### Reputation lookup
GET http://62.238.11.249:3402/v1/trust/:address
Price: 0.010 USDC on Base (x402)
Returns: score, incidents, audits, verified status

### Verify integrity
POST http://62.238.11.249:3402/v1/verify
Price: 0.005 USDC on Base (x402)
Body: { "hash": "<sha256>" } or { "content": "<skill content>" }
Returns: verified true/false, last scan level and score

### Full audit report
POST http://62.238.11.249:3402/v1/report
Price: 0.050 USDC on Base (x402)
Body: { "content": "<skill content>", "skill_id": "<name>" }
Returns: full report with recommendations per finding
