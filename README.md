# AgentTrust

**Security Scanner + Reputation Oracle for AI Agent Skills**

The trust layer for the x402 agent economy.

    POST /v1/scan    — 0.015 USDC — scan skill for threats (40 rules)
    GET  /v1/trust   — 0.010 USDC — agent reputation lookup
    POST /v1/verify  — 0.005 USDC — verify skill hash integrity
    POST /v1/report  — 0.050 USDC — full audit report

Pay with USDC on Base. No accounts. No API keys. No signups.

## Why

20% of skills on ClawHub carry security risks. Cisco found data exfiltration
and prompt injection in third-party OpenClaw skills. AgentTrust is the only
permissionless, x402-native scanner in the ecosystem.

## Quick Start

    curl -X POST http://62.238.11.249:3402/v1/scan \
      -H "Content-Type: application/json" \
      -H "X-Payment: <tx_hash>" \
      -d '{"content": "<skill content>"}'

## Self-Host

    git clone https://github.com/poteshniy/agenttrust
    cd agenttrust && cp .env.example .env
    npm install && npm start

## Roadmap

- [x] v0.1 - Live x402 server, scan + trust
- [x] v0.2 - 40 rules, /v1/verify, /v1/report
- [x] v0.3 - GitHub public repo
- [ ] v0.4 - OpenClaw SKILL.md listing + Agentic.Market indexing
- [ ] v0.5 - Twitter launch + first external users
- [ ] v0.6 - On-chain tx verification, rate limiting, SQLite
- [ ] v0.7 - ERC-8004 reputation registry on Base
- [ ] v1.0 - Web UI, GitHub Actions, whitelist registry

## License

MIT
