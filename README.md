# AgentTrust

**Security Scanner + Reputation Oracle for AI Agent Skills**

The trust layer for the x402 agent economy. Before your agent installs a skill, it asks AgentTrust.

    POST /v1/scan       — 0.015 USDC — full scan, 40 rules
    POST /v1/scan/free  — FREE       — quick scan, 5 rules, max 50 lines
    GET  /v1/trust      — 0.010 USDC — agent reputation lookup
    POST /v1/verify     — 0.005 USDC — verify skill hash integrity
    POST /v1/report     — 0.050 USDC — full audit report

Pay with USDC on Base. No accounts. No API keys. No signups.

Live at: https://agenttrust.uk

## Why

20% of skills on ClawHub carry security risks. Cisco found data exfiltration and prompt injection in third-party OpenClaw skills. AgentTrust is the only permissionless, x402-native scanner in the ecosystem.

## Quick Start

    # Free scan — no wallet needed
    curl -X POST https://agenttrust.uk/v1/scan/free \
      -H "Content-Type: application/json" \
      -d '{"content": "<skill content>"}'

    # Install as OpenClaw skill
    npx clawhub@latest install agenttrust-scanner

## Self-Host

    git clone https://github.com/poteshniy/agenttrust
    cd agenttrust && cp .env.example .env
    npm install && npm start

## Roadmap

- [x] v0.1 — Live x402 server, scan + trust
- [x] v0.2 — 40 rules, /v1/verify, /v1/report, /v1/scan/free
- [x] v0.3 — GitHub public repo
- [x] v0.4 — CDP Bazaar indexing, ClawHub listing, agenttrust.uk domain
- [x] v0.5 — Twitter launch, web landing page
- [ ] v0.6 — On-chain tx verification, rate limiting, SQLite persistence
- [ ] v0.7 — ERC-8004 reputation registry on Base
- [ ] v1.0 — GitHub Actions integration, whitelist registry, first paying users

## Resources

- Article: https://dev.to/poteshniy/i-built-a-security-scanner-for-ai-agent-skills-paid-per-scan-via-x402-no-api-keys-published-ai-4hi3
- ClawHub: https://clawhub.ai/poteshniy/agenttrust-scanner
- Live: https://agenttrust.uk

## License

MIT
