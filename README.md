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
- [x] v0.6 — SQLite persistence, rate limiting, on-chain tx verification
- [x] v0.7 — `GET /v1/reputation/{endpoint}` — trust score for any x402 endpoint, AgentTrust Badge
- [x] v0.8 — ERC-8257 Agent Tool Registry (Tool #5 on Base mainnet)
- [x] v0.9 — Provider dashboard, paid listings, trust-gated middleware API
- [ ] v1.0 — First paying providers, reputation infrastructure for x402 ecosystem

## ERC-8257 Registry

AgentTrust is registered as Tool #5 on the [ERC-8257 Agent Tool Registry](https://8257.ai) on Base mainnet.

- Tool ID: 5
- Registry: [0x265BB2DBFC0A8165C9A1941Eb1372F349baD2cf1](https://basescan.org/address/0x265BB2DBFC0A8165C9A1941Eb1372F349baD2cf1)
- TX: [0xc39794a4719c4a05d1909f8735fc2571d5f083e02a60ef840193cdd90d3b805a](https://basescan.org/tx/0xc39794a4719c4a05d1909f8735fc2571d5f083e02a60ef840193cdd90d3b805a)

## Resources

- Article: https://dev.to/poteshniy/i-built-a-security-scanner-for-ai-agent-skills-paid-per-scan-via-x402-no-api-keys-published-ai-4hi3
- ClawHub: https://clawhub.ai/poteshniy/agenttrust-scanner
- Live: https://agenttrust.uk

## License

MIT

## API Endpoints

| Endpoint | Price | Description |
|---|---|---|
| `POST /v1/scan` | $0.015 USDC | Full scan, 40 rules |
| `POST /v1/scan/free` | FREE | Quick scan, 5 rules, max 50 lines |
| `GET /v1/reputation` | FREE | x402 endpoint reputation check |
| `GET /v1/badge` | FREE | SVG trust badge for embedding |
| `GET /v1/trust/:address` | $0.010 USDC | Agent wallet reputation lookup |
| `POST /v1/verify` | $0.005 USDC | Verify skill hash integrity |
| `POST /v1/report` | $0.050 USDC | Full audit report |
