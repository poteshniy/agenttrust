# AgentTrust
**Security Scanner + Reputation Oracle for AI Agent Skills**

The trust layer for the x402 agent economy. Before your agent installs a skill or connects an MCP server, it asks AgentTrust.

    POST /v1/scan           — $0.015 USDC — full SKILL.md scan, 40 rules
    POST /v1/scan/free      — FREE        — quick scan, 5 rules, max 50 lines
    POST /v1/scan/mcp       — $0.015 USDC — full MCP manifest scan
    POST /v1/scan/mcp/free  — FREE        — MCP scan, 3 rules
    POST /v1/gate           — FREE        — unified ACT/HALT gate (skill + MCP + endpoint)
    GET  /v1/reputation     — FREE        — x402 endpoint reputation
    GET  /v1/badge          — FREE        — SVG trust badge
    GET  /v1/trust/:addr    — $0.010 USDC — agent wallet reputation
    POST /v1/verify         — $0.005 USDC — verify skill hash integrity
    POST /v1/report         — $0.050 USDC — full audit report

Pay with USDC on Base. No accounts. No API keys. No signups.

Live: https://agenttrust.uk | Dashboard: https://agenttrust.uk/dashboard

## Why

AI agents install skills and connect MCP servers without knowing what's inside. AgentTrust scans for malware, prompt injection, tool poisoning, and 47 other threat patterns — and returns a cryptographically signed ACT/HALT receipt your agent can verify.

The only permissionless, x402-native scanner in the ecosystem. Registered as Tool #5 on ERC-8257 Agent Tool Registry on Base mainnet.

## Quick Start

    # Free SKILL.md scan
    curl -X POST https://agenttrust.uk/v1/scan/free \
      -H "Content-Type: application/json" \
      -d '{"content": "<skill content>"}'

    # Free MCP manifest scan
    curl -X POST https://agenttrust.uk/v1/scan/mcp/free \
      -H "Content-Type: application/json" \
      -d '{"manifest": {"name": "my-server", "tools": [...]}}'

    # Unified gate — skill + MCP + endpoint in one call
    curl -X POST https://agenttrust.uk/v1/gate \
      -H "Content-Type: application/json" \
      -d '{"skill": "<content>", "mcp": {...}, "endpoint": "https://..."}'

    # Install as OpenClaw skill
    npx clawhub@latest install agenttrust-scanner

## JWS-Signed Receipts

Every scan response includes a cryptographically signed receipt per draft-krausz-verification-state-00:
https://datatracker.ietf.org/doc/draft-krausz-verification-state/

    {
      "v_gate": "halt",
      "v_recommendation": "refuted",
      "v_gate_mapping": "agenttrust-v0.3-2026-06-07",
      "receipt": { "protected": "...", "payload": "...", "signature": "..." }
    }

JWKS:        https://agenttrust.uk/.well-known/jwks.json
Mapping doc: https://raw.githubusercontent.com/poteshniy/agenttrust/main/docs/mapping-v0.3.md
Mapping hash: sha256-70f75200320cef0eed011197efe45c1ca063e8b98b002a623001e26adc496d29

## Roadmap

- [x] v0.1 — Live x402 server, scan + trust
- [x] v0.2 — 40 rules, /v1/verify, /v1/report, /v1/scan/free
- [x] v0.3 — GitHub public repo
- [x] v0.4 — CDP Bazaar indexing, ClawHub listing, agenttrust.uk domain
- [x] v0.5 — Twitter launch, web landing page
- [x] v0.6 — SQLite persistence, rate limiting, on-chain tx verification
- [x] v0.7 — GET /v1/reputation — trust score for any x402 endpoint, AgentTrust Badge
- [x] v0.8 — ERC-8257 Agent Tool Registry (Tool #5 on Base mainnet)
- [x] v0.9 — Provider dashboard, SIWE auth, verified providers, site redesign
- [x] v0.9.1 — MCP manifest scanner, JWS-signed receipts, second impl of draft-krausz-verification-state-00
- [x] v0.9.2 — Unified trust gate (POST /v1/gate) — skill + MCP + endpoint in one signed call
- [ ] v1.0 — First paying providers, GitHub Action, trust-gated middleware

## ERC-8257 Registry

Tool #5 on Base mainnet.
- Registry: 0x265BB2DBFC0A8165C9A1941Eb1372F349baD2cf1
- TX: 0xc39794a4719c4a05d1909f8735fc2571d5f083e02a60ef840193cdd90d3b805a

## API Endpoints

| Endpoint | Price | Description |
|---|---|---|
| POST /v1/scan | $0.015 USDC | Full SKILL.md scan, 40 rules, JWS receipt |
| POST /v1/scan/free | FREE | Quick scan, 5 rules, JWS receipt |
| POST /v1/scan/mcp | $0.015 USDC | Full MCP manifest scan, JWS receipt |
| POST /v1/scan/mcp/free | FREE | MCP scan, 3 rules, JWS receipt |
| POST /v1/gate | FREE | Unified ACT/HALT gate, JWS receipt |
| GET /v1/reputation | FREE | x402 endpoint reputation |
| GET /v1/badge | FREE | SVG trust badge |
| GET /v1/trust/:address | $0.010 USDC | Agent wallet reputation |
| POST /v1/verify | $0.005 USDC | Verify skill hash integrity |
| POST /v1/report | $0.050 USDC | Full audit report |

## Resources

- ClawHub: https://clawhub.ai/poteshniy/agenttrust-scanner
- Article: https://dev.to/poteshniy/i-built-a-security-scanner-for-ai-agent-skills-paid-per-scan-via-x402-no-api-keys-published-ai-4hi3
- Live: https://agenttrust.uk

## License
MIT
