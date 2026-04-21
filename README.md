# AgentTrust

**Security Scanner + Reputation Oracle for AI Agent Skills**

The trust layer for the x402 agent economy. Before your agent installs a skill, it asks AgentTrust.

    POST http://62.238.11.249:3402/v1/scan    — 0.015 USDC
    GET  http://62.238.11.249:3402/v1/trust   — 0.010 USDC
    POST http://62.238.11.249:3402/v1/verify  — 0.005 USDC
    POST http://62.238.11.249:3402/v1/report  — 0.050 USDC

Pay with USDC on Base. No accounts. No API keys. No signups.

## Why AgentTrust

20% of skills on ClawHub carry security risks. Cisco found data exfiltration and prompt injection in third-party OpenClaw skills. AgentTrust is the only permissionless, x402-native scanner in the ecosystem.

## Detection Rules (40 total)

| Category | Examples |
|---|---|
| backdoor | curl pipe to bash, reverse shells |
| credentials | cat ~/.env, id_rsa access |
| injection | prompt override, MCP tool poisoning |
| privilege | sudo chmod, crontab, SSH key inject |
| wallet | seed phrase, MetaMask vault, clipboard hijack |
| network | raw HTTP, WebSocket exfil, port scan |
| obfuscation | base64, hex, eval, env dump |
| supply_chain | typosquatting, remote imports |
| privacy | keylogger, screenshot, camera |
| suspicious | self-modifying skill, infinite loop |

## Quick Start

    curl -X POST http://62.238.11.249:3402/v1/scan \
      -H "Content-Type: application/json" \
      -H "X-Payment: <tx_hash>" \
      -d '{"content": "<skill content>"}'

## Self-Host

    git clone https://github.com/poteshniy/agenttrust
    cd agenttrust
    cp .env.example .env
    npm install && npm start

## Roadmap

- [x] v0.1 — Live x402 server, scan + trust
- [x] v0.2 — 40 rules, /v1/verify, /v1/report
- [ ] v0.3 — On-chain tx verification, rate limiting, SQLite
- [ ] v0.4 — ERC-8004 reputation registry on Base
- [ ] v0.5 — OpenClaw + Agentic.Market listing
- [ ] v1.0 — Web UI, GitHub Actions, whitelist registry

## License

MIT
