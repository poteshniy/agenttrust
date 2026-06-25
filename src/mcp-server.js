import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const API = 'https://agenttrust.uk';

async function call(endpoint, body) {
  const r = await fetch(`${API}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return r.json();
}

async function get(endpoint) {
  const r = await fetch(`${API}${endpoint}`);
  return r.json();
}

const server = new McpServer({
  name: 'agenttrust',
  version: '1.0.0',
  description: 'Security scanner and reputation oracle for AI agent skills and MCP servers',
});

// 1. scan_skill_free
server.tool('scan_skill_free',
  { content: z.string().describe('SKILL.md content to scan (max 50 lines)') },
  async ({ content }) => {
    const r = await call('/v1/scan/free', { content });
    return { content: [{ type: 'text', text: JSON.stringify(r, null, 2) }] };
  }
);

// 2. scan_skill
server.tool('scan_skill',
  { content: z.string().describe('Full SKILL.md content to scan (40 rules, $0.015 USDC)') },
  async ({ content }) => {
    const r = await call('/v1/scan', { content });
    return { content: [{ type: 'text', text: JSON.stringify(r, null, 2) }] };
  }
);

// 3. scan_mcp_free
server.tool('scan_mcp_free',
  { manifest: z.record(z.any()).describe('MCP server manifest JSON to scan (3 rules, free)') },
  async ({ manifest }) => {
    const r = await call('/v1/scan/mcp/free', { manifest });
    return { content: [{ type: 'text', text: JSON.stringify(r, null, 2) }] };
  }
);

// 4. scan_mcp
server.tool('scan_mcp',
  { manifest: z.record(z.any()).describe('MCP server manifest JSON to scan (50 rules, $0.015 USDC)') },
  async ({ manifest }) => {
    const r = await call('/v1/scan/mcp', { manifest });
    return { content: [{ type: 'text', text: JSON.stringify(r, null, 2) }] };
  }
);

// 5. trust_gate
server.tool('trust_gate',
  {
    skill: z.string().optional().describe('SKILL.md content'),
    mcp: z.record(z.any()).optional().describe('MCP manifest JSON'),
    endpoint: z.string().optional().describe('x402 endpoint URL'),
  },
  async (args) => {
    const r = await call('/v1/gate', args);
    return { content: [{ type: 'text', text: JSON.stringify(r, null, 2) }] };
  }
);

// 6. check_reputation
server.tool('check_reputation',
  { url: z.string().describe('x402 endpoint URL to check reputation') },
  async ({ url }) => {
    const r = await get(`/v1/reputation?url=${encodeURIComponent(url)}`);
    return { content: [{ type: 'text', text: JSON.stringify(r, null, 2) }] };
  }
);

// 7. verify_hash
server.tool('verify_hash',
  {
    content: z.string().optional().describe('SKILL.md content to verify'),
    hash: z.string().optional().describe('SHA256 hash to verify'),
  },
  async (args) => {
    const r = await call('/v1/verify', args);
    return { content: [{ type: 'text', text: JSON.stringify(r, null, 2) }] };
  }
);

// 8. full_report
server.tool('full_report',
  {
    content: z.string().describe('SKILL.md content for full audit ($0.050 USDC)'),
    skill_id: z.string().optional().describe('Skill name or identifier'),
  },
  async (args) => {
    const r = await call('/v1/report', args);
    return { content: [{ type: 'text', text: JSON.stringify(r, null, 2) }] };
  }
);

// 9. wallet_reputation
server.tool('wallet_reputation',
  { address: z.string().describe('Agent wallet address to look up ($0.010 USDC)') },
  async ({ address }) => {
    const r = await get(`/v1/trust/${address}`);
    return { content: [{ type: 'text', text: JSON.stringify(r, null, 2) }] };
  }
);

// 10. get_badge_url
server.tool('get_badge_url',
  { url: z.string().describe('x402 endpoint URL to get trust badge for') },
  async ({ url }) => {
    const badge_url = `${API}/v1/badge?url=${encodeURIComponent(url)}`;
    return { content: [{ type: 'text', text: JSON.stringify({ badge_url, embed: `<img src="${badge_url}"/>` }, null, 2) }] };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
console.error('AgentTrust MCP Server running');
