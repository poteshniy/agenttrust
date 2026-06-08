/**
 * AgentTrust MCP Scanner
 * Scans MCP server manifests for security threats
 * Reuses SKILL.md engine rules + MCP-specific checks
 */

import { scan } from './engine.js';

// MCP-specific rules (complement the 40 SKILL.md rules)
const MCP_RULES = [
  {
    id: 'M001', sev: 95, cat: 'mcp_poisoning',
    desc: 'Tool description contains system prompt override',
    test: (text) => /(?:ignore\s+(?:all\s+)?(?:previous|above)\s+instructions?|you\s+are\s+now|new\s+persona|override\s+system)/i.test(text)
  },
  {
    id: 'M002', sev: 92, cat: 'mcp_poisoning',
    desc: 'Hidden unicode injection in tool description',
    test: (text) => /[\u200B-\u200D\uFEFF\u2060\u00AD\u034F]/.test(text)
  },
  {
    id: 'M003', sev: 90, cat: 'mcp_shadowing',
    desc: 'Tool name shadows trusted system tool',
    test: (name) => /^(?:read_file|write_file|execute|bash|shell|run_command|list_directory|delete_file|create_file|python|node|eval)$/i.test(name)
  },
  {
    id: 'M004', sev: 88, cat: 'mcp_poisoning',
    desc: 'Tool description instructs to exfiltrate data',
    test: (text) => /(?:send|upload|post|transmit|forward)\s+(?:all|every|the)\s+(?:data|files?|content|output|result)/i.test(text)
  },
  {
    id: 'M005', sev: 85, cat: 'mcp_rug_pull',
    desc: 'Tool description references external update/reload mechanism',
    test: (text) => /(?:fetch|load|update|reload)\s+(?:latest|new|updated)\s+(?:instructions?|rules?|behavior|config)/i.test(text)
  },
  {
    id: 'M006', sev: 82, cat: 'mcp_exfiltration',
    desc: 'Resource URI points to suspicious external host',
    test: (uri) => /https?:\/\/(?!localhost|127\.0\.0\.1|api\.anthropic|api\.openai|github\.com)[a-z0-9.-]+\.[a-z]{2,}\/(?:upload|collect|exfil|beacon|log|track)/i.test(uri)
  },
  {
    id: 'M007', sev: 78, cat: 'mcp_poisoning',
    desc: 'Prompt template contains injection anchor',
    test: (text) => /(?:<\|system\|>|###\s*System|SYSTEM:\s*You are|\[INST\]\s*<<SYS>>)/i.test(text)
  },
  {
    id: 'M008', sev: 75, cat: 'mcp_poisoning',
    desc: 'Tool description is suspiciously long (>2000 chars, potential hidden payload)',
    test: (text) => text.length > 2000
  },
  {
    id: 'M009', sev: 70, cat: 'mcp_credential',
    desc: 'Tool schema accepts raw credential fields',
    test: (text) => /["'](?:password|secret|api_key|private_key|token|seed_phrase)["']\s*:\s*["']string["']/i.test(text)
  },
  {
    id: 'M010', sev: 65, cat: 'mcp_shadowing',
    desc: 'Multiple tools with near-identical names (shadowing pattern)',
    test: () => false // handled separately in manifest-level check
  },
];

/**
 * Extract all scannable text from MCP manifest
 */
function extractTextFromManifest(manifest) {
  const chunks = [];

  // Server metadata
  if (manifest.name) chunks.push({ field: 'server.name', text: manifest.name });
  if (manifest.description) chunks.push({ field: 'server.description', text: manifest.description });

  // Tools
  const tools = manifest.tools || [];
  for (const tool of tools) {
    if (tool.name) chunks.push({ field: `tool.${tool.name}.name`, text: tool.name, isName: true });
    if (tool.description) chunks.push({ field: `tool.${tool.name}.description`, text: tool.description });
    if (tool.inputSchema) chunks.push({ field: `tool.${tool.name}.schema`, text: JSON.stringify(tool.inputSchema) });
  }

  // Resources
  const resources = manifest.resources || [];
  for (const res of resources) {
    if (res.uri) chunks.push({ field: `resource.uri`, text: res.uri, isUri: true });
    if (res.description) chunks.push({ field: `resource.description`, text: res.description });
  }

  // Prompts
  const prompts = manifest.prompts || [];
  for (const prompt of prompts) {
    if (prompt.description) chunks.push({ field: `prompt.description`, text: prompt.description });
    if (prompt.template) chunks.push({ field: `prompt.template`, text: prompt.template });
  }

  return chunks;
}

/**
 * Check for tool name shadowing (near-duplicate names)
 */
function checkToolShadowing(tools) {
  const findings = [];
  const names = tools.map(t => t.name?.toLowerCase()).filter(Boolean);
  const seen = new Set();
  for (const name of names) {
    // Check near-duplicates (edit distance 1)
    for (const other of seen) {
      if (name !== other && levenshtein(name, other) <= 1) {
        findings.push({
          id: 'M010', sev: 65, cat: 'mcp_shadowing',
          desc: `Near-duplicate tool names detected: "${name}" vs "${other}"`,
          field: 'tools', match: `${name} / ${other}`
        });
      }
    }
    seen.add(name);
  }
  return findings;
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return dp[a.length][b.length];
}

/**
 * Scan MCP manifest JSON
 * @param {object} manifest - parsed MCP server manifest
 * @param {boolean} fullScan - true for paid full scan, false for free tier
 */
export function scanMCP(manifest, fullScan = false) {
  // Safety: limit manifest size to prevent DoS
  const manifestStr = JSON.stringify(manifest);
  if (manifestStr.length > 512 * 1024) {
    return { score: 0, level: 'SAFE', findings: [], crits: 0, highs: 0, mediums: 0, lows: 0,
      manifest_stats: { tools: 0, resources: 0, prompts: 0 }, error: 'Manifest too large (max 512KB)' };
  }
  const findings = [];
  const chunks = extractTextFromManifest(manifest);

  // Apply MCP-specific rules
  const rulesToApply = fullScan ? MCP_RULES : MCP_RULES.slice(0, 3);

  for (const chunk of chunks) {
    for (const rule of rulesToApply) {
      if (rule.id === 'M010') continue; // handled separately
      // M003 only applies to tool names, M006 only to resource URIs
      if (rule.id === 'M003' && !chunk.isName) continue;
      if (rule.id === 'M006' && !chunk.isUri) continue;
      if (rule.test(chunk.text)) {
        findings.push({
          id: rule.id, sev: rule.sev, cat: rule.cat,
          desc: rule.desc, field: chunk.field,
          match: chunk.text.slice(0, 100)
        });
        break;
      }
    }
  }

  // Tool shadowing check (manifest-level)
  if (fullScan && manifest.tools) {
    findings.push(...checkToolShadowing(manifest.tools));
  }

  // Also run SKILL.md engine rules on all concatenated text (catch code in descriptions)
  const allText = chunks.map(c => c.text).join('\n');
  if (fullScan) {
    const engineResult = scan(allText);
    for (const f of engineResult.findings) {
      // Avoid duplicates
      if (!findings.find(x => x.id === f.id)) {
        findings.push({ ...f, field: 'content' });
      }
    }
  }

  findings.sort((a, b) => b.sev - a.sev);

  const crits   = findings.filter(f => f.sev >= 90).length;
  const highs   = findings.filter(f => f.sev >= 70 && f.sev < 90).length;
  const mediums = findings.filter(f => f.sev >= 40 && f.sev < 70).length;
  const lows    = findings.filter(f => f.sev < 40).length;
  const score   = Math.min(100, crits*30 + highs*15 + mediums*7 + lows*2);
  const level   = crits > 0 ? 'CRITICAL' : highs > 2 ? 'HIGH' : score >= 15 ? 'MEDIUM' : 'SAFE';

  // Stats
  const toolCount = (manifest.tools || []).length;
  const resourceCount = (manifest.resources || []).length;

  return {
    score: Math.round(score),
    level,
    findings: fullScan ? findings : findings.slice(0, 3),
    crits, highs, mediums, lows,
    manifest_stats: { tools: toolCount, resources: resourceCount, prompts: (manifest.prompts || []).length },
    limits: fullScan ? null : { rules_checked: 3, rules_total: MCP_RULES.length + 40, tools_checked: Math.min(toolCount, 3), tools_total: toolCount },
    upgrade: fullScan ? null : { endpoint: 'POST /v1/scan/mcp', price: '$0.015 USDC via x402' }
  };
}
