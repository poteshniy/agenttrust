const RULES = [
  { id: "S001", sev: 100, cat: "exfiltration",  desc: "Data exfiltration endpoint",         re: /https?:\/\/(?!api\.anthropic|api\.openai|github\.com|npmjs\.com)[a-z0-9.-]+\.[a-z]{2,}\/(?:upload|collect|exfil|send|log|track|beacon|ping|report)/i },
  { id: "S002", sev: 100, cat: "credentials",   desc: "Credential file access",             re: /(?:cat|read|open|type)\s+[~\/].*(?:\.env|id_rsa|id_ed25519|authorized_keys|shadow|passwd|keychain|vault|\.netrc|\.pgpass)/i },
  { id: "S003", sev: 100, cat: "backdoor",      desc: "Reverse shell attempt",              re: /(?:bash|sh|nc|ncat|netcat)\s+.*(?:-e|--exec|-c)\s+['"\/]?(?:bash|sh|cmd|powershell)/i },
  { id: "S004", sev: 100, cat: "backdoor",      desc: "Curl pipe to shell",                 re: /curl\s+.+\|\s*(?:bash|sh|python|node|perl|ruby)/i },
  { id: "S005", sev: 100, cat: "cryptominer",   desc: "Cryptominer process signature",      re: /(?:xmrig|minerd|cpuminer|cgminer|stratum\+tcp|mining\.pool)/i },
  { id: "S006", sev: 95,  cat: "injection",     desc: "Prompt injection attempt",           re: /(?:ignore\s+(?:all\s+)?(?:previous|above)\s+instructions?|you\s+are\s+now\s+in\s+\w+\s+mode|\[INST\]\s*System:|<\|system\|>|###\s*System\s*Override)/i },
  { id: "S007", sev: 95,  cat: "injection",     desc: "MCP tool poisoning",                 re: /(?:tool_call|function_call)\s*:\s*\{[^}]*(?:system|exec|shell|eval)[^}]*\}/i },
  { id: "S008", sev: 90,  cat: "privilege",     desc: "Privilege escalation via sudo",      re: /sudo\s+(?:chmod|chown|su\b|bash|sh\b|python|node|perl)\s*(?:777|[+-]x|root|-R)?/i },
  { id: "S009", sev: 90,  cat: "privilege",     desc: "Crontab modification",               re: /(?:crontab\s+-[el]|echo\s+.+>>\s*\/etc\/cron|\/etc\/cron\.d\/)/i },
  { id: "S010", sev: 88,  cat: "privilege",     desc: "SSH authorized_keys injection",      re: /echo\s+.+>>\s*~?\/.ssh\/authorized_keys/i },
  { id: "S011", sev: 85,  cat: "wallet",        desc: "Seed phrase extraction",             re: /(?:seed[_\s]?phrase|mnemonic|private[_\s]?key|wallet\.dat|keystore|\.json\s+wallet)/i },
  { id: "S012", sev: 85,  cat: "wallet",        desc: "MetaMask vault access",              re: /(?:metamask|phantom|exodus|ledger).*(?:vault|seed|key|password)/i },
  { id: "S013", sev: 82,  cat: "wallet",        desc: "Clipboard hijacking for addresses",  re: /(?:clipboard|navigator\.clipboard).*(?:0x[0-9a-f]{40}|write|replace)/i },
  { id: "S014", sev: 80,  cat: "network",       desc: "Raw HTTP to non-whitelisted host",   re: /fetch\s*\(\s*['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'"]+['"]/i },
  { id: "S015", sev: 80,  cat: "network",       desc: "WebSocket to external host",         re: /new\s+WebSocket\s*\(\s*['"]wss?:\/\/(?!localhost)[^'"]+['"]/i },
  { id: "S016", sev: 78,  cat: "network",       desc: "DNS lookup for exfiltration",        re: /(?:nslookup|dig|host)\s+[a-z0-9.-]+\.[a-z]{2,}/i },
  { id: "S017", sev: 75,  cat: "network",       desc: "Port scanning activity",             re: /(?:nmap|masscan|zmap|nc\s+-z)\s+/i },
  { id: "S018", sev: 75,  cat: "filesystem",    desc: "System file write",                  re: /(?:write|append|tee|echo\s+.+>>?)\s+['"]?\/(?:etc|proc|sys|boot|root|usr\/bin)\//i },
  { id: "S019", sev: 72,  cat: "filesystem",    desc: "SSH key generation",                 re: /ssh-keygen\s+/i },
  { id: "S020", sev: 70,  cat: "filesystem",    desc: "Mass file deletion",                 re: /rm\s+(?:-rf?|--recursive)\s+(?:\/|~|\$HOME|\*)/i },
  { id: "S021", sev: 65,  cat: "obfuscation",   desc: "Base64 encoded payload",             re: /(?:atob|btoa|base64\s*(?:-d|-D)|Buffer\.from\([^,]+,\s*['"]base64['"]\))/i },
  { id: "S022", sev: 65,  cat: "obfuscation",   desc: "Hex encoded payload",                re: /(?:\\x[0-9a-f]{2}){6,}/i },
  { id: "S023", sev: 62,  cat: "obfuscation",   desc: "Character code obfuscation",         re: /(?:String\.fromCharCode|chr\()\s*\(\s*\d+(?:\s*,\s*\d+){5,}/i },
  { id: "S024", sev: 60,  cat: "obfuscation",   desc: "Dynamic code execution",             re: /eval\s*\(\s*(?:fetch|atob|Buffer|require|__)/i },
  { id: "S025", sev: 58,  cat: "obfuscation",   desc: "Process environment dump",           re: /process\.env(?!\.(PORT|NODE_ENV|PATH|HOME|PAYMENT))/i },
  { id: "S026", sev: 55,  cat: "supply_chain",  desc: "Typosquatted package name",          re: /(?:requirre|improt|lодаsh|expres\b|mongooose|axois|reqest)\s*[=(]/i },
  { id: "S027", sev: 55,  cat: "supply_chain",  desc: "Unpinned remote script import",      re: /import\s+.+from\s+['"]https?:\/\/(?!esm\.sh|cdn\.skypack|unpkg\.com|deno\.land)[^'"]+['"]/i },
  { id: "S028", sev: 52,  cat: "supply_chain",  desc: "Postinstall script hook",            re: /["']postinstall["']\s*:\s*["'][^"']+["']/i },
  { id: "S029", sev: 50,  cat: "privacy",       desc: "PII collection pattern",             re: /(?:ssn|social.security|credit.card|cvv|passport.number)\s*[=:]/i },
  { id: "S030", sev: 50,  cat: "privacy",       desc: "Keylogger pattern",                  re: /(?:keydown|keypress|keyup)\s*.*(?:send|post|fetch|log)/i },
  { id: "S031", sev: 48,  cat: "privacy",       desc: "Screenshot capture",                 re: /(?:screenshot|screen\.capture|getDisplayMedia|html2canvas)/i },
  { id: "S032", sev: 45,  cat: "privacy",       desc: "Microphone or camera access",        re: /getUserMedia\s*\(\s*\{[^}]*(?:audio|video)\s*:\s*true/i },
  { id: "S033", sev: 40,  cat: "suspicious",    desc: "Broad filesystem enumeration",       re: /(?:readdirSync|glob\.sync|find\s+\/\s+-name)\s*['"\/]/i },
  { id: "S034", sev: 38,  cat: "suspicious",    desc: "Self-modifying skill",               re: /(?:writeFile|appendFile)\s*\(['"]\.\/?SKILL\.md['"]/i },
  { id: "S035", sev: 35,  cat: "suspicious",    desc: "Timing-based evasion",               re: /setTimeout\s*\([^,]+,\s*(?:[6-9]\d{4}|\d{6,})\)/i },
  { id: "S036", sev: 32,  cat: "suspicious",    desc: "Hidden iframe injection",            re: /<iframe[^>]+(?:display\s*:\s*none|visibility\s*:\s*hidden)/i },
  { id: "S037", sev: 30,  cat: "suspicious",    desc: "Sensitive data in localStorage",     re: /localStorage\.setItem\s*\(['"]\w*(?:key|token|pass|secret|auth)\w*['"]/i },
  { id: "S038", sev: 28,  cat: "suspicious",    desc: "Aggressive memory allocation",       re: /new\s+(?:Array|Buffer|Uint8Array)\s*\(\s*(?:[1-9]\d{8,})\s*\)/i },
  { id: "S039", sev: 25,  cat: "suspicious",    desc: "Infinite loop risk",                 re: /while\s*\(\s*true\s*\)\s*\{(?!.*break)/i },
  { id: "S040", sev: 20,  cat: "suspicious",    desc: "Unvalidated user redirect",          re: /(?:window\.location|location\.href)\s*=\s*(?:req\.|request\.|params\.|query\.)/i },
];

export function scan(text) {
  const lines = text.split('\n');
  const findings = [];
  for (const rule of RULES) {
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(rule.re);
      if (m) { findings.push({ id: rule.id, sev: rule.sev, cat: rule.cat, desc: rule.desc, line: i + 1, match: m[0].slice(0, 100) }); break; }
    }
  }
  findings.sort((a, b) => b.sev - a.sev);
  const score   = Math.min(100, crits*30 + highs*15 + mediums*7 + lows*2);
  const crits   = findings.filter(f => f.sev >= 90).length;
  const highs   = findings.filter(f => f.sev >= 70 && f.sev < 90).length;
  const mediums = findings.filter(f => f.sev >= 40 && f.sev < 70).length;
  const lows    = findings.filter(f => f.sev < 40).length;
  const level   = crits > 0 ? 'CRITICAL' : score >= 70 ? 'CRITICAL' : score >= 40 ? 'HIGH' : score >= 15 ? 'MEDIUM' : 'SAFE';
  const cats    = {};
  for (const f of findings) cats[f.cat] = (cats[f.cat] || 0) + 1;
  return { score: Math.round(score), level, findings, crits, highs, mediums, lows, categories: cats };
}
