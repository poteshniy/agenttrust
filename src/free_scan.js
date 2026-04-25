export function freeScan(content) {
  const lines = content.split('\n');
  const findings = [];

  const checks = [
    { id: 'S001', sev: 100, cat: 'backdoor',     desc: 'Curl pipe to shell',       test: (l) => /curl.*\|.*(bash|sh|python|node)/i.test(l) },
    { id: 'S002', sev: 100, cat: 'credentials',  desc: 'Credential file access',   test: (l) => /cat\s+.*\.(env|pem|key)/.test(l) || /cat.*id_rsa/.test(l) },
    { id: 'S003', sev: 95,  cat: 'injection',    desc: 'Prompt injection attempt', test: (l) => /ignore.*(previous|above).*instructions/i.test(l) },
    { id: 'S004', sev: 90,  cat: 'privilege',    desc: 'Privilege escalation',     test: (l) => /sudo\s+(chmod|bash|sh|python)/.test(l) },
    { id: 'S005', sev: 85,  cat: 'wallet',       desc: 'Seed phrase extraction',   test: (l) => /seed.phrase|mnemonic|private.key/i.test(l) },
  ];

  for (const check of checks) {
    for (let i = 0; i < lines.length; i++) {
      if (check.test(lines[i])) {
        findings.push({ id: check.id, sev: check.sev, cat: check.cat, desc: check.desc, line: i + 1 });
        break;
      }
    }
  }

  findings.sort((a, b) => b.sev - a.sev);
  const crits = findings.filter(f => f.sev >= 90).length;
  const score = Math.min(100, crits * 30 + findings.filter(f => f.sev < 90).length * 15);
  const level = crits > 0 ? 'CRITICAL' : score >= 15 ? 'MEDIUM' : 'SAFE';

  return { score, level, findings: findings.slice(0, 3), crits,
    limits: { rules_checked: 5, rules_total: 40, findings_shown: Math.min(findings.length, 3), findings_total: findings.length },
    upgrade: { endpoint: 'POST /v1/scan', price: '$0.015 USDC via x402' }
  };
}
