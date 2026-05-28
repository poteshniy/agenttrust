const COLORS = {
  TRUSTED: { bg: '#0a1a0a', border: '#4ade80', text: '#4ade80', dot: '#4ade80' },
  UNVERIFIED: { bg: '#1a1a0a', border: '#facc15', text: '#facc15', dot: '#facc15' },
  SUSPICIOUS: { bg: '#1a0a0a', border: '#f87171', text: '#f87171', dot: '#f87171' },
};

export function generateBadge(badge, score, url) {
  const c = COLORS[badge] || COLORS.UNVERIFIED;
  const label = badge === 'TRUSTED' ? '✓ Trusted' : badge === 'SUSPICIOUS' ? '⚠ Suspicious' : '? Unverified';

  return `<svg xmlns="http://www.w3.org/2000/svg" width="260" height="28" viewBox="0 0 260 28">
  <title>AgentTrust: ${badge} (${score}/100)</title>
  <a href="https://agenttrust.uk" target="_blank">
    <rect width="260" height="28" rx="4" fill="${c.bg}" stroke="${c.border}" stroke-width="1"/>
    <circle cx="12" cy="14" r="4" fill="${c.dot}"/>
    <text x="22" y="18" font-family="monospace" font-size="11" fill="${c.text}" font-weight="bold">${label}</text>
    <text x="110" y="18" font-family="monospace" font-size="10" fill="#444444">|</text>
    <text x="120" y="18" font-family="monospace" font-size="11" fill="#cccccc" font-weight="bold">${score}/100</text>
    <text x="170" y="18" font-family="monospace" font-size="10" fill="#444444">|</text>
    <text x="180" y="18" font-family="monospace" font-size="11" fill="${c.text}" font-weight="bold" opacity="0.6">AgentTrust</text>
  </a>
</svg>`;
}
