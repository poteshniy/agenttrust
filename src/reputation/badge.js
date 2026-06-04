const COLORS = {
  TRUSTED:    { accent: '#2BE8A0', bg_left: '#081a10', bg_right: '#0A0F11', border: '#2BE8A0' },
  UNVERIFIED: { accent: '#FFC24B', bg_left: '#1a140a', bg_right: '#0A0F11', border: '#FFC24B' },
  SUSPICIOUS: { accent: '#FF5C57', bg_left: '#1a0a0a', bg_right: '#0A0F11', border: '#FF5C57' },
};

export function generateBadge(badge, score, url) {
  const c = COLORS[badge] || COLORS.UNVERIFIED;
  const label = badge === 'TRUSTED' ? 'TRUSTED' : badge === 'SUSPICIOUS' ? 'SUSPICIOUS' : 'UNVERIFIED';

  // Two-panel layout: 280×56
  // Left panel (0–124): dot + AGENT TRUST
  // Right panel (125–280): label + score
  return `<svg xmlns="http://www.w3.org/2000/svg" width="280" height="56" viewBox="0 0 280 56">
  <title>AgentTrust: ${badge} (${score}/100)</title>
  <a href="https://agenttrust.uk" target="_blank">
    <!-- outer border -->
    <rect width="280" height="56" rx="5" fill="${c.bg_right}" stroke="${c.border}" stroke-width="1"/>
    <!-- left panel -->
    <rect x="1" y="1" width="123" height="54" rx="4" fill="${c.bg_left}"/>
    <!-- divider -->
    <rect x="124" y="8" width="1" height="40" fill="${c.accent}" opacity="0.35"/>
    <!-- colored dot -->
    <rect x="13" y="24" width="8" height="8" fill="${c.accent}"/>
    <!-- AGENT text -->
    <text x="27" y="33" font-family="monospace" font-size="11" fill="#E9EFEC" font-weight="700" letter-spacing="1">AGENT</text>
    <!-- TRUST text in accent color -->
    <text x="73" y="33" font-family="monospace" font-size="11" fill="${c.accent}" font-weight="700" letter-spacing="1">TRUST</text>
    <!-- label (small caps) -->
    <text x="140" y="22" font-family="monospace" font-size="8.5" fill="${c.accent}" font-weight="700" letter-spacing="2.5">${label}</text>
    <!-- score (large) -->
    <text x="140" y="45" font-family="monospace" font-size="20" fill="${c.accent}" font-weight="800">${score}</text>
    <!-- /100 -->
    <text x="${score >= 100 ? 177 : score >= 10 ? 165 : 153}" y="45" font-family="monospace" font-size="11" fill="#4a5a54">/100</text>
  </a>
</svg>`;
}
