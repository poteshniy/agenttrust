const store = new Map();

export function getReputation(address) {
  if (!address?.match(/^0x[0-9a-fA-F]{40}$/)) return { error: "Invalid address" };
  const addr = address.toLowerCase();
  if (!store.has(addr)) {
    const seed = parseInt(addr.slice(2, 10), 16);
    store.set(addr, {
      address: addr,
      score: 50 + (seed % 45),
      incidents: seed % 3,
      audits: 1 + (seed % 5),
      last_seen: new Date(Date.now() - (seed % 30) * 86400000).toISOString(),
      verified: seed % 4 === 0,
    });
  }
  return store.get(addr);
}

export function recordIncident(address, type) {
  const rep = getReputation(address);
  if (rep.error) return rep;
  rep.incidents++;
  rep.score = Math.max(0, rep.score - 20);
  store.set(address.toLowerCase(), rep);
  return rep;
}
