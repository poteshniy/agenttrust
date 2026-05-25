import { wrapFetchWithPayment } from '@x402/fetch';
import { privateKeyToAccount } from 'viem/accounts';
import { x402Client } from '@x402/core/client';
import { registerExactEvmScheme } from '@x402/evm/exact/client';

const PKEY = process.env.PKEY;
if (!PKEY) { console.error('Usage: PKEY=0x... node x402pay_all.js'); process.exit(1); }

const account = privateKeyToAccount(PKEY);
const client = new x402Client();
registerExactEvmScheme(client, { signer: account });
const fetchWithPayment = wrapFetchWithPayment(fetch, client);

console.log('\n  AgentTrust — all endpoints test');
console.log('  Payer:', account.address);

const endpoints = [
  { method: 'POST', url: 'https://agenttrust.uk/v1/scan', body: { content: '# Test Skill\n## Description\nTest.' }, label: 'Full scan ($0.015)' },
  { method: 'GET', url: 'https://agenttrust.uk/v1/trust/0xE08e64d4044Cd7CE4bfbB44D908E358c4EAfde09', body: null, label: 'Trust lookup ($0.010)' },
  { method: 'POST', url: 'https://agenttrust.uk/v1/verify', body: { content: '# Test Skill\n## Description\nTest.' }, label: 'Verify ($0.005)' },
  { method: 'POST', url: 'https://agenttrust.uk/v1/report', body: { content: '# Test Skill\n## Description\nTest.', skill_id: 'test-skill' }, label: 'Report ($0.050)' },
];

for (const ep of endpoints) {
  console.log(`\n  Testing: ${ep.label}`);
  try {
    const opts = { method: ep.method, headers: { 'Content-Type': 'application/json' } };
    if (ep.body) opts.body = JSON.stringify(ep.body);
    const res = await fetchWithPayment(ep.url, opts);
    console.log('  Status:', res.status);
    const data = await res.json().catch(() => ({}));
    console.log('  Result:', JSON.stringify(data).slice(0, 100));
  } catch(e) {
    console.error('  Error:', e.message);
  }
}
console.log('\n  Done!');
