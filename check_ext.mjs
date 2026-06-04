import { wrapFetchWithPayment } from '@x402/fetch';
import { privateKeyToAccount } from 'viem/accounts';
import { createWalletClient, http } from 'viem';
import { base } from 'viem/chains';
import { x402Client } from '@x402/core/client';
import { registerExactEvmScheme } from '@x402/evm/exact/client';

const PKEY = '0x7214f85ceb9a9bdb30a88ca29eac75698f9a25f7945b20b00bad5ecde2af2381';
const account = privateKeyToAccount(PKEY);
const walletClient = createWalletClient({ account, chain: base, transport: http() });
const client = new x402Client(walletClient);
registerExactEvmScheme(client);
const fetchWithPayment = wrapFetchWithPayment(fetch, client);

const res = await fetchWithPayment('https://agenttrust.uk/v1/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ content: 'test skill content for bazaar' })
});

console.log('Status:', res.status);
for (const [k, v] of res.headers.entries()) {
  if (k.toLowerCase().includes('extension')) {
    console.log('Header:', k);
    try {
      const decoded = JSON.parse(Buffer.from(v, 'base64').toString());
      console.log('Decoded:', JSON.stringify(decoded, null, 2));
    } catch { console.log('Value:', v); }
  }
}
