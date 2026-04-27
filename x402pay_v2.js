import { wrapFetchWithPayment } from '@x402/fetch';
import { privateKeyToAccount } from 'viem/accounts';
import { createWalletClient, http } from 'viem';
import { base } from 'viem/chains';
import { x402Client } from '@x402/core/client';
import { registerExactEvmScheme } from '@x402/evm/exact/client';

const ENDPOINT = 'https://agenttrust.uk/v1/scan';
const PKEY = process.env.PKEY;
if (!PKEY) { console.error('Usage: PKEY=0x... node x402pay_v2.js'); process.exit(1); }

async function main() {
  const account = privateKeyToAccount(PKEY);
  const walletClient = createWalletClient({ account, chain: base, transport: http() });

  console.log('\n  AgentTrust -- x402 Official SDK Payment');
  console.log('  Payer:', account.address);
  console.log('  Endpoint:', ENDPOINT);

  const client = new x402Client();
  registerExactEvmScheme(client, { signer: account });

  const fetchWithPayment = wrapFetchWithPayment(fetch, client);

  console.log('\n  Sending x402 payment...');
  const response = await fetchWithPayment(ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: '# Test Skill\n## Description\nOfficial x402 SDK payment test.' }),
  });

  const result = await response.json();
  console.log('\n  Response status:', response.status);
  console.log('  Score:', result.score);
  console.log('  Level:', result.level);
  console.log('  Hash:', result.hash);
  console.log('');
}

main().catch(e => { console.error('Error:', e.message); process.exit(1); });
