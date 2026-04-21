import { ethers } from 'ethers';

// Config
const RECIPIENT = '0xE08e64d4044Cd7CE4bfbB44D908E358c4EAfde09';
const USDC_BASE  = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const RPC        = 'https://mainnet.base.org';
const ENDPOINT   = 'http://62.238.11.249:3402/v1/scan';
const AMOUNT     = 0.015; // USDC

const USDC_ABI = [
  'function transfer(address to, uint256 amount) returns (bool)',
  'function balanceOf(address) view returns (uint256)',
  'function decimals() view returns (uint8)',
];

const PKEY = process.env.PKEY;
if (!PKEY) { console.error('Usage: PKEY=0x... node x402pay.js'); process.exit(1); }

async function main() {
  const provider = new ethers.JsonRpcProvider(RPC);
  const wallet   = new ethers.Wallet(PKEY, provider);
  const usdc     = new ethers.Contract(USDC_BASE, USDC_ABI, wallet);

  console.log('\n  AgentTrust -- x402 Payment Test');
  console.log('  Payer:    ', wallet.address);
  console.log('  Recipient:', RECIPIENT);
  console.log('  Amount:    0.015 USDC\n');

  // Check balance
  const bal = await usdc.balanceOf(wallet.address);
  const dec = await usdc.decimals();
  const balFloat = Number(bal) / 10**Number(dec);
  console.log(`  USDC balance: ${balFloat}`);

  if (balFloat < AMOUNT) {
    console.error(`  Not enough USDC. Need ${AMOUNT}, have ${balFloat}`);
    process.exit(1);
  }

  // Step 1: send USDC
  console.log('  Step 1/3 -- Sending USDC...');
  const amountWei = BigInt(Math.round(AMOUNT * 10**Number(dec)));
  const tx = await usdc.transfer(RECIPIENT, amountWei);
  console.log(`  tx hash: ${tx.hash}`);
  console.log('  Step 2/3 -- Waiting for confirmation...');
  await tx.wait();
  console.log('  Confirmed!');

  // Step 2: call API with payment proof
  console.log('  Step 3/3 -- Calling AgentTrust API...');
  const res = await fetch(ENDPOINT, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Payment': tx.hash,
    },
    body: JSON.stringify({ content: `# Test Skill\n## Description\nFirst x402 payment to AgentTrust.\n## Instructions\nHello world.` }),
  });

  const data = await res.json();
  console.log('\n  API Response:');
  console.log(`  Score:    ${data.score}/100`);
  console.log(`  Level:    ${data.level}`);
  console.log(`  Findings: ${data.findings?.length || 0}`);
  console.log(`  Charged:  ${data.charged} ${data.currency}`);
  console.log(`\n  Basescan: https://basescan.org/tx/${tx.hash}\n`);
}

main().catch(e => { console.error(e.message); process.exit(1); });
