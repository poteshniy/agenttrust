import { generateJwt } from '@coinbase/cdp-sdk/auth';

export async function settleWithCDP(paymentHeader, paymentRequirements) {
  const apiKeyId = process.env.CDP_KEY_NAME;
  const apiKeySecret = process.env.CDP_PRIVATE_KEY?.replace(/\\n/g, '\n');
  if (!apiKeyId || !apiKeySecret) {
    console.log('  [settle] CDP credentials not configured');
    return null;
  }
  try {
    const token = await generateJwt({
      apiKeyId,
      apiKeySecret,
      requestMethod: 'POST',
      requestHost: 'api.cdp.coinbase.com',
      requestPath: '/platform/v2/x402/settle',
    });

    const payload = JSON.parse(Buffer.from(paymentHeader, 'base64').toString());

    const res = await fetch('https://api.cdp.coinbase.com/platform/v2/x402/settle', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({
        x402Version: 1,
        paymentPayload: payload,
        paymentRequirements,
      }),
    });

    const text = await res.text();
    console.log(`  [settle] CDP ${res.status}:`, text.slice(0, 200));
    try { return JSON.parse(text); } catch { return { status: res.status }; }
  } catch (e) {
    console.error('  [settle] Error:', e.message);
    return null;
  }
}
