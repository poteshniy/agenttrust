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

    // Enrich paymentPayload per RipperMercs fix (x402#2207)
    // resource must be object {url, description, mimeType}
    if (!payload.resource || typeof payload.resource === 'string') {
      payload.resource = {
        url: paymentRequirements?.resource?.url || paymentRequirements?.url || '',
        description: paymentRequirements?.resource?.description || paymentRequirements?.description || '',
        mimeType: paymentRequirements?.resource?.mimeType || 'application/json',
      };
    }
    // extensions must be echoed from 402 challenge
    if (!payload.extensions && paymentRequirements?.extensions) {
      payload.extensions = paymentRequirements.extensions;
    }

    const res = await fetch('https://api.cdp.coinbase.com/platform/v2/x402/settle', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({
        x402Version: 2,
        paymentPayload: payload,
        paymentRequirements,
      }),
    });

    const text = await res.text();
    let result;
    try { result = JSON.parse(text); } catch { result = { status: res.status }; }

    // Log EXTENSION-RESPONSES
    const extResp = res.headers.get('extension-responses');
    if (extResp) {
      try {
        const decoded = JSON.parse(Buffer.from(extResp, 'base64').toString());
        console.log('  [settle] EXTENSION-RESPONSES:', JSON.stringify(decoded));
      } catch { console.log('  [settle] EXTENSION-RESPONSES raw:', extResp); }
    } else {
      console.log('  [settle] No EXTENSION-RESPONSES header');
    }

    console.log(`  [settle] CDP ${res.status}:`, text.slice(0, 200));
    return result;
  } catch (e) {
    console.error('  [settle] Error:', e.message);
    return null;
  }
}
