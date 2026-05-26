// Monkey-patch globalThis.fetch to intercept CDP settle calls
// and enrich paymentPayload per RipperMercs fix (x402#2207)
const origFetch = globalThis.fetch;
globalThis.fetch = async function patchedFetch(input, init) {
  const url = typeof input === 'string' ? input : input?.url || '';

  // Intercept CDP settle calls
  if (url.includes('api.cdp.coinbase.com/platform/v2/x402/settle') && init?.body) {
    try {
      const body = JSON.parse(init.body);
      const payload = body.paymentPayload;
      const requirements = body.paymentRequirements;

      // Enrich resource
      if (payload && (!payload.resource || typeof payload.resource === 'string')) {
        payload.resource = {
          url: requirements?.resource?.url || requirements?.url || '',
          description: requirements?.resource?.description || requirements?.description || '',
          mimeType: requirements?.resource?.mimeType || 'application/json',
        };
        console.log('[cdp-tap] enriched resource:', payload.resource.url);
      }

      // Enrich extensions
      if (payload && !payload.extensions && requirements?.extensions) {
        payload.extensions = requirements.extensions;
        console.log('[cdp-tap] enriched extensions: bazaar present');
      }

      // Force x402Version 2
      body.x402Version = 2;

      init = { ...init, body: JSON.stringify(body) };
    } catch(e) {
      console.error('[cdp-tap] parse error:', e.message);
    }
  }

  const response = await origFetch(input, init);

  // Log EXTENSION-RESPONSES
  if (url.includes('api.cdp.coinbase.com/platform/v2/x402')) {
    const extResp = response.headers.get('extension-responses');
    if (extResp) {
      try {
        const decoded = JSON.parse(Buffer.from(extResp, 'base64').toString());
        console.log('[cdp-tap] EXTENSION-RESPONSES:', JSON.stringify(decoded));
      } catch { console.log('[cdp-tap] EXTENSION-RESPONSES raw:', extResp); }
    }
  }

  return response;
};

console.log('[cdp-tap] installed');
