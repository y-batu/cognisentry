// Reserved for a future secure gateway. This milestone never calls a model.
export const onRequest = async (): Promise<Response> => new Response(
  JSON.stringify({ error: { code: 'gateway_deferred', message: 'Analysis gateway is not enabled.' } }),
  { status: 503, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } },
)
