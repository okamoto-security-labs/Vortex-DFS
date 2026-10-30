function backend(env, path) {
  const base = env.VORTEX_BACKEND_BASE_URL;
  if (!base || !/^https:\/\/[a-zA-Z0-9.-]+(?::443)?\/?$/.test(base)) return null;
  return base.replace(/\/$/, "") + path;
}

export async function onRequestPost({ request, env }) {
  const url = backend(env, "/stripe/webhook");
  if (!url) return Response.json({ error: "Webhook backend not configured" }, { status: 503 });
  const signature = request.headers.get("Stripe-Signature");
  if (!signature) return Response.json({ error: "Missing Stripe signature" }, { status: 400 });
  const body = await request.arrayBuffer();
  if (body.byteLength > 65536) return Response.json({ error: "Webhook too large" }, { status: 413 });
  try {
    const upstream = await fetch(url, { method: "POST", redirect: "manual",
      headers: { "Stripe-Signature": signature, "Content-Type": "application/json" }, body });
    return new Response(upstream.body, { status: upstream.status, headers: { "Cache-Control": "no-store" } });
  } catch (_) { return Response.json({ error: "Webhook backend unavailable" }, { status: 502 }); }
}
