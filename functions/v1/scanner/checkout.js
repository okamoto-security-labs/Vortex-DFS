function backend(env, path) {
  const base = env.VORTEX_BACKEND_BASE_URL;
  if (!base || !/^https:\/\/[a-zA-Z0-9.-]+(?::443)?\/?$/.test(base)) return null;
  return base.replace(/\/$/, "") + path;
}

export async function onRequestGet({ env }) {
  const url = backend(env, "/v1/scanner/checkout");
  if (!url) return Response.json({ error: "Checkout backend not configured" }, { status: 503 });
  try {
    const upstream = await fetch(url, { redirect: "manual" });
    const location = upstream.headers.get("Location");
    if (upstream.status === 302 && location &&
      (location.startsWith("https://buy.stripe.com/") || location.startsWith("https://checkout.stripe.com/"))) {
      return Response.redirect(location, 302);
    }
    return new Response(upstream.body, {
      status: upstream.status,
      headers: { "Content-Type": upstream.headers.get("Content-Type") || "application/json", "Cache-Control": "no-store" }
    });
  } catch (_) { return Response.json({ error: "Checkout backend unavailable" }, { status: 502 }); }
}
