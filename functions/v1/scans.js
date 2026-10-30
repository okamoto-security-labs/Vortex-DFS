function backend(env, path) {
  const base = env.VORTEX_BACKEND_BASE_URL;
  if (!base || !/^https:\/\/[a-zA-Z0-9.-]+(?::443)?\/?$/.test(base)) return null;
  return base.replace(/\/$/, "") + path;
}

export async function onRequestPost({ request, env }) {
  const url = backend(env, "/v1/scans");
  const secret = env.VORTEX_PROXY_SHARED_SECRET;
  const ip = request.headers.get("CF-Connecting-IP");
  if (!url || !secret || secret.length < 24 || !ip) {
    return Response.json({ error: "Scanner backend not configured" }, { status: 503 });
  }
  if ((Number(request.headers.get("Content-Length")) || 0) > 4096) {
    return Response.json({ error: "Request too large" }, { status: 413 });
  }
  const body = await request.text();
  if (body.length > 4096) return Response.json({ error: "Request too large" }, { status: 413 });
  const headers = {
    "Content-Type": "application/json",
    "X-Vortex-Client-IP": ip,
    "X-Vortex-Proxy-Secret": secret
  };
  const authorization = request.headers.get("Authorization");
  if (authorization) headers["Authorization"] = authorization;
  try {
    const upstream = await fetch(url, { method: "POST", headers, body, redirect: "manual" });
    return new Response(upstream.body, {
      status: upstream.status,
      headers: { "Content-Type": upstream.headers.get("Content-Type") || "application/json", "Cache-Control": "no-store" }
    });
  } catch (_) {
    return Response.json({ error: "Scanner backend unavailable" }, { status: 502 });
  }
}
