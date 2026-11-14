export async function onRequest(context) {
  const { request, env, params } = context;
  const backend = (env.BACKEND_URL || "").replace(/\/$/, "");
  if (!backend) return Response.json({error:"Backend is not connected yet. Set BACKEND_URL in Cloudflare Pages environment variables."},{status:503});
  const part = Array.isArray(params.path) ? params.path.join("/") : (params.path || "");
  const incoming = new URL(request.url);
  const destination = new URL("/api/" + part + incoming.search, backend);
  const headers = new Headers(request.headers);
  headers.delete("host");
  const upstream = new Request(destination.toString(), new Request(request, {headers}));
  return fetch(upstream, {redirect:"manual"});
}