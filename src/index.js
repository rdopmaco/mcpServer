/**
 * mcpserver — MCP-style Cloudflare Worker fronting Acumatica.
 *
 * Env vars expected (see wrangler.toml):
 *   ACUMATICA_URL             e.g. "https://yourcompany.acumatica.com"
 *   ACUMATICA_TENANT          your Acumatica tenant/company id
 *   ACUMATICA_CLIENT_ID       (secret) OAuth Client ID from Acumatica
 *   ACUMATICA_CLIENT_SECRET   (secret) OAuth Shared Secret from Acumatica
 *   COOKIE_ENCRYPTION_KEY     (secret) 64-char hex string, 32 random bytes
 *   ADMIN_SECRET              (secret) bearer token for /admin/* routes
 *   KV                        KV namespace binding (see wrangler.toml)
 *
 * Routes:
 *   GET  /authorize   -> redirects the browser to Acumatica's OAuth login
 *   GET  /callback    -> OAuth redirect target; exchanges code for tokens
 *   GET  /            -> simple status page
 *   ALL  /mcp          -> MCP endpoint; requires a valid session cookie
 *   GET  /admin/sessions -> list active sessions (requires ADMIN_SECRET)
 *   POST /admin/revoke   -> revoke one session (requires ADMIN_SECRET)
 */

const SESSION_COOKIE_NAME = "mcp_session";
const SESSION_TTL_SECONDS = 60 * 60 * 8; // 8 hours

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    try {
      if (url.pathname === "/authorize") return handleAuthorize(request, env);
      if (url.pathname === "/callback") return handleCallback(request, env);
      if (url.pathname === "/") return handleStatus(request, env);
      if (url.pathname === "/mcp") return handleMcp(request, env);
      if (url.pathname === "/admin/sessions") return handleAdminSessions(request, env);
      if (url.pathname === "/admin/revoke") return handleAdminRevoke(request, env);

      return new Response("Not found", { status: 404 });
    } catch (err) {
      console.error(err);
      return new Response(
        JSON.stringify({ error: "internal_error", message: String(err) }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      );
    }
  },
};

// ---------------------------------------------------------------------------
// OAuth: kick off login
// ---------------------------------------------------------------------------

function handleAuthorize(request, env) {
  const url = new URL(request.url);
  const redirectUri = `${url.origin}/callback`;
  const state = crypto.randomUUID();

  const authorizeUrl = new URL(`${env.ACUMATICA_URL}/identity/connect/authorize`);
  authorizeUrl.searchParams.set("client_id", env.ACUMATICA_CLIENT_ID);
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("redirect_uri", redirectUri);
  authorizeUrl.searchParams.set("scope", "api offline_access");
  authorizeUrl.searchParams.set("state", state);

  // Stash state briefly so /callback can verify it (5 min TTL)
  const headers = new Headers();
  headers.append(
    "Set-Cookie",
    `oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300`
  );
  headers.set("Location", authorizeUrl.toString());

  return new Response(null, { status: 302, headers });
}

// ---------------------------------------------------------------------------
// OAuth: handle redirect back from Acumatica
// ---------------------------------------------------------------------------

async function handleCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const cookies = parseCookies(request.headers.get("Cookie") || "");

  if (!code) {
    return new Response("Missing authorization code", { status: 400 });
  }
  if (!state || state !== cookies["oauth_state"]) {
    return new Response("Invalid or expired state", { status: 400 });
  }

  const redirectUri = `${url.origin}/callback`;
  const tokenRes = await fetch(`${env.ACUMATICA_URL}/identity/connect/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: env.ACUMATICA_CLIENT_ID,
      client_secret: env.ACUMATICA_CLIENT_SECRET,
    }),
  });

  if (!tokenRes.ok) {
    const detail = await tokenRes.text();
    return new Response(`Token exchange failed: ${detail}`, { status: 502 });
  }

  const tokens = await tokenRes.json(); // { access_token, refresh_token, expires_in, ... }
  const sessionId = crypto.randomUUID();
  const session = {
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expires_at: Date.now() + (tokens.expires_in ?? 3600) * 1000,
    created_at: Date.now(),
  };

  await env.KV.put(`session:${sessionId}`, JSON.stringify(session), {
    expirationTtl: SESSION_TTL_SECONDS,
  });

  const cookieValue = await encryptValue(sessionId, env.COOKIE_ENCRYPTION_KEY);
  const headers = new Headers();
  headers.append(
    "Set-Cookie",
    `${SESSION_COOKIE_NAME}=${cookieValue}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}`
  );
  // Clear the one-time state cookie
  headers.append("Set-Cookie", `oauth_state=; Path=/; Max-Age=0`);
  headers.set("Location", "/");

  return new Response(null, { status: 302, headers });
}

// ---------------------------------------------------------------------------
// Status page
// ---------------------------------------------------------------------------

async function handleStatus(request, env) {
  const session = await getSessionFromRequest(request, env);
  const body = session
    ? { status: "ok", authenticated: true }
    : { status: "ok", authenticated: false, login: "/authorize" };

  return new Response(JSON.stringify(body, null, 2), {
    headers: { "Content-Type": "application/json" },
  });
}

// ---------------------------------------------------------------------------
// MCP endpoint — requires a valid session; proxies to Acumatica's API
// ---------------------------------------------------------------------------

async function handleMcp(request, env) {
  let session = await getSessionFromRequest(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: "unauthorized", login: "/authorize" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Refresh the access token if it's expired or about to expire
  if (session.expires_at < Date.now() + 30_000) {
    session = await refreshSession(session, env);
    if (!session) {
      return new Response(JSON.stringify({ error: "session_expired", login: "/authorize" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  // ---- Replace this with your actual MCP protocol handling ----
  // Example: proxy a simple request to Acumatica's REST endpoint.
  const payload = await request.json().catch(() => ({}));

  return new Response(
    JSON.stringify({
      message: "MCP endpoint reached. Wire up your tool-call handling here.",
      received: payload,
      acumatica_tenant: env.ACUMATICA_TENANT,
    }),
    { headers: { "Content-Type": "application/json" } }
  );
}

async function refreshSession(session, env) {
  if (!session.refresh_token) return null;

  const res = await fetch(`${env.ACUMATICA_URL}/identity/connect/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: session.refresh_token,
      client_id: env.ACUMATICA_CLIENT_ID,
      client_secret: env.ACUMATICA_CLIENT_SECRET,
    }),
  });

  if (!res.ok) return null;
  const tokens = await res.json();

  const updated = {
    ...session,
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token ?? session.refresh_token,
    expires_at: Date.now() + (tokens.expires_in ?? 3600) * 1000,
  };

  if (session._id) {
    await env.KV.put(`session:${session._id}`, JSON.stringify(updated), {
      expirationTtl: SESSION_TTL_SECONDS,
    });
  }

  return updated;
}

// ---------------------------------------------------------------------------
// Admin routes — protected by ADMIN_SECRET bearer token
// ---------------------------------------------------------------------------

function isAdminAuthorized(request, env) {
  const auth = request.headers.get("Authorization") || "";
  return auth === `Bearer ${env.ADMIN_SECRET}`;
}

async function handleAdminSessions(request, env) {
  if (!isAdminAuthorized(request, env)) {
    return new Response("Forbidden", { status: 403 });
  }
  const list = await env.KV.list({ prefix: "session:" });
  return new Response(JSON.stringify(list, null, 2), {
    headers: { "Content-Type": "application/json" },
  });
}

async function handleAdminRevoke(request, env) {
  if (!isAdminAuthorized(request, env)) {
    return new Response("Forbidden", { status: 403 });
  }
  const { sessionId } = await request.json();
  if (!sessionId) {
    return new Response(JSON.stringify({ error: "sessionId required" }), { status: 400 });
  }
  await env.KV.delete(`session:${sessionId}`);
  return new Response(JSON.stringify({ revoked: sessionId }), {
    headers: { "Content-Type": "application/json" },
  });
}

// ---------------------------------------------------------------------------
// Session lookup helper
// ---------------------------------------------------------------------------

async function getSessionFromRequest(request, env) {
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const cookieValue = cookies[SESSION_COOKIE_NAME];
  if (!cookieValue) return null;

  let sessionId;
  try {
    sessionId = await decryptValue(cookieValue, env.COOKIE_ENCRYPTION_KEY);
  } catch {
    return null;
  }

  const raw = await env.KV.get(`session:${sessionId}`);
  if (!raw) return null;

  const session = JSON.parse(raw);
  session._id = sessionId;
  return session;
}

// ---------------------------------------------------------------------------
// Cookie parsing
// ---------------------------------------------------------------------------

function parseCookies(cookieHeader) {
  const cookies = {};
  cookieHeader.split(";").forEach((pair) => {
    const idx = pair.indexOf("=");
    if (idx === -1) return;
    const key = pair.slice(0, idx).trim();
    const value = pair.slice(idx + 1).trim();
    cookies[key] = value;
  });
  return cookies;
}

// ---------------------------------------------------------------------------
// AES-GCM encryption for cookie values, keyed by COOKIE_ENCRYPTION_KEY
// (expects a 64-char hex string = 32 raw bytes, e.g. from `openssl rand -hex 32`)
// ---------------------------------------------------------------------------

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToBase64Url(bytes) {
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "===".slice((b64.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function getAesKey(hexKey) {
  const keyBytes = hexToBytes(hexKey);
  return crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function encryptValue(plainText, hexKey) {
  const key = await getAesKey(hexKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plainText);
  const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
  const cipherBytes = new Uint8Array(cipherBuf);

  const combined = new Uint8Array(iv.length + cipherBytes.length);
  combined.set(iv, 0);
  combined.set(cipherBytes, iv.length);

  return bytesToBase64Url(combined);
}

async function decryptValue(cookieValue, hexKey) {
  const key = await getAesKey(hexKey);
  const combined = base64UrlToBytes(cookieValue);
  const iv = combined.slice(0, 12);
  const cipherBytes = combined.slice(12);

  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipherBytes);
  return new TextDecoder().decode(plainBuf);
}
