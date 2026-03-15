import crypto from "node:crypto";
import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { URL, fileURLToPath } from "node:url";
import { getAdapter, DEFAULTS, genId } from "./config.mjs";
import { handleTokenExchange } from "./grants/token-exchange.mjs";
import { DiscordProvider } from "./providers/discord.mjs";
import { GenericOAuthProvider } from "./providers/generic-oauth.mjs";
import { loadTrustedIssuersFromEnv, addTrustedIssuers, fetchJson } from "./verifiers/index.mjs";

// --- Resolve web directory (Node 18 compat — no import.meta.dirname) ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const WEB_DIR = path.join(__dirname, "web");

// --- Provider instance cache ---
const providerInstances = new Map();

export function getProviderInstance(providerConfig) {
  if (providerInstances.has(providerConfig.id)) {
    return providerInstances.get(providerConfig.id);
  }
  let inst;
  if (providerConfig.name === "discord") {
    inst = new DiscordProvider(providerConfig);
  } else {
    inst = new GenericOAuthProvider(providerConfig);
  }
  providerInstances.set(providerConfig.id, inst);
  return inst;
}

/**
 * Generate a JWK keypair (ES256) for the vault's own JWKS endpoint.
 */
async function generateJwks(adapter) {
  const existing = await adapter.find("keys", "as-jwks");
  if (existing && existing.keys) {
    return existing;
  }

  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });

  const privJwk = privateKey.export({ format: "jwk" });
  const pubJwk = publicKey.export({ format: "jwk" });
  const kid = crypto.randomUUID();
  privJwk.kid = kid;
  privJwk.use = "sig";
  privJwk.alg = "ES256";
  pubJwk.kid = kid;
  pubJwk.use = "sig";
  pubJwk.alg = "ES256";

  const data = { keys: [privJwk], publicKeys: [pubJwk] };
  await adapter.upsert("keys", "as-jwks", data);
  return data;
}

// --- Security constants ---
const MAX_BODY_BYTES = 64 * 1024; // 64 KB
const BODY_TIMEOUT_MS = 10000;
const SESSION_MAX_AGE_MS = 10 * 60 * 1000; // 10 minutes
const WEB_SESSION_MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours
const SESSION_CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

// --- Rate limiter (sliding window per IP) ---
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 60; // 60 requests per minute per IP
const rateLimitMap = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  let entry = rateLimitMap.get(ip);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    entry = { windowStart: now, count: 0 };
    rateLimitMap.set(ip, entry);
  }
  entry.count++;
  // Evict stale entries periodically
  if (rateLimitMap.size > 10000) {
    for (const [k, v] of rateLimitMap) {
      if (now - v.windowStart > RATE_LIMIT_WINDOW_MS) rateLimitMap.delete(k);
    }
  }
  return entry.count <= RATE_LIMIT_MAX;
}

/**
 * Parse URL-encoded body with size limit and timeout.
 */
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    const timeout = setTimeout(() => {
      req.destroy();
      reject(new Error("body read timeout"));
    }, BODY_TIMEOUT_MS);

    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        clearTimeout(timeout);
        req.destroy();
        reject(new Error("body too large"));
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      clearTimeout(timeout);
      try {
        const raw = Buffer.concat(chunks).toString("utf-8");
        resolve(Object.fromEntries(new URLSearchParams(raw)));
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", (e) => {
      clearTimeout(timeout);
      reject(e);
    });
  });
}

/**
 * Security headers for API responses.
 */
const API_SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'none'",
  "Referrer-Policy": "no-referrer",
};

/**
 * Security headers for web page responses.
 */
const WEB_SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'",
  "Referrer-Policy": "no-referrer",
};

/**
 * Send a JSON response with security headers.
 */
function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    ...API_SECURITY_HEADERS,
  });
  res.end(payload);
}

/**
 * Send a redirect response.
 */
function redirect(res, location, cookieHeader) {
  const headers = { Location: location, ...API_SECURITY_HEADERS };
  if (cookieHeader) {
    headers["Set-Cookie"] = cookieHeader;
  }
  res.writeHead(302, headers);
  res.end();
}

// Valid provider/issuer name: alphanumeric + hyphens only
const VALID_PROVIDER_NAME = /^[a-z0-9-]+$/;

// Allowed static file extensions
const STATIC_EXTENSIONS = new Map([
  [".html", "text/html; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".js", "application/javascript; charset=utf-8"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".ico", "image/x-icon"],
]);

// --- Cookie helpers ---

function parseCookies(req) {
  const header = req.headers.cookie || "";
  return Object.fromEntries(
    header
      .split(";")
      .map((c) => {
        const [k, ...v] = c.trim().split("=");
        return [k, v.join("=")];
      })
      .filter(([k]) => k)
  );
}

function buildSessionCookie(sessionId, issuerUrl) {
  const isLocal =
    !issuerUrl ||
    issuerUrl.startsWith("http://localhost") ||
    issuerUrl.startsWith("http://127.0.0.1");
  let cookie = `opencloak_session=${sessionId}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400`;
  if (!isLocal) {
    cookie += "; Secure";
  }
  return cookie;
}

function clearSessionCookie() {
  return "opencloak_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0";
}

// --- PKCE helpers ---

function generatePKCE() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");
  return { verifier, challenge };
}

// --- Vault-issued id_token minting ---

function mintIdToken(vaultIssuer, jwksData, claims) {
  const privateJwk = jwksData.keys[0];
  const header = { alg: "ES256", typ: "JWT", kid: privateJwk.kid };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: vaultIssuer,
    sub: claims.sub,
    aud: vaultIssuer,
    email: claims.email,
    iat: now,
    exp: now + 600,
  };

  const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signingInput = `${headerB64}.${payloadB64}`;

  const key = crypto.createPrivateKey({ key: privateJwk, format: "jwk" });
  const signature = crypto.sign("SHA256", Buffer.from(signingInput), key);
  const sigB64 = signature.toString("base64url");

  return `${headerB64}.${payloadB64}.${sigB64}`;
}

// --- Device Authorization Flow helpers ---
const USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ2345679";
const DEVICE_POLL_INTERVAL_MS = 5000;

function generateUserCode() {
  const bytes = crypto.randomBytes(8);
  let code = "";
  for (let i = 0; i < 8; i++) code += USER_CODE_ALPHABET[bytes[i] % USER_CODE_ALPHABET.length];
  return code.slice(0, 4) + "-" + code.slice(4);
}

function normalizeUserCode(input) {
  return input.replace(/[\s\-]/g, "").toUpperCase();
}

function htmlPage(res, status, title, bodyHtml) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} — OpenCloak</title>
  <link rel="stylesheet" href="/web/style.css">
</head>
<body>
  <div class="container">
    <header><h1>OpenCloak</h1></header>
    ${bodyHtml}
  </div>
</body>
</html>`;
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": Buffer.byteLength(html),
    ...WEB_SECURITY_HEADERS,
  });
  res.end(html);
}

// --- Static file serving ---

async function serveStaticFile(res, filePath) {
  const ext = path.extname(filePath);
  const contentType = STATIC_EXTENSIONS.get(ext);
  if (!contentType) {
    json(res, 404, { error: "not_found" });
    return;
  }

  // Path traversal protection: resolved path must be inside WEB_DIR
  const resolved = path.resolve(filePath);
  if (!resolved.startsWith(WEB_DIR + path.sep) && resolved !== WEB_DIR) {
    json(res, 404, { error: "not_found" });
    return;
  }

  try {
    const data = await fs.readFile(resolved);
    res.writeHead(200, {
      "Content-Type": contentType,
      "Content-Length": data.length,
      "Cache-Control": "no-cache",
      ...WEB_SECURITY_HEADERS,
    });
    res.end(data);
  } catch {
    json(res, 404, { error: "not_found" });
  }
}

/**
 * Start the vault server.
 */
export async function startServer(options = {}) {
  loadTrustedIssuersFromEnv();
  const port = options.port || DEFAULTS.port;
  const issuer = options.issuer || `http://localhost:${port}`;
  const adapter = getAdapter(options.dataDir);

  // Load registered issuers from storage
  const storedIssuers = await adapter.findAll("issuers");
  if (storedIssuers.length > 0) {
    addTrustedIssuers(storedIssuers.map((i) => i.issuer_url));
    console.log(`Loaded ${storedIssuers.length} issuer(s) from storage`);
  }

  // Trust the vault's own issuer so vault-minted id_tokens are accepted
  addTrustedIssuers([issuer]);

  const jwksData = await generateJwks(adapter);

  // Periodic session cleanup
  const cleanupInterval = setInterval(async () => {
    try {
      await adapter.cleanExpiredSessions(SESSION_MAX_AGE_MS);
    } catch {
      // non-fatal
    }
  }, SESSION_CLEANUP_INTERVAL_MS);
  cleanupInterval.unref();

  const server = http.createServer(async (req, res) => {
    const clientIp = req.socket.remoteAddress || "unknown";

    // Rate limit on token and auth endpoints
    if (
      (req.url?.startsWith("/token") || req.url?.startsWith("/auth/") || req.url?.startsWith("/device/")) &&
      !checkRateLimit(clientIp)
    ) {
      return json(res, 429, {
        error: "too_many_requests",
        error_description: "rate limit exceeded, try again later",
      });
    }

    const url = new URL(req.url, issuer);
    const pathname = url.pathname;

    try {
      // --- POST /token — RFC 8693 Token Exchange ---
      if (pathname === "/token" && req.method === "POST") {
        const body = await parseBody(req);

        if (
          body.grant_type !==
          "urn:ietf:params:oauth:grant-type:token-exchange"
        ) {
          return json(res, 400, {
            error: "unsupported_grant_type",
            error_description:
              "only urn:ietf:params:oauth:grant-type:token-exchange is supported",
          });
        }

        const result = await handleTokenExchange(body, adapter);
        return json(res, result.status, result.body);
      }

      // --- GET /oauth/callback/:provider ---
      if (pathname.startsWith("/oauth/callback/") && req.method === "GET") {
        const providerName = decodeURIComponent(
          pathname.split("/oauth/callback/")[1] || ""
        );

        // Validate provider name (Finding 13)
        if (
          !providerName ||
          !VALID_PROVIDER_NAME.test(providerName) ||
          providerName.includes("..")
        ) {
          return json(res, 400, {
            error: "invalid_request",
            error_description: "invalid provider name",
          });
        }

        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");
        const callbackError = url.searchParams.get("error");

        if (callbackError) {
          const errorUrl = `/connect?error=provider_denied&error_description=${encodeURIComponent("authorization was denied by the provider")}`;
          res.writeHead(302, { Location: errorUrl });
          res.end();
          return;
        }

        if (!code || !state) {
          return json(res, 400, {
            error: "invalid_request",
            error_description: "missing code or state parameter",
          });
        }

        // Validate state format (hex, 32 chars)
        if (!/^[a-f0-9]{32}$/.test(state)) {
          return json(res, 400, {
            error: "invalid_request",
            error_description: "malformed state parameter",
          });
        }

        const session = await adapter.find("sessions", state);
        if (!session) {
          res.writeHead(302, { Location: "/connect?error=expired_state&error_description=Session+expired.+Please+try+connecting+again." });
          res.end();
          return;
        }

        // Check session expiry (Finding 8)
        const sessionAge = Date.now() - new Date(session.created_at).getTime();
        if (sessionAge > SESSION_MAX_AGE_MS) {
          await adapter.destroy("sessions", state);
          return json(res, 400, {
            error: "invalid_request",
            error_description: "state parameter expired",
          });
        }

        const providerConfig = await adapter.find(
          "providers",
          session.provider_id
        );
        if (!providerConfig) {
          return json(res, 500, {
            error: "server_error",
            error_description: "an internal error occurred",
          });
        }

        const providerInstance = getProviderInstance(providerConfig);
        // Use session's provider_id for redirect URI, not the URL path
        const redirectUri = `${issuer}/oauth/callback/${session.provider_id}`;

        try {
          const tokenData = await providerInstance.exchangeCode(
            code,
            redirectUri
          );

          const accountId = session.account_id || genId();
          const accountData = {
            owner_id: session.owner_id,
            provider_id: providerConfig.id,
            access_token: tokenData.access_token,
            refresh_token: tokenData.refresh_token,
            scopes_granted: tokenData.scope || session.scopes,
            access_token_expires_at: tokenData.expires_in
              ? new Date(
                  Date.now() + tokenData.expires_in * 1000
                ).toISOString()
              : null,
            last_refreshed: new Date().toISOString(),
            created_at: new Date().toISOString(),
          };

          if (tokenData.webhook) {
            accountData.webhook_data = {
              id: tokenData.webhook.id,
              token: tokenData.webhook.token,
              url: tokenData.webhook.url,
              channel_id: tokenData.webhook.channel_id,
              guild_id: tokenData.webhook.guild_id,
            };
          }

          await adapter.upsert("accounts", accountId, accountData);
          await adapter.destroy("sessions", state);

          const basePath = session.return_to === "device" ? "/device/complete" : "/connect";
          const successUrl = `${basePath}?connected=1&provider=${encodeURIComponent(session.provider_id)}&scopes=${encodeURIComponent(tokenData.scope || session.scopes)}`;
          res.writeHead(302, { Location: successUrl });
          res.end();
          return;
        } catch (err) {
          console.error("OAuth callback error:", err);
          const errorUrl = `/connect?error=server_error&error_description=${encodeURIComponent("failed to complete OAuth flow")}`;
          res.writeHead(302, { Location: errorUrl });
          res.end();
          return;
        }
      }

      // --- GET /connect/:provider — Start OAuth connect flow from browser ---
      if (pathname.startsWith("/connect/") && req.method === "GET") {
        const providerName = decodeURIComponent(
          pathname.split("/connect/")[1] || ""
        );
        if (
          !providerName ||
          !VALID_PROVIDER_NAME.test(providerName) ||
          providerName.includes("..")
        ) {
          return json(res, 400, {
            error: "invalid_request",
            error_description: "invalid provider name",
          });
        }

        const providerConfig = await adapter.find("providers", providerName);
        if (!providerConfig) {
          return json(res, 404, {
            error: "not_found",
            error_description: `provider '${providerName}' not configured`,
          });
        }

        // Ensure we have an owner
        const owners = await adapter.findAll("owners");
        const owner = owners[0];
        if (!owner) {
          return json(res, 500, {
            error: "server_error",
            error_description: "no owner configured",
          });
        }

        const scopes = url.searchParams.get("scopes") || "read";
        const state = crypto.randomBytes(16).toString("hex");
        const redirectUri = `${issuer}/oauth/callback/${providerName}`;

        const returnTo = url.searchParams.get("return_to") || "";

        await adapter.upsert("sessions", state, {
          provider_id: providerConfig.id,
          owner_id: owner.id,
          scopes,
          return_to: returnTo,
          created_at: new Date().toISOString(),
        });

        const providerInstance = getProviderInstance(providerConfig);
        const authorizeUrl = providerInstance.getAuthorizeUrl(
          scopes.split(" "),
          state,
          redirectUri
        );

        res.writeHead(302, { Location: authorizeUrl });
        res.end();
        return;
      }

      // --- GET /providers ---
      if (pathname === "/providers" && req.method === "GET") {
        const allProviders = await adapter.findAll("providers");
        const list = allProviders.map((p) => ({ id: p.id, name: p.name || p.id }));
        return json(res, 200, list);
      }

      // --- GET /connect (page) ---
      if (pathname === "/connect" && req.method === "GET") {
        return serveStaticFile(res, path.join(WEB_DIR, "connect.html"));
      }

      // --- GET /health ---
      if (pathname === "/health" && req.method === "GET") {
        return json(res, 200, { status: "ok", version: "0.1.0" });
      }

      // --- GET /.well-known/openid-configuration ---
      if (
        pathname === "/.well-known/openid-configuration" &&
        req.method === "GET"
      ) {
        return json(res, 200, {
          issuer,
          token_endpoint: `${issuer}/token`,
          jwks_uri: `${issuer}/jwks`,
          device_authorization_endpoint: `${issuer}/device/code`,
          grant_types_supported: [
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "urn:ietf:params:oauth:grant-type:device_code",
          ],
          token_endpoint_auth_methods_supported: ["none"],
          response_types_supported: ["token"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["ES256"],
        });
      }

      // --- GET /jwks ---
      if (pathname === "/jwks" && req.method === "GET") {
        // Always derive public keys at runtime — never trust stored publicKeys
        const pubKeys = jwksData.keys.map(stripPrivate);
        return json(res, 200, { keys: pubKeys });
      }

      // --- GET /auth/issuers ---
      if (pathname === "/auth/issuers" && req.method === "GET") {
        const allIssuers = await adapter.findAll("issuers");
        const signinIssuers = allIssuers
          .filter((i) => i.client_id)
          .map((i) => ({ id: i.id, issuer_url: i.issuer_url }));
        return json(res, 200, signinIssuers);
      }

      // --- GET /auth/session ---
      if (pathname === "/auth/session" && req.method === "GET") {
        const cookies = parseCookies(req);
        const sessionId = cookies.opencloak_session;
        if (sessionId) {
          const webSession = await adapter.find("sessions", sessionId);
          if (webSession && webSession.type === "web") {
            const age = Date.now() - new Date(webSession.created_at).getTime();
            if (age <= WEB_SESSION_MAX_AGE_MS) {
              return json(res, 200, {
                authenticated: true,
                issuer_id: webSession.issuer_id,
                id_token: webSession.id_token,
                claims: webSession.claims,
              });
            }
            // Expired
            await adapter.destroy("sessions", sessionId);
          }
        }
        return json(res, 200, { authenticated: false });
      }

      // --- POST /auth/logout ---
      if (pathname === "/auth/logout" && req.method === "POST") {
        const cookies = parseCookies(req);
        const sessionId = cookies.opencloak_session;
        if (sessionId) {
          await adapter.destroy("sessions", sessionId);
        }
        const payload = JSON.stringify({ status: "ok" });
        res.writeHead(200, {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
          "Cache-Control": "no-store",
          "Set-Cookie": clearSessionCookie(),
          ...API_SECURITY_HEADERS,
        });
        res.end(payload);
        return;
      }

      // --- GET /auth/:issuer/callback ---
      const callbackMatch = pathname.match(/^\/auth\/([a-z0-9-]+)\/callback$/);
      if (callbackMatch && req.method === "GET") {
        const issuerId = callbackMatch[1];
        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");
        const callbackError = url.searchParams.get("error");

        if (callbackError) {
          return redirect(res, "/#error");
        }

        if (!code || !state) {
          return json(res, 400, {
            error: "invalid_request",
            error_description: "missing code or state parameter",
          });
        }

        // Validate state format (64 hex chars = 32 bytes)
        if (!/^[a-f0-9]{64}$/.test(state)) {
          return json(res, 400, {
            error: "invalid_request",
            error_description: "malformed state parameter",
          });
        }

        const authSession = await adapter.find("sessions", state);
        if (!authSession || authSession.type !== "auth") {
          return json(res, 400, {
            error: "invalid_request",
            error_description: "invalid or expired state parameter",
          });
        }

        // Check auth session expiry
        const authAge =
          Date.now() - new Date(authSession.created_at).getTime();
        if (authAge > SESSION_MAX_AGE_MS) {
          await adapter.destroy("sessions", state);
          return json(res, 400, {
            error: "invalid_request",
            error_description: "state parameter expired",
          });
        }

        if (authSession.issuer_id !== issuerId) {
          return json(res, 400, {
            error: "invalid_request",
            error_description: "issuer mismatch",
          });
        }

        const issuerConfig = await adapter.find("issuers", issuerId);
        if (!issuerConfig || !issuerConfig.client_id) {
          return json(res, 400, {
            error: "invalid_request",
            error_description: "issuer not configured for sign-in",
          });
        }

        try {
          // Fetch discovery doc
          const discoveryUrl = `${issuerConfig.issuer_url.replace(/\/$/, "")}/.well-known/openid-configuration`;
          const discovery = await fetchJson(discoveryUrl, true);

          if (!discovery.token_endpoint) {
            throw new Error("missing token_endpoint in discovery");
          }

          // Exchange code for tokens
          const tokenBody = new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: `${issuer}/auth/${issuerId}/callback`,
            client_id: issuerConfig.client_id,
            client_secret: issuerConfig.client_secret,
            code_verifier: authSession.code_verifier,
          });

          const tokenRes = await fetch(discovery.token_endpoint, {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: tokenBody,
          });

          if (!tokenRes.ok) {
            const errBody = await tokenRes.text();
            console.error("Token exchange failed:", tokenRes.status, errBody);
            return redirect(res, "/#error");
          }

          const tokenData = await tokenRes.json();
          const idToken = tokenData.id_token;
          if (!idToken) {
            return redirect(res, "/#error");
          }

          // Decode id_token payload (for display; real verification happens at /token endpoint)
          const payloadB64 = idToken.split(".")[1];
          const claims = JSON.parse(
            Buffer.from(payloadB64, "base64url").toString("utf-8")
          );

          // Validate nonce
          if (claims.nonce !== authSession.nonce) {
            await adapter.destroy("sessions", state);
            return json(res, 400, {
              error: "invalid_request",
              error_description: "nonce mismatch",
            });
          }

          // Create web session
          const webSessionId = crypto.randomBytes(32).toString("hex");
          await adapter.upsert("sessions", webSessionId, {
            type: "web",
            issuer_id: issuerId,
            id_token: idToken,
            claims,
            created_at: new Date().toISOString(),
          });

          // Delete auth session
          await adapter.destroy("sessions", state);

          // Set cookie and redirect
          return redirect(
            res,
            "/#signed-in",
            buildSessionCookie(webSessionId, issuer)
          );
        } catch (err) {
          console.error("OIDC callback error:", err);
          return redirect(res, "/#error");
        }
      }

      // --- GET /auth/:issuer — Start OIDC flow ---
      const authMatch = pathname.match(/^\/auth\/([a-z0-9-]+)$/);
      if (authMatch && req.method === "GET") {
        const issuerId = authMatch[1];

        const issuerConfig = await adapter.find("issuers", issuerId);
        if (!issuerConfig || !issuerConfig.client_id) {
          return json(res, 404, {
            error: "not_found",
            error_description: "issuer not found or not configured for sign-in",
          });
        }

        try {
          // Fetch OIDC discovery doc
          const discoveryUrl = `${issuerConfig.issuer_url.replace(/\/$/, "")}/.well-known/openid-configuration`;
          const discovery = await fetchJson(discoveryUrl, true);

          if (!discovery.authorization_endpoint) {
            throw new Error("missing authorization_endpoint in discovery");
          }

          // Generate state, nonce, PKCE
          const state = crypto.randomBytes(32).toString("hex");
          const nonce = crypto.randomBytes(16).toString("hex");
          const pkce = generatePKCE();

          // Store auth session
          await adapter.upsert("sessions", state, {
            type: "auth",
            issuer_id: issuerId,
            nonce,
            code_verifier: pkce.verifier,
            created_at: new Date().toISOString(),
          });

          // Build authorization URL
          const authUrl = new URL(discovery.authorization_endpoint);
          authUrl.searchParams.set("response_type", "code");
          authUrl.searchParams.set("client_id", issuerConfig.client_id);
          authUrl.searchParams.set(
            "redirect_uri",
            `${issuer}/auth/${issuerId}/callback`
          );
          authUrl.searchParams.set("scope", "openid email profile");
          authUrl.searchParams.set("state", state);
          authUrl.searchParams.set("nonce", nonce);
          authUrl.searchParams.set("code_challenge", pkce.challenge);
          authUrl.searchParams.set("code_challenge_method", "S256");

          return redirect(res, authUrl.toString());
        } catch (err) {
          console.error("OIDC start error:", err);
          return json(res, 500, {
            error: "server_error",
            error_description: "an internal error occurred",
          });
        }
      }

      // --- Device Authorization Flow (RFC 8628) ---

      // POST /device/code — Agent starts device flow
      if (pathname === "/device/code" && req.method === "POST") {
        const body = await parseBody(req).catch(() => ({}));
        const issuerId = body.issuer_id || null;

        // If issuer_id specified, verify it exists
        if (issuerId) {
          const issuerConfig = await adapter.find("issuers", issuerId);
          if (!issuerConfig || !issuerConfig.client_id) {
            return json(res, 400, {
              error: "invalid_request",
              error_description: "unknown or unconfigured issuer",
            });
          }
        }

        const deviceCode = crypto.randomBytes(32).toString("hex");

        // Generate unique user code
        let userCode;
        for (let attempts = 0; attempts < 10; attempts++) {
          userCode = generateUserCode();
          const normalized = normalizeUserCode(userCode);
          // Check uniqueness among active device sessions
          const allSessions = await adapter.findAll("sessions");
          const conflict = allSessions.some(
            (s) => s.type === "device" && s.status === "pending" && normalizeUserCode(s.user_code) === normalized
          );
          if (!conflict) break;
          if (attempts === 9) {
            return json(res, 503, {
              error: "server_error",
              error_description: "could not generate unique user code, try again",
            });
          }
        }

        await adapter.upsert("sessions", deviceCode, {
          type: "device",
          user_code: userCode,
          status: "pending",
          issuer_id: issuerId,
          id_token: null,
          claims: null,
          last_poll: null,
          created_at: new Date().toISOString(),
        });

        const verificationUri = `${issuer}/device/verify`;
        return json(res, 200, {
          device_code: deviceCode,
          user_code: userCode,
          verification_uri: verificationUri,
          verification_uri_complete: `${verificationUri}?code=${encodeURIComponent(userCode)}`,
          expires_in: 600,
          interval: 5,
        });
      }

      // GET /device/verify — Serves code entry page
      if (pathname === "/device/verify" && req.method === "GET") {
        return serveStaticFile(res, path.join(WEB_DIR, "device.html"));
      }

      // POST /device/verify — Human submits code
      if (pathname === "/device/verify" && req.method === "POST") {
        const body = await parseBody(req);
        const rawCode = body.user_code;
        if (!rawCode) {
          return htmlPage(res, 400, "Error", `<div class="card"><h2>Missing Code</h2><p>Please enter a device code.</p><div class="actions"><a href="/device/verify" class="btn btn-primary">Try Again</a></div></div>`);
        }

        const normalized = normalizeUserCode(rawCode);
        if (normalized.length !== 8) {
          return htmlPage(res, 400, "Error", `<div class="card"><h2>Invalid Code</h2><p>The code should be 8 characters (XXXX-XXXX).</p><div class="actions"><a href="/device/verify" class="btn btn-primary">Try Again</a></div></div>`);
        }

        // Find matching pending device session
        const allSessions = await adapter.findAll("sessions");
        const deviceSession = allSessions.find(
          (s) => s.type === "device" && s.status === "pending" && normalizeUserCode(s.user_code) === normalized
        );

        if (!deviceSession) {
          return htmlPage(res, 400, "Error", `<div class="card"><h2>Code Not Found</h2><p>No pending authorization matches that code. It may have expired.</p><div class="actions"><a href="/device/verify" class="btn btn-primary">Try Again</a></div></div>`);
        }

        // Check device session expiry
        const deviceAge = Date.now() - new Date(deviceSession.created_at).getTime();
        if (deviceAge > SESSION_MAX_AGE_MS) {
          return htmlPage(res, 400, "Error", `<div class="card"><h2>Code Expired</h2><p>This code has expired. Please request a new one from your agent.</p></div>`);
        }

        // Check for existing web session — auto-approve if human already signed in
        const cookies = parseCookies(req);
        const webSessionId = cookies.opencloak_session;
        if (webSessionId) {
          const webSession = await adapter.find("sessions", webSessionId);
          if (webSession && webSession.type === "web") {
            const webAge = Date.now() - new Date(webSession.created_at).getTime();
            if (webAge <= WEB_SESSION_MAX_AGE_MS && webSession.claims && webSession.claims.sub) {
              // Human already authenticated — mint a vault id_token and auto-approve
              const vaultIdToken = mintIdToken(issuer, jwksData, webSession.claims);
              const vaultClaims = JSON.parse(
                Buffer.from(vaultIdToken.split(".")[1], "base64url").toString("utf-8")
              );
              await adapter.upsert("sessions", deviceSession.id, {
                ...deviceSession,
                status: "authorized",
                id_token: vaultIdToken,
                claims: vaultClaims,
              });
              console.log(`Device code auto-approved for ${webSession.claims.email || webSession.claims.sub}`);
              return redirect(res, "/device/complete");
            }
          }
        }

        // Determine issuer — if pre-selected or only one available
        let targetIssuerId = deviceSession.issuer_id || body.issuer_id;
        if (!targetIssuerId) {
          const allIssuers = await adapter.findAll("issuers");
          const signinIssuers = allIssuers.filter((i) => i.client_id);
          if (signinIssuers.length === 0) {
            return htmlPage(res, 500, "Error", `<div class="card"><h2>No Issuers</h2><p>No sign-in providers are configured.</p></div>`);
          }
          if (signinIssuers.length === 1) {
            targetIssuerId = signinIssuers[0].id;
          } else {
            // Render issuer selection
            const buttons = signinIssuers.map(
              (i) => `<form method="POST" action="/device/verify" style="margin:0"><input type="hidden" name="user_code" value="${rawCode}"><input type="hidden" name="issuer_id" value="${i.id}"><button type="submit" class="signin-btn">${i.id}</button></form>`
            ).join("");
            return htmlPage(res, 200, "Choose Provider", `<div class="card"><h2>Choose Sign-In Provider</h2><p>Code: <strong>${deviceSession.user_code}</strong></p><div class="signin-buttons">${buttons}</div></div>`);
          }
        }

        const issuerConfig = await adapter.find("issuers", targetIssuerId);
        if (!issuerConfig || !issuerConfig.client_id) {
          return htmlPage(res, 400, "Error", `<div class="card"><h2>Invalid Provider</h2><p>The selected sign-in provider is not configured.</p></div>`);
        }

        try {
          const discoveryUrl = `${issuerConfig.issuer_url.replace(/\/$/, "")}/.well-known/openid-configuration`;
          const discovery = await fetchJson(discoveryUrl, true);
          if (!discovery.authorization_endpoint) {
            throw new Error("missing authorization_endpoint in discovery");
          }

          const state = crypto.randomBytes(32).toString("hex");
          const nonce = crypto.randomBytes(16).toString("hex");
          const pkce = generatePKCE();

          // Store auth session linked to device session
          await adapter.upsert("sessions", state, {
            type: "auth",
            issuer_id: targetIssuerId,
            nonce,
            code_verifier: pkce.verifier,
            device_session_id: deviceSession.id,
            created_at: new Date().toISOString(),
          });

          const authUrl = new URL(discovery.authorization_endpoint);
          authUrl.searchParams.set("response_type", "code");
          authUrl.searchParams.set("client_id", issuerConfig.client_id);
          authUrl.searchParams.set("redirect_uri", `${issuer}/device/callback/${targetIssuerId}`);
          authUrl.searchParams.set("scope", "openid email profile");
          authUrl.searchParams.set("state", state);
          authUrl.searchParams.set("nonce", nonce);
          authUrl.searchParams.set("code_challenge", pkce.challenge);
          authUrl.searchParams.set("code_challenge_method", "S256");

          return redirect(res, authUrl.toString());
        } catch (err) {
          console.error("Device verify OIDC error:", err);
          return htmlPage(res, 500, "Error", `<div class="card"><h2>Error</h2><p>Failed to start sign-in. Please try again.</p></div>`);
        }
      }

      // GET /device/callback/:issuer — OIDC callback for device flow
      const deviceCallbackMatch = pathname.match(/^\/device\/callback\/([a-z0-9-]+)$/);
      if (deviceCallbackMatch && req.method === "GET") {
        const issuerId = deviceCallbackMatch[1];
        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");
        const callbackError = url.searchParams.get("error");

        if (callbackError) {
          return htmlPage(res, 400, "Error", `<div class="card"><h2>Authorization Denied</h2><p>The sign-in provider denied the request.</p></div>`);
        }

        if (!code || !state) {
          return htmlPage(res, 400, "Error", `<div class="card"><h2>Invalid Request</h2><p>Missing code or state parameter.</p></div>`);
        }

        if (!/^[a-f0-9]{64}$/.test(state)) {
          return htmlPage(res, 400, "Error", `<div class="card"><h2>Invalid Request</h2><p>Malformed state parameter.</p></div>`);
        }

        const authSession = await adapter.find("sessions", state);
        if (!authSession || authSession.type !== "auth" || !authSession.device_session_id) {
          return htmlPage(res, 400, "Error", `<div class="card"><h2>Invalid Request</h2><p>Invalid or expired session.</p></div>`);
        }

        const authAge = Date.now() - new Date(authSession.created_at).getTime();
        if (authAge > SESSION_MAX_AGE_MS) {
          await adapter.destroy("sessions", state);
          return htmlPage(res, 400, "Error", `<div class="card"><h2>Session Expired</h2><p>The authorization session has expired. Please try again.</p></div>`);
        }

        if (authSession.issuer_id !== issuerId) {
          return htmlPage(res, 400, "Error", `<div class="card"><h2>Issuer Mismatch</h2><p>Unexpected provider callback.</p></div>`);
        }

        const issuerConfig = await adapter.find("issuers", issuerId);
        if (!issuerConfig || !issuerConfig.client_id) {
          return htmlPage(res, 500, "Error", `<div class="card"><h2>Configuration Error</h2><p>Issuer not configured for sign-in.</p></div>`);
        }

        try {
          const discoveryUrl = `${issuerConfig.issuer_url.replace(/\/$/, "")}/.well-known/openid-configuration`;
          const discovery = await fetchJson(discoveryUrl, true);
          if (!discovery.token_endpoint) {
            throw new Error("missing token_endpoint in discovery");
          }

          const tokenBody = new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: `${issuer}/device/callback/${issuerId}`,
            client_id: issuerConfig.client_id,
            client_secret: issuerConfig.client_secret,
            code_verifier: authSession.code_verifier,
          });

          const tokenRes = await fetch(discovery.token_endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: tokenBody,
          });

          if (!tokenRes.ok) {
            const errBody = await tokenRes.text();
            console.error("Device callback token exchange failed:", tokenRes.status, errBody);
            return htmlPage(res, 500, "Error", `<div class="card"><h2>Sign-In Failed</h2><p>Could not complete the sign-in. Please try again.</p></div>`);
          }

          const tokenData = await tokenRes.json();
          const idToken = tokenData.id_token;
          if (!idToken) {
            return htmlPage(res, 500, "Error", `<div class="card"><h2>Sign-In Failed</h2><p>No ID token received from provider.</p></div>`);
          }

          // Decode and validate nonce
          const payloadB64 = idToken.split(".")[1];
          const claims = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf-8"));

          if (claims.nonce !== authSession.nonce) {
            await adapter.destroy("sessions", state);
            return htmlPage(res, 400, "Error", `<div class="card"><h2>Security Error</h2><p>Nonce mismatch. Please try again.</p></div>`);
          }

          // Update device session to authorized
          const deviceSession = await adapter.find("sessions", authSession.device_session_id);
          if (deviceSession && deviceSession.type === "device") {
            await adapter.upsert("sessions", authSession.device_session_id, {
              ...deviceSession,
              status: "authorized",
              id_token: idToken,
              claims,
            });
          }

          // Delete auth session
          await adapter.destroy("sessions", state);

          // Create web session so subsequent device flows auto-approve
          const deviceWebSessionId = crypto.randomBytes(32).toString("hex");
          await adapter.upsert("sessions", deviceWebSessionId, {
            type: "web",
            issuer_id: issuerId,
            id_token: idToken,
            claims,
            created_at: new Date().toISOString(),
          });

          return redirect(res, "/device/complete", buildSessionCookie(deviceWebSessionId, issuer));
        } catch (err) {
          console.error("Device callback error:", err);
          return htmlPage(res, 500, "Error", `<div class="card"><h2>Error</h2><p>An unexpected error occurred.</p></div>`);
        }
      }

      // GET /device/complete — Success page
      if (pathname === "/device/complete" && req.method === "GET") {
        return serveStaticFile(res, path.join(WEB_DIR, "device-complete.html"));
      }

      // GET /device/token — Agent polls for result
      if (pathname === "/device/token" && req.method === "GET") {
        const deviceCode = url.searchParams.get("device_code");
        if (!deviceCode || !/^[a-f0-9]{64}$/.test(deviceCode)) {
          return json(res, 400, { error: "invalid_request", error_description: "missing or malformed device_code" });
        }

        const deviceSession = await adapter.find("sessions", deviceCode);
        if (!deviceSession || deviceSession.type !== "device") {
          return json(res, 400, { error: "expired_token", error_description: "device code not found or expired" });
        }

        // Check expiry
        const deviceAge = Date.now() - new Date(deviceSession.created_at).getTime();
        if (deviceAge > SESSION_MAX_AGE_MS) {
          await adapter.destroy("sessions", deviceCode);
          return json(res, 400, { error: "expired_token", error_description: "device code expired" });
        }

        // Enforce polling interval
        const now = Date.now();
        if (deviceSession.last_poll && now - new Date(deviceSession.last_poll).getTime() < DEVICE_POLL_INTERVAL_MS) {
          return json(res, 400, { error: "slow_down", error_description: "polling too frequently" });
        }

        // Update last_poll
        await adapter.upsert("sessions", deviceCode, {
          ...deviceSession,
          last_poll: new Date().toISOString(),
        });

        if (deviceSession.status === "pending") {
          return json(res, 400, { error: "authorization_pending", error_description: "waiting for user authorization" });
        }

        if (deviceSession.status === "authorized" && deviceSession.id_token) {
          const result = { id_token: deviceSession.id_token, claims: deviceSession.claims };
          // One-time retrieval — destroy session
          await adapter.destroy("sessions", deviceCode);
          return json(res, 200, result);
        }

        return json(res, 400, { error: "authorization_pending", error_description: "waiting for user authorization" });
      }

      // --- Static file serving ---
      if (req.method === "GET") {
        if (pathname === "/") {
          return serveStaticFile(res, path.join(WEB_DIR, "index.html"));
        }
        if (pathname.startsWith("/web/")) {
          const relPath = pathname.slice(5); // strip "/web/"
          // Prevent empty path or directory traversal
          if (
            !relPath ||
            relPath.includes("..") ||
            relPath.includes("\0")
          ) {
            return json(res, 404, { error: "not_found" });
          }
          return serveStaticFile(
            res,
            path.join(WEB_DIR, relPath)
          );
        }
      }

      // --- 404 ---
      json(res, 404, { error: "not_found" });
    } catch (err) {
      console.error("Unhandled error:", err);
      // Never leak internal error details to clients (Finding 10)
      json(res, 500, {
        error: "server_error",
        error_description: "an internal error occurred",
      });
    }
  });

  server.listen(port, () => {
    console.log(`OpenCloak vault listening on ${issuer}`);
    console.log(`  Token exchange: POST ${issuer}/token`);
    console.log(`  Health check:   GET  ${issuer}/health`);
    console.log(`  Device auth:    POST ${issuer}/device/code`);
    console.log(`  Demo UI:        GET  ${issuer}/`);
  });

  return { server, adapter };
}

/**
 * Strip private key fields from a JWK (return public-only).
 */
function stripPrivate(jwk) {
  const { d, p, q, dp, dq, qi, k, ...pub } = jwk;
  return pub;
}

// --- Run directly ---
if (
  process.argv[1] &&
  (process.argv[1].endsWith("server.mjs") ||
    process.argv[1].endsWith("server"))
) {
  startServer({
    port: parseInt(process.env.PORT || DEFAULTS.port, 10),
    dataDir: process.env.OPENCLOAK_DATA_DIR || undefined,
    issuer: process.env.OPENCLOAK_ISSUER || undefined,
  });
}
