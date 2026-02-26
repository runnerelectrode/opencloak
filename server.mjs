import crypto from "node:crypto";
import http from "node:http";
import { URL } from "node:url";
import { getAdapter, DEFAULTS, genId } from "./config.mjs";
import { handleTokenExchange } from "./grants/token-exchange.mjs";
import { DiscordProvider } from "./providers/discord.mjs";
import { GenericOAuthProvider } from "./providers/generic-oauth.mjs";
import { loadTrustedIssuersFromEnv } from "./verifiers/index.mjs";

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
 * Security headers applied to every response.
 */
const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'none'",
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
    ...SECURITY_HEADERS,
  });
  res.end(payload);
}

// Valid provider name: alphanumeric + hyphens only
const VALID_PROVIDER_NAME = /^[a-z0-9-]+$/;

/**
 * Start the vault server.
 */
export async function startServer(options = {}) {
  loadTrustedIssuersFromEnv();
  const port = options.port || DEFAULTS.port;
  const issuer = options.issuer || `http://localhost:${port}`;
  const adapter = getAdapter(options.dataDir);
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

    // Rate limit on token endpoint
    if (req.url?.startsWith("/token") && !checkRateLimit(clientIp)) {
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
          return json(res, 400, {
            error: "provider_denied",
            error_description: "authorization was denied by the provider",
          });
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
          return json(res, 400, {
            error: "invalid_request",
            error_description: "invalid or expired state parameter",
          });
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

          return json(res, 200, {
            message: "Account connected successfully",
            account_id: accountId,
            provider: session.provider_id,
            scopes: tokenData.scope || session.scopes,
          });
        } catch (err) {
          console.error("OAuth callback error:", err);
          return json(res, 500, {
            error: "server_error",
            error_description: "failed to complete OAuth flow",
          });
        }
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
          grant_types_supported: [
            "urn:ietf:params:oauth:grant-type:token-exchange",
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
