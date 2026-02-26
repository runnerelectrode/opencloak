import crypto from "node:crypto";
import http from "node:http";
import { URL } from "node:url";
import { getAdapter, DEFAULTS, genId } from "./config.mjs";
import { handleTokenExchange } from "./grants/token-exchange.mjs";
import { DiscordProvider } from "./providers/discord.mjs";
import { GenericOAuthProvider } from "./providers/generic-oauth.mjs";

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

/**
 * Parse URL-encoded body from an http.IncomingMessage.
 */
function parseBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf-8");
        resolve(Object.fromEntries(new URLSearchParams(raw)));
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

/**
 * Send a JSON response.
 */
function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
    "Cache-Control": "no-store",
  });
  res.end(payload);
}

/**
 * Start the vault server.
 */
export async function startServer(options = {}) {
  const port = options.port || DEFAULTS.port;
  const issuer = options.issuer || `http://localhost:${port}`;
  const adapter = getAdapter(options.dataDir);
  const jwksData = await generateJwks(adapter);

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, issuer);
    const path = url.pathname;

    try {
      // --- POST /token — RFC 8693 Token Exchange ---
      if (path === "/token" && req.method === "POST") {
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
      if (path.startsWith("/oauth/callback/") && req.method === "GET") {
        const providerName = path.split("/oauth/callback/")[1];
        if (!providerName) {
          return json(res, 400, { error: "missing provider name" });
        }

        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");
        const error = url.searchParams.get("error");

        if (error) {
          return json(res, 400, {
            error: "provider_denied",
            error_description:
              url.searchParams.get("error_description") || error,
          });
        }

        if (!code || !state) {
          return json(res, 400, {
            error: "missing code or state parameter",
          });
        }

        const session = await adapter.find("sessions", state);
        if (!session) {
          return json(res, 400, {
            error: "invalid or expired state parameter",
          });
        }

        const providerConfig = await adapter.find(
          "providers",
          session.provider_id
        );
        if (!providerConfig) {
          return json(res, 500, { error: "provider config not found" });
        }

        const providerInstance = getProviderInstance(providerConfig);
        const redirectUri = `${issuer}/oauth/callback/${providerName}`;

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
            provider: providerName,
            scopes: tokenData.scope || session.scopes,
          });
        } catch (err) {
          return json(res, 500, {
            error: "token_exchange_failed",
            error_description: err.message,
          });
        }
      }

      // --- GET /health ---
      if (path === "/health" && req.method === "GET") {
        return json(res, 200, { status: "ok", version: "0.1.0" });
      }

      // --- GET /.well-known/openid-configuration ---
      if (
        path === "/.well-known/openid-configuration" &&
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
      if (path === "/jwks" && req.method === "GET") {
        // Return only public keys
        const pubKeys = jwksData.publicKeys || jwksData.keys.map(stripPrivate);
        return json(res, 200, { keys: pubKeys });
      }

      // --- 404 ---
      json(res, 404, { error: "not_found" });
    } catch (err) {
      console.error("Unhandled error:", err);
      json(res, 500, {
        error: "server_error",
        error_description: err.message,
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
  const { d, p, q, dp, dq, qi, ...pub } = jwk;
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
