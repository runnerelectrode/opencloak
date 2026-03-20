/**
 * Gateway proxy logic.
 *
 * - Extracts Bearer token per RFC 6750 (presentation)
 * - Verifies JWT per RFC 9068 using JOSE/JWKS (verification)
 * - Checks path allowlist from provider config
 * - Checks model allowlist from JWT claims
 * - Injects API key and proxies to upstream
 * - Streams SSE responses back
 * - Emits OCSF-aligned audit events
 */

import { createPublicKey, verify } from "node:crypto";
import { emitAuditEvent } from "./audit.mjs";

const MAX_BODY_SIZE = 1 * 1024 * 1024; // 1 MB

// --- JWKS cache ---
const JWKS_CACHE_TTL_MS = 5 * 60 * 1000;
let jwksCache = { keys: [], expiresAt: 0, url: null };

/**
 * Fetch JWKS from the configured URL, with caching.
 * If forceRefresh is true, bypass the cache (for unknown kid retry).
 */
async function fetchJwks(jwksUrl, forceRefresh = false) {
  if (!forceRefresh && jwksCache.url === jwksUrl && jwksCache.expiresAt > Date.now()) {
    return jwksCache.keys;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const res = await fetch(jwksUrl, { signal: controller.signal });
    if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
    const data = await res.json();
    if (!data.keys || !Array.isArray(data.keys)) throw new Error("JWKS missing keys array");

    jwksCache = {
      keys: data.keys,
      expiresAt: Date.now() + JWKS_CACHE_TTL_MS,
      url: jwksUrl,
    };
    return data.keys;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Find a JWK by kid, with one retry on cache miss (handles key rotation).
 */
async function findKey(kid, jwksUrl) {
  let keys = await fetchJwks(jwksUrl);
  let key = keys.find((k) => k.kid === kid);
  if (key) return key;

  // kid not in cache — force refresh once
  keys = await fetchJwks(jwksUrl, true);
  key = keys.find((k) => k.kid === kid);
  return key || null;
}

/**
 * Verify a gateway JWT (RFC 9068).
 *
 * @param {string} token - Raw JWT string
 * @param {string} jwksUrl - URL to fetch JWKS from
 * @param {string} expectedAudience - Expected aud claim (gateway URL)
 * @returns {object} Verified JWT payload
 */
async function verifyGatewayJwt(token, jwksUrl, expectedAudience) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new GatewayError(401, "malformed JWT");

  const [headerB64, payloadB64, sigB64] = parts;
  const header = JSON.parse(Buffer.from(headerB64, "base64url").toString());
  const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());

  // Validate header
  if (header.alg !== "ES256") throw new GatewayError(401, "unsupported algorithm");
  if (header.typ !== "at+jwt") throw new GatewayError(401, "invalid token type");
  if (!header.kid) throw new GatewayError(401, "missing kid");

  // Validate required claims
  if (!payload.iss) throw new GatewayError(401, "missing iss");
  if (!payload.sub) throw new GatewayError(401, "missing sub");
  if (!payload.aud) throw new GatewayError(401, "missing aud");
  if (!payload.exp) throw new GatewayError(401, "missing exp");
  if (!payload.provider_id) throw new GatewayError(401, "missing provider_id");

  // Validate expiry
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now - 30) throw new GatewayError(401, "token expired");

  // Validate audience
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(expectedAudience)) {
    throw new GatewayError(401, "invalid audience");
  }

  // Find key and verify signature
  const key = await findKey(header.kid, jwksUrl);
  if (!key) throw new GatewayError(401, "unknown signing key");

  const pubKey = createPublicKey({ key, format: "jwk" });
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`);
  const signature = Buffer.from(sigB64, "base64url");

  let valid;
  try {
    valid = verify("SHA256", signingInput, { key: pubKey, dsaEncoding: "ieee-p1363" }, signature);
  } catch {
    valid = false;
  }
  if (!valid) {
    // Fallback: DER encoding
    try {
      valid = verify("SHA256", signingInput, pubKey, signature);
    } catch {
      valid = false;
    }
  }
  if (!valid) throw new GatewayError(401, "invalid signature");

  return payload;
}

/**
 * Read the full request body (with size limit).
 */
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_SIZE) {
        reject(new GatewayError(413, "request body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

/**
 * Handle a proxied request.
 *
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 * @param {object} adapter - gateway storage adapter
 * @param {object} config - { jwksUrl, gatewayUrl }
 */
export async function handleProxyRequest(req, res, adapter, config) {
  const startTime = Date.now();
  const auditActor = {};
  const auditResource = {};
  const auditRequest = { method: req.method, path: req.url };
  const auditResponse = { status: 500 };
  let modelAllowed = null;
  let pathAllowed = null;

  try {
    // --- 1. Extract Bearer token (RFC 6750) ---
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      throw new GatewayError(401, "missing or invalid Authorization header");
    }
    const token = authHeader.slice(7);

    // --- 2. Verify JWT (RFC 9068 via JOSE/JWKS) ---
    const claims = await verifyGatewayJwt(token, config.jwksUrl, config.gatewayUrl);
    auditActor.sub = claims.sub;
    auditActor.email = claims.email;
    auditActor.jti = claims.jti;
    auditActor.agent_id = claims.agent_id;
    auditActor.scope = claims.scope;

    // --- 3. Look up provider ---
    const provider = await adapter.find("providers", claims.provider_id);
    if (!provider || provider.type !== "llm") {
      throw new GatewayError(404, `unknown LLM provider: ${claims.provider_id}`);
    }
    auditResource.provider_id = claims.provider_id;

    // --- 4. Check path allowlist ---
    if (provider.allowed_paths && provider.allowed_paths.length > 0) {
      const reqPath = req.url.split("?")[0]; // strip query string
      pathAllowed = provider.allowed_paths.some((p) => reqPath === p || reqPath.startsWith(p + "/"));
      if (!pathAllowed) {
        throw new GatewayError(403, `path '${reqPath}' not allowed for provider '${claims.provider_id}'`);
      }
    } else {
      pathAllowed = true;
    }

    // --- 5. Read request body once ---
    let bodyBuffer = Buffer.alloc(0);
    if (req.method !== "GET" && req.method !== "HEAD") {
      bodyBuffer = await readBody(req);
    }

    // --- 6. Check model allowlist ---
    let requestModel = null;
    if (bodyBuffer.length > 0) {
      try {
        const parsed = JSON.parse(bodyBuffer.toString("utf-8"));
        requestModel = parsed.model || null;
      } catch {
        // Not JSON or no model field — skip model check
      }
    }
    auditRequest.model = requestModel;

    if (claims.allowed_models && claims.allowed_models.length > 0 && requestModel) {
      modelAllowed = claims.allowed_models.includes(requestModel);
      if (!modelAllowed) {
        throw new GatewayError(403, `model '${requestModel}' not allowed`);
      }
    } else {
      modelAllowed = true;
    }

    // --- 7. Build upstream request ---
    const upstreamUrl = provider.upstream_base_url.replace(/\/$/, "") + req.url;
    auditResource.upstream_url = upstreamUrl;

    const upstreamHeaders = {
      "Content-Type": req.headers["content-type"] || "application/json",
      "Accept": req.headers["accept"] || "application/json",
    };

    // Inject API key
    if (provider.auth_scheme) {
      upstreamHeaders[provider.auth_header] = `${provider.auth_scheme} ${provider.api_key}`;
    } else {
      upstreamHeaders[provider.auth_header] = provider.api_key;
    }

    // Add extra headers (e.g. anthropic-version)
    if (provider.extra_headers) {
      for (const [k, v] of Object.entries(provider.extra_headers)) {
        upstreamHeaders[k] = v;
      }
    }

    // Forward content-length if present
    if (bodyBuffer.length > 0) {
      upstreamHeaders["Content-Length"] = String(bodyBuffer.length);
    }

    // --- 8. Proxy to upstream ---
    const upstreamRes = await fetch(upstreamUrl, {
      method: req.method,
      headers: upstreamHeaders,
      body: bodyBuffer.length > 0 ? bodyBuffer : undefined,
    });

    auditResponse.status = upstreamRes.status;

    // --- 9. Stream response back ---
    res.writeHead(upstreamRes.status, {
      "Content-Type": upstreamRes.headers.get("content-type") || "application/json",
    });

    const isSSE = (upstreamRes.headers.get("content-type") || "").includes("text/event-stream");

    if (isSSE && upstreamRes.body) {
      // Stream SSE chunks directly
      const reader = upstreamRes.body.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          res.write(value);
        }
      } catch (err) {
        if (!res.destroyed) res.destroy(err);
      } finally {
        res.end();
      }
    } else {
      // Non-streaming: read full response, extract token usage
      const responseBody = await upstreamRes.arrayBuffer();
      const responseBuf = Buffer.from(responseBody);
      res.end(responseBuf);

      // Try to extract token usage from response
      if (responseBuf.length > 0 && responseBuf.length < MAX_BODY_SIZE) {
        try {
          const parsed = JSON.parse(responseBuf.toString("utf-8"));
          if (parsed.usage) {
            auditResponse.tokens_in = parsed.usage.input_tokens ?? parsed.usage.prompt_tokens ?? null;
            auditResponse.tokens_out = parsed.usage.output_tokens ?? parsed.usage.completion_tokens ?? null;
          }
        } catch {
          // Not JSON — skip
        }
      }
    }
  } catch (err) {
    if (err instanceof GatewayError) {
      auditResponse.status = err.status;
      if (!res.headersSent) {
        res.writeHead(err.status, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: { type: "gateway_error", message: err.message } }));
      }
    } else {
      auditResponse.status = 502;
      console.error("Gateway proxy error:", err.message);
      if (!res.headersSent) {
        res.writeHead(502, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: { type: "gateway_error", message: "upstream request failed" } }));
      }
    }
  } finally {
    emitAuditEvent({
      actor: auditActor,
      resource: auditResource,
      request: auditRequest,
      response: auditResponse,
      startTime,
      modelAllowed,
      pathAllowed,
    });
  }
}

class GatewayError extends Error {
  constructor(status, message) {
    super(message);
    this.name = "GatewayError";
    this.status = status;
  }
}

/**
 * Pre-fetch JWKS on startup.
 */
export async function prefetchJwks(jwksUrl) {
  await fetchJwks(jwksUrl, true);
}
