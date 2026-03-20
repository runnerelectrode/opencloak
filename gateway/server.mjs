/**
 * OpenCloak Gateway — standalone HTTP server.
 *
 * Listens on port 3423 (default), validates JWTs, and proxies
 * requests to upstream LLM providers with credential injection.
 */

import http from "node:http";
import { getGatewayAdapter } from "./config.mjs";
import { handleProxyRequest, prefetchJwks } from "./proxy.mjs";

// --- Rate limiter: 60 req/min per IP ---
const RATE_WINDOW_MS = 60 * 1000;
const RATE_LIMIT = 60;
const rateBuckets = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  let bucket = rateBuckets.get(ip);
  if (!bucket || now - bucket.start > RATE_WINDOW_MS) {
    bucket = { start: now, count: 0 };
    rateBuckets.set(ip, bucket);
  }
  bucket.count++;
  return bucket.count <= RATE_LIMIT;
}

// Periodic cleanup of stale rate-limit buckets
setInterval(() => {
  const now = Date.now();
  for (const [ip, bucket] of rateBuckets) {
    if (now - bucket.start > RATE_WINDOW_MS) rateBuckets.delete(ip);
  }
}, RATE_WINDOW_MS).unref();

function json(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(data),
  });
  res.end(data);
}

/**
 * Start the gateway server.
 */
export async function startGateway(config) {
  const { port, jwksUrl, dataDir } = config;
  const adapter = getGatewayAdapter(dataDir);

  // Gateway URL for audience validation (from config or derived)
  const gatewayUrl = config.gatewayUrl;

  // Pre-fetch JWKS on startup
  try {
    await prefetchJwks(jwksUrl);
    console.log(`JWKS loaded from ${jwksUrl}`);
  } catch (err) {
    console.warn(`Warning: JWKS pre-fetch failed (${err.message}). Will retry on first request.`);
  }

  const proxyConfig = { jwksUrl, gatewayUrl };

  const server = http.createServer(async (req, res) => {
    const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress;

    // Rate limiting
    if (!checkRateLimit(ip)) {
      json(res, 429, { error: { type: "gateway_error", message: "rate limit exceeded" } });
      return;
    }

    // Health check
    if (req.url === "/health" && req.method === "GET") {
      json(res, 200, { status: "ok", service: "opencloak-gateway" });
      return;
    }

    // All other requests → proxy
    try {
      await handleProxyRequest(req, res, adapter, proxyConfig);
    } catch (err) {
      console.error("Unhandled gateway error:", err);
      if (!res.headersSent) {
        json(res, 500, { error: { type: "gateway_error", message: "internal error" } });
      }
    }
  });

  server.listen(port, () => {
    console.log(`OpenCloak Gateway listening on http://localhost:${port}`);
    console.log(`  JWKS:     ${jwksUrl}`);
    console.log(`  Data dir: ${dataDir}`);
    console.log(`  Audience: ${gatewayUrl}`);
  });

  return server;
}
