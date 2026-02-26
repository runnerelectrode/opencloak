import { createPublicKey, verify } from "node:crypto";

// --- Trusted issuer patterns ---
// Only accept tokens from Tailscale tsidp issuers.
// Override with OPENCLOAK_TRUSTED_ISSUERS env var (comma-separated).
const DEFAULT_ISSUER_PATTERNS = [
  /^https:\/\/login\.tailscale\.com/,
  /^https:\/\/[a-z0-9-]+\.ts\.net/,
  /^https:\/\/[a-z0-9-]+\.tailscale\.ts\.net/,
];

let trustedIssuers = DEFAULT_ISSUER_PATTERNS;

export function setTrustedIssuers(patterns) {
  trustedIssuers = patterns;
}

// --- Algorithm allowlist ---
const ALLOWED_ALGS = new Set(["RS256", "ES256"]);

// --- JWKS cache with bounded size ---
const MAX_CACHE_SIZE = 32;
const CACHE_TTL_MS = 5 * 60 * 1000;
const jwksCache = new Map();

// --- Maximum token age (seconds) ---
const MAX_TOKEN_AGE_SECONDS = 600;

/**
 * Verify a Tailscale tsidp OIDC token.
 *
 * @param {string} token - Raw JWT string from tsidp
 * @param {object} [options] - Verification options
 * @param {string} [options.audience] - Expected audience claim
 * @returns {{ sub: string, iss: string, aud: string|string[], email?: string }}
 */
export async function verifyOidcToken(token, options = {}) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new OidcError("malformed JWT: expected 3 parts");
  }

  const [headerB64, payloadB64, sigB64] = parts;
  const header = safeParse(headerB64);
  const payload = safeParse(payloadB64);

  // --- Validate required claims ---
  if (!payload.iss) throw new OidcError("missing iss claim");
  if (!payload.sub) throw new OidcError("missing sub claim");
  if (!payload.exp) throw new OidcError("missing exp claim");

  // --- Validate algorithm (reject none, HS*, etc.) ---
  if (!header.alg || !ALLOWED_ALGS.has(header.alg)) {
    throw new OidcError(`disallowed algorithm: ${header.alg || "none"}`);
  }

  // --- Validate issuer against allowlist (prevents SSRF + cache poisoning) ---
  const issuerAllowed = trustedIssuers.some((pattern) => {
    if (pattern instanceof RegExp) return pattern.test(payload.iss);
    return payload.iss === pattern || payload.iss.startsWith(pattern + "/");
  });
  if (!issuerAllowed) {
    throw new OidcError(`untrusted issuer: ${payload.iss}`);
  }

  // --- Check expiry (with 30s clock skew tolerance) ---
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now - 30) {
    throw new OidcError("token expired");
  }

  // --- Check not-before (with 30s clock skew tolerance) ---
  if (payload.nbf && payload.nbf > now + 30) {
    throw new OidcError("token not yet valid");
  }

  // --- Check token age ---
  if (payload.iat) {
    if (now - payload.iat > MAX_TOKEN_AGE_SECONDS) {
      throw new OidcError("token too old");
    }
  }

  // --- Validate audience ---
  if (options.audience) {
    const validAud = Array.isArray(payload.aud)
      ? payload.aud.includes(options.audience)
      : payload.aud === options.audience;
    if (!validAud) {
      throw new OidcError(`invalid audience: expected '${options.audience}'`);
    }
  }

  // --- Fetch OIDC discovery → JWKS (issuer already validated) ---
  const discoveryUrl = `${payload.iss.replace(/\/$/, "")}/.well-known/openid-configuration`;
  const discovery = await fetchJson(discoveryUrl);
  if (!discovery.jwks_uri) {
    throw new OidcError("OIDC discovery missing jwks_uri");
  }

  // Validate that jwks_uri is under the same origin as the issuer
  const issuerOrigin = new URL(payload.iss).origin;
  const jwksOrigin = new URL(discovery.jwks_uri).origin;
  if (jwksOrigin !== issuerOrigin) {
    throw new OidcError("jwks_uri origin does not match issuer origin");
  }

  const jwks = await getJwks(discovery.jwks_uri);

  // --- Find matching key (strict: require kid match) ---
  if (!header.kid) {
    throw new OidcError("missing kid in JWT header");
  }
  const key = jwks.keys.find((k) => k.kid === header.kid);
  if (!key) {
    throw new OidcError(`no key found for kid: ${header.kid}`);
  }

  // Verify key algorithm matches header algorithm
  if (key.alg && key.alg !== header.alg) {
    throw new OidcError(`key algorithm mismatch: key=${key.alg}, header=${header.alg}`);
  }

  // --- Build public key and verify signature ---
  const pubKey = createPublicKey({ key, format: "jwk" });
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`);
  const signature = Buffer.from(sigB64, "base64url");

  const algorithm = header.alg === "RS256" || header.alg === "ES256"
    ? "SHA256"
    : undefined;

  const valid = verify(algorithm, signingInput, pubKey, signature);
  if (!valid) {
    throw new OidcError("invalid signature");
  }

  return {
    sub: payload.sub,
    iss: payload.iss,
    aud: payload.aud,
    email: payload.email,
  };
}

/**
 * Flush the JWKS cache (for admin/emergency use).
 */
export function flushJwksCache() {
  jwksCache.clear();
}

// --- Helpers ---

function safeParse(b64url) {
  try {
    return JSON.parse(Buffer.from(b64url, "base64url").toString("utf-8"));
  } catch {
    throw new OidcError("malformed JWT segment");
  }
}

async function fetchJson(url) {
  // Validate URL is HTTPS
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") {
    throw new OidcError(`OIDC endpoints must use HTTPS: ${url}`);
  }

  // Block private/internal IP ranges (SSRF protection)
  if (isPrivateHost(parsed.hostname)) {
    throw new OidcError(`OIDC endpoint resolves to private address: ${parsed.hostname}`);
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) {
      throw new OidcError(`failed to fetch ${url}: ${res.status}`);
    }
    return res.json();
  } finally {
    clearTimeout(timeout);
  }
}

function isPrivateHost(hostname) {
  // Block obvious private ranges — DNS resolution happens at fetch time,
  // but we can catch literal IPs here.
  if (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1") {
    return true;
  }
  // 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 169.254.x.x (link-local/metadata)
  if (/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.)/.test(hostname)) {
    return true;
  }
  // AWS/GCP/Azure metadata endpoints
  if (hostname === "metadata.google.internal") {
    return true;
  }
  return false;
}

async function getJwks(jwksUri) {
  const cached = jwksCache.get(jwksUri);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.data;
  }

  const jwks = await fetchJson(jwksUri);

  // Evict oldest entries if cache is full
  if (jwksCache.size >= MAX_CACHE_SIZE) {
    const oldest = [...jwksCache.entries()].sort(
      (a, b) => a[1].expiresAt - b[1].expiresAt
    )[0];
    if (oldest) jwksCache.delete(oldest[0]);
  }

  jwksCache.set(jwksUri, {
    data: jwks,
    expiresAt: Date.now() + CACHE_TTL_MS,
  });

  return jwks;
}

export class OidcError extends Error {
  constructor(message) {
    super(message);
    this.name = "OidcError";
  }
}
