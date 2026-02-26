import { createPublicKey, verify } from "node:crypto";

const jwksCache = new Map();

/**
 * Verify a Tailscale tsidp OIDC token.
 *
 * 1. Decode header + payload (no verification yet)
 * 2. Check expiry
 * 3. Fetch OIDC discovery from the issuer
 * 4. Fetch JWKS and cache for 5 minutes
 * 5. Verify signature with the matching key
 *
 * @param {string} token - Raw JWT string from tsidp
 * @returns {{ sub: string, iss: string, aud: string|string[], email?: string }}
 */
export async function verifyOidcToken(token) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new OidcError("malformed JWT: expected 3 parts");
  }

  const [headerB64, payloadB64, sigB64] = parts;
  const header = safeParse(headerB64);
  const payload = safeParse(payloadB64);

  // Validate required claims
  if (!payload.iss) throw new OidcError("missing iss claim");
  if (!payload.sub) throw new OidcError("missing sub claim");

  // Check expiry
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) {
    throw new OidcError("token expired");
  }

  // Check not-before
  if (payload.nbf && payload.nbf > now + 30) {
    throw new OidcError("token not yet valid");
  }

  // Fetch OIDC discovery → JWKS
  const discoveryUrl = `${payload.iss.replace(/\/$/, "")}/.well-known/openid-configuration`;
  const discovery = await fetchJson(discoveryUrl);
  if (!discovery.jwks_uri) {
    throw new OidcError("OIDC discovery missing jwks_uri");
  }

  const jwks = await getJwks(discovery.jwks_uri);

  // Find matching key
  const key =
    jwks.keys.find((k) => k.kid === header.kid) ||
    jwks.keys.find((k) => k.alg === header.alg) ||
    jwks.keys[0];

  if (!key) {
    throw new OidcError("no matching key in JWKS");
  }

  // Build public key and verify signature
  const pubKey = createPublicKey({ key, format: "jwk" });
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`);
  const signature = Buffer.from(sigB64, "base64url");

  // Determine algorithm — tsidp uses RS256 or ES256
  let algorithm;
  if (header.alg === "RS256") {
    algorithm = "SHA256";
  } else if (header.alg === "ES256") {
    algorithm = "SHA256";
  } else if (header.alg === "RS384" || header.alg === "ES384") {
    algorithm = "SHA384";
  } else if (header.alg === "RS512" || header.alg === "ES512") {
    algorithm = "SHA512";
  } else if (header.alg === "EdDSA") {
    algorithm = undefined; // Ed25519 doesn't need explicit hash
  } else {
    throw new OidcError(`unsupported algorithm: ${header.alg}`);
  }

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

// --- Helpers ---

function safeParse(b64url) {
  try {
    return JSON.parse(Buffer.from(b64url, "base64url").toString("utf-8"));
  } catch {
    throw new OidcError("malformed JWT segment");
  }
}

async function fetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) {
    throw new OidcError(
      `failed to fetch ${url}: ${res.status} ${res.statusText}`
    );
  }
  return res.json();
}

async function getJwks(jwksUri) {
  const cached = jwksCache.get(jwksUri);
  if (cached) return cached;

  const jwks = await fetchJson(jwksUri);
  jwksCache.set(jwksUri, jwks);
  setTimeout(() => jwksCache.delete(jwksUri), 5 * 60 * 1000);
  return jwks;
}

export class OidcError extends Error {
  constructor(message) {
    super(message);
    this.name = "OidcError";
  }
}
