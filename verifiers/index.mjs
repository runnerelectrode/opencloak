import { verifyOidcToken, OidcError, setTrustedIssuers, addTrustedIssuers, loadTrustedIssuersFromEnv, flushJwksCache, fetchJson } from "./oidc.mjs";

const TOKEN_TYPE_ID_TOKEN =
  "urn:ietf:params:oauth:token-type:id_token";
const TOKEN_TYPE_SANDBOX =
  "urn:opencloak:token-type:sandbox_token";

/**
 * Verify an actor token based on its declared type.
 *
 * @param {string} token - The raw token string
 * @param {string} tokenType - The token type URI
 * @param {object} [options] - Verification options
 * @param {string} [options.audience] - Expected audience claim
 * @returns {{ sub: string, iss: string, aud: string|string[], email?: string }}
 */
export async function verifyActorToken(token, tokenType, options = {}) {
  switch (tokenType) {
    case TOKEN_TYPE_ID_TOKEN:
      return verifyOidcToken(token, options);

    case TOKEN_TYPE_SANDBOX:
      return verifySandboxToken(token);

    default:
      throw new VerifierError(
        `unsupported actor_token_type: ${tokenType}`
      );
  }
}

/**
 * Verify a sandbox token. The token IS the identity string (e.g., "sandbox:<id>").
 * Used in Daytona sandboxes where the sandbox itself is the identity boundary.
 */
function verifySandboxToken(token) {
  if (!token || typeof token !== "string" || token.length > 256) {
    throw new VerifierError("invalid sandbox token");
  }
  return {
    sub: token,
    iss: "opencloak:sandbox",
    aud: "opencloak",
  };
}

export class VerifierError extends Error {
  constructor(message) {
    super(message);
    this.name = "VerifierError";
  }
}

export { OidcError, setTrustedIssuers, addTrustedIssuers, loadTrustedIssuersFromEnv, flushJwksCache, fetchJson };
