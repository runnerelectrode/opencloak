import { verifyOidcToken, OidcError, setTrustedIssuers, flushJwksCache } from "./oidc.mjs";

const TOKEN_TYPE_ID_TOKEN =
  "urn:ietf:params:oauth:token-type:id_token";

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

    default:
      throw new VerifierError(
        `unsupported actor_token_type: ${tokenType}`
      );
  }
}

export class VerifierError extends Error {
  constructor(message) {
    super(message);
    this.name = "VerifierError";
  }
}

export { OidcError, setTrustedIssuers, flushJwksCache };
