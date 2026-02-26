import { verifyOidcToken, OidcError } from "./oidc.mjs";

const TOKEN_TYPE_ID_TOKEN =
  "urn:ietf:params:oauth:token-type:id_token";

/**
 * Verify an actor token based on its declared type.
 *
 * @param {string} token - The raw token string
 * @param {string} tokenType - The token type URI
 * @returns {{ sub: string, iss: string, aud: string|string[], email?: string }}
 */
export async function verifyActorToken(token, tokenType) {
  switch (tokenType) {
    case TOKEN_TYPE_ID_TOKEN:
      return verifyOidcToken(token);

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

export { OidcError };
