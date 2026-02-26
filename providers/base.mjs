/**
 * Base provider interface.
 * Every provider connector (Discord, GitHub, etc.) must implement these methods.
 */
export class BaseProvider {
  constructor(config) {
    this.config = config;
  }

  /** Return provider ID (e.g., "discord") */
  get id() {
    throw new Error("not implemented");
  }

  /** Return the full authorize URL for the OAuth consent flow. */
  getAuthorizeUrl(scopes, state, redirectUri) {
    throw new Error("not implemented");
  }

  /** Exchange an authorization code for tokens. Returns { access_token, refresh_token, ... } */
  async exchangeCode(code, redirectUri) {
    throw new Error("not implemented");
  }

  /** Refresh an access token using a stored refresh token. Returns { access_token, refresh_token?, expires_in } */
  async refreshToken(refreshToken) {
    throw new Error("not implemented");
  }

  /** Revoke a token at the provider. */
  async revokeToken(token, tokenTypeHint) {
    throw new Error("not implemented");
  }

  /**
   * Map a resource URI to this provider.
   * Returns true if the given resource URI belongs to this provider.
   */
  matchesResource(resourceUri) {
    throw new Error("not implemented");
  }
}
