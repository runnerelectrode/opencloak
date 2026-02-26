import { BaseProvider } from "./base.mjs";

/**
 * Generic OAuth2 provider connector.
 * Works with any standard OAuth2 provider by accepting endpoint URLs in config.
 *
 * Config shape:
 * {
 *   client_id, client_secret,
 *   authorize_url, token_url, revoke_url,
 *   resource_uri   // e.g. "https://api.github.com"
 * }
 */
export class GenericOAuthProvider extends BaseProvider {
  get id() {
    return this.config.provider_id || "generic";
  }

  getAuthorizeUrl(scopes, state, redirectUri) {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.config.client_id,
      scope: scopes.join(" "),
      state,
      redirect_uri: redirectUri,
    });
    return `${this.config.authorize_url}?${params}`;
  }

  async exchangeCode(code, redirectUri) {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: this.config.client_id,
      client_secret: this.config.client_secret,
    });

    const res = await fetch(this.config.token_url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Token exchange failed: ${res.status} ${text}`);
    }

    return res.json();
  }

  async refreshToken(refreshToken) {
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: this.config.client_id,
      client_secret: this.config.client_secret,
    });

    const res = await fetch(this.config.token_url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Token refresh failed: ${res.status} ${text}`);
    }

    return res.json();
  }

  async revokeToken(token, tokenTypeHint) {
    if (!this.config.revoke_url) return false;

    const body = new URLSearchParams({ token });
    if (tokenTypeHint) body.set("token_type_hint", tokenTypeHint);

    const res = await fetch(this.config.revoke_url, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${Buffer.from(`${this.config.client_id}:${this.config.client_secret}`).toString("base64")}`,
      },
      body,
    });

    return res.ok;
  }

  matchesResource(resourceUri) {
    return (
      resourceUri === this.config.resource_uri ||
      resourceUri.startsWith(this.config.resource_uri + "/")
    );
  }
}
