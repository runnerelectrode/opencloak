import { BaseProvider } from "./base.mjs";

const DISCORD_AUTHORIZE = "https://discord.com/oauth2/authorize";
const DISCORD_TOKEN = "https://discord.com/api/oauth2/token";
const DISCORD_REVOKE = "https://discord.com/api/oauth2/token/revoke";
const DISCORD_RESOURCE = "https://discord.com/api";

export class DiscordProvider extends BaseProvider {
  get id() {
    return "discord";
  }

  getAuthorizeUrl(scopes, state, redirectUri) {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.config.client_id,
      scope: scopes.join(" "),
      state,
      redirect_uri: redirectUri,
      prompt: "consent",
    });
    return `${DISCORD_AUTHORIZE}?${params}`;
  }

  async exchangeCode(code, redirectUri) {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
    });

    const res = await fetch(DISCORD_TOKEN, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: basicAuth(
          this.config.client_id,
          this.config.client_secret
        ),
      },
      body,
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Discord token exchange failed: ${res.status} ${text}`);
    }

    const data = await res.json();

    // Discord returns webhook data in the response when scope includes webhook.incoming
    return {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_in: data.expires_in,
      scope: data.scope,
      token_type: data.token_type,
      webhook: data.webhook || null,
    };
  }

  async refreshToken(refreshToken) {
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    });

    const res = await fetch(DISCORD_TOKEN, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: basicAuth(
          this.config.client_id,
          this.config.client_secret
        ),
      },
      body,
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Discord token refresh failed: ${res.status} ${text}`);
    }

    const data = await res.json();

    return {
      access_token: data.access_token,
      refresh_token: data.refresh_token, // persist defensively even if unchanged
      expires_in: data.expires_in,
      scope: data.scope,
    };
  }

  async revokeToken(token, tokenTypeHint) {
    const body = new URLSearchParams({ token });
    if (tokenTypeHint) body.set("token_type_hint", tokenTypeHint);

    const res = await fetch(DISCORD_REVOKE, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: basicAuth(
          this.config.client_id,
          this.config.client_secret
        ),
      },
      body,
    });

    return res.ok;
  }

  matchesResource(resourceUri) {
    try {
      const targetOrigin = new URL(DISCORD_RESOURCE).origin;
      const requestOrigin = new URL(resourceUri).origin;
      if (targetOrigin !== requestOrigin) return false;
    } catch {
      return false;
    }
    return (
      resourceUri === DISCORD_RESOURCE ||
      resourceUri.startsWith(DISCORD_RESOURCE + "/")
    );
  }
}

function basicAuth(clientId, clientSecret) {
  const encoded = Buffer.from(`${clientId}:${clientSecret}`).toString(
    "base64"
  );
  return `Basic ${encoded}`;
}
