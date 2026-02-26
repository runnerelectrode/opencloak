# OpenCloak

Open-source OAuth vault for AI agents. RFC 8693 token exchange via Tailscale identity.

Agents on your tailnet prove who they are with a Tailscale tsidp OIDC token. OpenCloak checks policy and returns a scoped, short-lived access token for third-party APIs (Discord, GitHub, Google, Slack). Agents never see or store long-lived credentials.

**Zero external dependencies.** Pure Node.js 18+.

## Prerequisites

- **Node.js 18+** installed
- **Tailscale** installed with your node joined to a tailnet
- **tsidp enabled** on your tailnet (for OIDC token issuance)
- A **Discord Developer Application** (or other OAuth provider) with client ID and secret

## Step-by-Step Setup

### Step 1: Clone and install

```bash
git clone https://github.com/<your-user>/opencloak.git
cd opencloak
npm install
```

### Step 2: Start the vault server

```bash
node cli.mjs start --port 3422
```

The vault starts on `http://localhost:3422`. You'll see:

```
OpenCloak vault listening on http://localhost:3422
  Token exchange: POST http://localhost:3422/token
  Health check:   GET  http://localhost:3422/health
```

### Step 3: Register an OAuth provider

Create a Discord application at https://discord.com/developers/applications, then:

```bash
node cli.mjs add-provider discord \
  --client-id <YOUR_DISCORD_CLIENT_ID> \
  --client-secret <YOUR_DISCORD_CLIENT_SECRET>
```

Set the redirect URI in your Discord app settings to:
- Local dev: `http://localhost:3422/oauth/callback/discord`
- Tailnet: `https://<your-node>.<tailnet>.ts.net/oauth/callback/discord`

### Step 4: Register an agent

Register an agent by its Tailscale identity (the `sub` claim from tsidp — either a user email or a device tag):

```bash
node cli.mjs register-agent --ts-identity user@example.com
```

### Step 5: Set agent permissions

Define what scopes the agent is allowed to request:

```bash
node cli.mjs policy set user@example.com discord --scopes "identify,guilds"
```

### Step 6: Connect your account (one-time, human-in-the-loop)

As the account owner, run:

```bash
node cli.mjs connect discord --scopes "identify guilds"
```

This prints an authorization URL. Open it in your browser, authorize the app, and Discord redirects back to the vault's callback endpoint. The vault stores your refresh token securely.

### Step 7: Agent performs token exchange

The agent sends an RFC 8693 token exchange request, presenting its Tailscale OIDC token:

```bash
curl -X POST http://localhost:3422/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "actor_token=<TSIDP_OIDC_TOKEN>" \
  -d "actor_token_type=urn:ietf:params:oauth:token-type:id_token" \
  -d "resource=https://discord.com/api" \
  -d "scope=identify"
```

The vault verifies the agent's identity, checks policy, refreshes the provider token, and returns:

```json
{
  "access_token": "<scoped_discord_access_token>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 604800,
  "scope": "identify"
}
```

### Step 8: Agent uses the token

```bash
curl -H "Authorization: Bearer <access_token>" \
  https://discord.com/api/v10/users/@me
```

## Discord Webhook Mode (Least-Privilege)

For agents that only need to post messages, use webhook mode — no broad bot permissions needed:

```bash
# Set policy
node cli.mjs policy set user@example.com discord --scopes "webhook.incoming"

# Connect with webhook scope
node cli.mjs connect discord --scopes "webhook.incoming"

# Agent exchanges for webhook credentials
curl -X POST http://localhost:3422/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "actor_token=<TSIDP_OIDC_TOKEN>" \
  -d "actor_token_type=urn:ietf:params:oauth:token-type:id_token" \
  -d "resource=https://discord.com/api" \
  -d "scope=webhook.incoming"

# Post a message via the returned webhook URL
curl -X POST <webhook_url> \
  -H "Content-Type: application/json" \
  -d '{"content": "Hello from an AI agent via OpenCloak!"}'
```

## Tailnet Deployment

Expose the vault only within your tailnet (never on the public internet):

```bash
tailscale serve https / http://localhost:3422
```

Update your provider's redirect URI to use the tailnet hostname:
```
https://<your-node>.<tailnet>.ts.net/oauth/callback/discord
```

## Docker

```bash
docker build -t opencloak .
docker run -p 3422:3422 -v opencloak-data:/data opencloak
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `start [--port 3422]` | Start the vault server |
| `add-provider <name> --client-id X --client-secret Y` | Register an OAuth provider |
| `register-agent --ts-identity <email-or-tag>` | Register an agent by Tailscale identity |
| `policy set <identity> <provider> --scopes <scopes>` | Set agent permissions (comma-separated) |
| `connect <provider> [--scopes "s1 s2"]` | Start OAuth consent flow (opens browser) |
| `exchange --provider <name> --scope <scope>` | Manual token exchange (dev/testing) |
| `list` | Show all registered entities |
| `help` | Show usage information |

## How It Works

```
Agent (on tailnet)                    OpenCloak Vault                     Discord/GitHub/etc.
      |                                     |                                    |
      |-- POST /token ---------------------->|                                    |
      |   (tsidp OIDC token + resource)     |                                    |
      |                                     |-- Verify OIDC token (JWKS) ------->|
      |                                     |-- Look up agent + policy            |
      |                                     |-- Refresh provider token ---------->|
      |                                     |<-- Fresh access token --------------|
      |<-- Scoped access token -------------|                                    |
      |                                                                          |
      |-- GET /users/@me (Bearer token) ------------------------------------>|
      |<-- User data --------------------------------------------------------|
```

1. **Agent authenticates** — presents Tailscale tsidp OIDC token (proves tailnet identity)
2. **Vault verifies** — fetches OIDC discovery + JWKS from tsidp, verifies JWT signature
3. **Policy check** — looks up agent, finds owner's connected account, intersects scopes with policy
4. **Token refresh** — uses stored refresh token to get a fresh access token from the provider
5. **Scoped return** — returns only the scopes the agent's policy allows

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/token` | POST | RFC 8693 token exchange |
| `/oauth/callback/:provider` | GET | OAuth callback (receives authorization codes) |
| `/health` | GET | Health check |
| `/.well-known/openid-configuration` | GET | OIDC discovery metadata |
| `/jwks` | GET | JSON Web Key Set (public keys only) |

## Project Structure

```
opencloak/
├── server.mjs              # HTTP server with all endpoints
├── cli.mjs                 # CLI tool for vault management
├── config.mjs              # Configuration and adapter singleton
├── policy.mjs              # Per-agent policy evaluation
├── grants/
│   └── token-exchange.mjs  # RFC 8693 token exchange handler
├── verifiers/
│   ├── oidc.mjs            # OIDC token verification (JWKS)
│   └── index.mjs           # Verifier dispatcher
├── providers/
│   ├── base.mjs            # Provider interface
│   ├── discord.mjs         # Discord OAuth2 connector
│   └── generic-oauth.mjs   # Generic OAuth2 (for adding new providers)
├── adapters/
│   ├── base.mjs            # Storage adapter interface
│   └── json-file.mjs       # File-based storage with atomic writes
├── Dockerfile
└── package.json
```

## Adding New Providers

Extend `providers/generic-oauth.mjs` or create a new provider file:

```bash
node cli.mjs add-provider github \
  --client-id <ID> --client-secret <SECRET> \
  --authorize-url https://github.com/login/oauth/authorize \
  --token-url https://github.com/login/oauth/access_token \
  --resource-uri https://api.github.com
```

## Security Model

- **Tailnet-only** — vault is never exposed to the public internet
- **No stored API keys** — only OAuth refresh tokens (revocable, scoped)
- **Per-agent policy** — each agent gets independently scoped access
- **Atomic token rotation** — safe handling of rotating refresh tokens
- **File permissions** — vault data stored with 0700/0600 permissions

## License

MIT
