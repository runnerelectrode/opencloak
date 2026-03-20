<p align="center">
  <img src="logo.png" alt="OpenCloak" width="600">
</p>

<p align="center">
  Open-source OAuth vault and LLM gateway for AI agents. Built for <a href="https://github.com/runnerelectrode/openclaw">OpenClaw</a>.<br>
  RFC 8693 token exchange · RFC 8628 device authorization · LLM credential gateway · Pluggable OIDC identity.
</p>

Any AI agent proves who it is with a standard OIDC token (Google, Okta, Auth0, Azure AD, or any compliant provider). OpenCloak checks policy and returns a scoped, short-lived access token for third-party APIs (Linear, GitHub, Google, Slack) — or a gateway JWT for LLM APIs (Anthropic, OpenAI, OpenRouter). Your agent never sees or stores long-lived credentials.

**Zero external dependencies.** Pure Node.js 18+.

## How It Works

### First Time (human-in-the-loop)

```
                        ┌─────────┐
                        │  Human  │
                        │(browser)│
                        └────┬────┘
                             │
                        ② Enters code
                        Signs in with Google
                             │
                             ▼
┌──────────────┐  ①  ┌──────────────┐     ┌──────────────┐
│   AI Agent   │────>│              │     │    Google     │
│  (headless   │     │  OpenCloak   │<───>│    (OIDC)    │
│   sandbox)   │<────│  (the vault) │     └──────────────┘
└──────────────┘  ⑤  │              │
       │              └──────────────┘
       │                     │
       │              ④ Token exchange
       │<────────────────────┘
       │
       │  ⑥ Bearer token
       ▼
┌──────────────┐
│   Linear     │
│   GraphQL    │  Agent calls API directly with Bearer token
└──────────────┘
```

| Step | What happens |
|------|-------------|
| ① | Agent calls `POST /device/code` → gets a short code like `BCDF-GH34` |
| ② | Human enters the code at `/device/verify`, signs in with Google |
| ③ | Agent polls `GET /device/token` → gets `id_token` proving the human authorized it |
| ④ | Agent calls `POST /token` (RFC 8693 token exchange) with the `id_token` |
| ⑤ | OpenCloak checks policy, returns a scoped Bearer token for Linear |
| ⑥ | Agent calls Linear GraphQL API directly with the Bearer token |

### After Authorization (same sandbox)

Once a human has authorized a device code, the device session persists for **24 hours**. The same sandbox can keep polling for fresh `id_token`s and exchanging them for scoped Bearer tokens — no re-authorization required:

```
┌──────────────┐  ①  ┌──────────────┐
│   AI Agent   │────>│  OpenCloak   │  Same device_code → fresh id_token
│  (same       │     │  (the vault) │  (minted on each poll, never expires
│   sandbox)   │<────│              │   within the 24h session)
└──────────────┘  ②  └──────────────┘
       │
       │  ③ Bearer token
       ▼
┌──────────────┐
│   Linear     │
│   GraphQL    │
└──────────────┘
```

**New sandboxes always require human approval.** Each new `POST /device/code` starts as `pending` — a different sandbox could be malicious. The human-in-the-loop is the security guarantee (RFC 8628). The same sandbox making multiple requests does not need re-approval.

The agent never sees your Linear OAuth credentials. It only gets back what OpenCloak's policy allows — a scoped, short-lived Bearer token.

## LLM Gateway

For LLM APIs (Anthropic, OpenAI, OpenRouter), OAuth token exchange doesn't work — these APIs use API keys, not Bearer tokens. If the vault returned the raw API key, the agent would have it in plaintext.

The **LLM Gateway** (`gateway.opencloak.org`) solves this as a standalone reverse proxy. The agent gets a short-lived JWT, calls the gateway, and the gateway injects the real API key server-side. The agent never sees it.

```
┌──────────────┐  ①  ┌──────────────┐     ┌──────────────┐
│   AI Agent   │────>│  OpenCloak   │────>│    Google     │
│  (headless   │     │  Vault       │     │    (OIDC)     │
│   sandbox)   │<────│              │     └──────────────┘
└──────────────┘  ②  └──────────────┘
       │              JWT with scope
       │              "llm:openrouter"
       │
       │  ③ POST /v1/chat/completions
       │     Authorization: Bearer <gateway_jwt>
       ▼
┌──────────────┐  ④  ┌──────────────┐
│  OpenCloak   │────>│  OpenRouter  │
│  Gateway     │     │  (upstream)  │
│              │<────│              │
│  Validates   │  ⑤  └──────────────┘
│  JWT, injects│
│  API key     │
└──────────────┘
```

| Step | What happens |
|------|-------------|
| ① | Agent does device flow → gets `id_token` (same as OAuth flow) |
| ② | Agent exchanges `id_token` at vault with `scope=llm:openrouter` → gets gateway JWT (15 min) |
| ③ | Agent calls `POST gateway.opencloak.org/v1/chat/completions` with the JWT |
| ④ | Gateway validates JWT via JWKS, injects the real API key, proxies to OpenRouter |
| ⑤ | Response streams back through the gateway to the agent |

### Why a Separate Gateway

- **Standalone** — run just the LLM proxy without the full vault. Works with any OIDC issuer (Auth0, Okta, Keycloak)
- **Independent scaling** — LLM proxy traffic (large streaming responses) ≠ auth traffic (small JSON)
- **No shared secrets** — gateway validates JWTs via standard JWKS discovery, not shared keys
- **API keys encrypted at rest** — AES-256-GCM via the shared adapter

### Gateway Quick Start

```bash
# 1. Start the gateway
node gateway/cli.mjs start --jwks-url https://id.opencloak.org/jwks --port 3423

# 2. Register an LLM provider with your API key
node gateway/cli.mjs llm add openrouter --api-key sk-or-v1-...
node gateway/cli.mjs llm add anthropic --api-key sk-ant-...
node gateway/cli.mjs llm add openai --api-key sk-...

# 3. Register the provider stub on the vault (no API key needed)
node cli.mjs add-provider openrouter --type llm

# 4. Set policy
node cli.mjs policy set user@example.com openrouter --scopes "llm:openrouter"
```

Then the agent exchanges for a gateway JWT and calls the LLM through the gateway:

```bash
# Exchange id_token for gateway JWT
curl -X POST https://id.opencloak.org/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "actor_token=<id_token>" \
  -d "actor_token_type=urn:ietf:params:oauth:token-type:id_token" \
  -d "resource=https://gateway.opencloak.org" \
  -d "scope=llm:openrouter"

# Call LLM through gateway — API key injected server-side
curl -X POST https://gateway.opencloak.org/v1/chat/completions \
  -H "Authorization: Bearer <gateway_jwt>" \
  -H "Content-Type: application/json" \
  -d '{"model":"anthropic/claude-sonnet-4","max_tokens":100,"messages":[{"role":"user","content":"Hi"}]}'
```

### Built-in Provider Presets

| Provider | Upstream | Auth Header | Extras |
|----------|----------|-------------|--------|
| `anthropic` | `https://api.anthropic.com` | `x-api-key` | `anthropic-version: 2023-06-01` |
| `openai` | `https://api.openai.com` | `Authorization: Bearer` | — |
| `openrouter` | `https://openrouter.ai/api` | `Authorization: Bearer` | — |

Custom providers are supported with `--upstream-url`, `--auth-header`, and `--auth-scheme`.

## Prerequisites

- **Node.js 18+** installed
- **An OIDC identity provider** (Google, Okta, Auth0, Azure AD, etc.)
- A **third-party OAuth provider** to delegate access to (Linear, GitHub, etc.)

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/runnerelectrode/opencloak.git
cd opencloak
npm install
```

### 2. Start the vault server

```bash
node cli.mjs start --port 3422
```

### 3. Register an identity provider

```bash
node cli.mjs add-issuer google \
  --issuer-url https://accounts.google.com \
  --audience YOUR_GOOGLE_CLIENT_ID
```

For device flow (headless agents), also pass the Google OAuth client credentials:

```bash
node cli.mjs add-issuer google \
  --issuer-url https://accounts.google.com \
  --audience YOUR_GOOGLE_CLIENT_ID \
  --client-id YOUR_GOOGLE_CLIENT_ID \
  --client-secret YOUR_GOOGLE_CLIENT_SECRET
```

### 4. Register an OAuth provider

```bash
node cli.mjs add-provider linear \
  --client-id <YOUR_LINEAR_CLIENT_ID> \
  --client-secret <YOUR_LINEAR_CLIENT_SECRET>
```

### 5. Register an agent and set policy

```bash
node cli.mjs register-agent --identity user@example.com
node cli.mjs policy set user@example.com linear --scopes "issues:create"
```

### 6. Connect your account (one-time, human-in-the-loop)

**Web UI:** Navigate to `/connect` on your vault to connect accounts via OAuth in the browser.

**CLI:**

```bash
node cli.mjs connect linear --scopes "issues:create"
```

### 7. Agent performs token exchange

```bash
curl -X POST http://localhost:3422/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "actor_token=<OIDC_TOKEN>" \
  -d "actor_token_type=urn:ietf:params:oauth:token-type:id_token" \
  -d "resource=https://api.linear.app" \
  -d "scope=issues:create"
```

## Device Flow for Headless Agents

When an agent can't open a browser (sandboxed, headless, CI/CD), use the device flow. A human signs in via the browser once per sandbox. After that, the sandbox can keep getting fresh tokens for 24 hours.

```javascript
// 1. Agent requests a device code
const codeRes = await fetch("https://vault.example.com/device/code", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: "issuer_id=google",
});
const { device_code, user_code, verification_uri_complete } = await codeRes.json();

console.log(`Enter code ${user_code} at ${verification_uri_complete}`);

// 2. Poll until the human signs in
let idToken;
while (!idToken) {
  await new Promise(r => setTimeout(r, 5000));
  const pollRes = await fetch(`https://vault.example.com/device/token?device_code=${device_code}`);
  const data = await pollRes.json();
  if (data.id_token) idToken = data.id_token;
  if (data.error === "expired_token") throw new Error("Code expired");
}

// 3. Exchange id_token for scoped Bearer token
const tokenRes = await fetch("https://vault.example.com/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    actor_token: idToken,
    actor_token_type: "urn:ietf:params:oauth:token-type:id_token",
    resource: "https://api.linear.app",
    scope: "issues:create",
  }),
});
const { access_token } = await tokenRes.json();

// 4. Use the Bearer token — agent never had Linear secrets
await fetch("https://api.linear.app/graphql", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${access_token}`,
  },
  body: JSON.stringify({
    query: `mutation {
      issueCreate(input: {
        title: "Hello from a headless agent!"
        teamId: "YOUR_TEAM_ID"
      }) { success issue { url } }
    }`,
  }),
});

// 5. Later — same sandbox can re-poll for a fresh id_token (no re-auth)
const freshPoll = await fetch(`https://vault.example.com/device/token?device_code=${device_code}`);
const { id_token: freshIdToken } = await freshPoll.json();
// Exchange again for a new Bearer token...
```

## Running in E2B

OpenCloak works with [E2B](https://e2b.dev/) sandboxes. E2B provides full internet access by default, so agents can reach any vault and API endpoint. The agent runs inside a secure sandbox with zero credentials — it authenticates via the device flow and gets scoped tokens from OpenCloak.

```
┌─────────────────────────┐
│       E2B Sandbox       │
│                         │
│   ┌────────────┐        │       ┌────────────┐       ┌────────────┐
│   │  OpenClaw  │───────────────>│  OpenCloak │──────>│   Google   │
│   │  (agent)   │  POST /device/ │  (vault)   │ OIDC  │   (OIDC)   │
│   │            │  code + token  │            │       └────────────┘
│   │            │                │            │
│   │            │  POST /token   │            │
│   │            │  (id_token) ──>│            │
│   │            │<── Bearer ─────│            │
│   │            │    token       └────────────┘
│   │            │
│   │            │  POST graphql  ┌────────────┐
│   │            │  Authorization:│   Linear   │
│   │            │  Bearer ──────>│    API     │
│   │            │<── issue ──────│            │
│   └────────────┘   created      └────────────┘
│                         │
└─────────────────────────┘
```

### E2B Demo

The demo creates an E2B sandbox with the `openclaw` template, runs the device flow (human approves once), then the [OpenClaw](https://github.com/runnerelectrode/openclaw) agent autonomously exchanges tokens and creates Linear issues:

```bash
node e2b-openclaw-demo.mjs
```

The script:
1. Creates an E2B sandbox with OpenClaw pre-installed
2. Configures OpenRouter as the LLM provider (Sonnet 4.5 or DeepSeek V3)
3. Agent requests a device code — **human signs in with Google**
4. Agent polls, gets `id_token`, exchanges for Linear Bearer token (RFC 8693)
5. Agent creates a Linear issue — zero credentials in its environment
6. Sandbox stays alive — subsequent issues need no re-authorization

Multiple sandboxes can run independently, each with their own device session and authorization.

### E2B Agent Demo (raw)

A raw demo without OpenClaw — uses DeepSeek V3 directly with tool calls:

```bash
node e2b-agent-demo.mjs
```

## Running in Blaxel

OpenCloak works with [Blaxel](https://blaxel.ai/) sandboxes — perpetual microVMs that resume from standby in under 25ms. The agent runs in a `blaxel/node:latest` sandbox with zero credentials, authenticates via device flow, and gets scoped tokens from OpenCloak.

```
┌─────────────────────────┐
│      Blaxel Sandbox     │
│                         │
│   ┌────────────┐        │       ┌────────────┐       ┌────────────┐
│   │  OpenClaw  │───────────────>│  OpenCloak │──────>│   Google   │
│   │  (agent)   │  POST /device/ │  (vault)   │ OIDC  │   (OIDC)   │
│   │  Sonnet    │  code + token  │            │       └────────────┘
│   │  4.5 via   │                │            │
│   │  OpenRouter│  POST /token   │            │
│   │            │  (id_token) ──>│            │
│   │            │<── Bearer ─────│            │
│   │            │    token       └────────────┘
│   │            │
│   │            │  POST graphql  ┌────────────┐
│   │            │  Authorization:│   Linear   │
│   │            │  Bearer ──────>│    API     │
│   │            │<── issue ──────│            │
│   └────────────┘   created      └────────────┘
│                         │
└─────────────────────────┘
```

### Blaxel Demo

The demo creates a Blaxel sandbox, installs OpenClaw, runs the device flow (human approves once), then the OpenClaw agent autonomously exchanges tokens and creates Linear issues:

```bash
node blaxel-openclaw-demo.mjs
```

The script:
1. Creates a Blaxel sandbox (`blaxel/node:latest`, 4GB RAM)
2. Installs OpenClaw and configures OpenRouter (Sonnet 4.5)
3. Agent requests a device code — **human signs in with Google**
4. Agent polls, gets `id_token`, exchanges for Linear Bearer token (RFC 8693)
5. OpenClaw agent creates a Linear issue — zero credentials in its environment
6. Sandbox stays alive — subsequent issues need no re-authorization

The sandbox auto-scales to zero after inactivity and resumes in <25ms, so it can be reused across sessions.

## Running in Daytona

OpenCloak also works with [Daytona](https://www.daytona.io/) sandboxes. Note that Daytona Tier 1/2 restricts outbound network access — `*.herokuapp.com` and `*.linear.app` are on the allowlist.

## OpenClaw Skill

OpenCloak ships with an [OpenClaw](https://github.com/runnerelectrode/openclaw) skill that teaches any agent how to authenticate via the device flow.

### Install the skill

```bash
# Copy to your OpenClaw skills directory
cp -r skills/opencloak-auth ~/.openclaw/skills/

# Or symlink it
ln -s $(pwd)/skills/opencloak-auth ~/.openclaw/skills/opencloak-auth
```

### Use it

Set the vault URL and ask the agent to do something that requires API access:

```bash
export OPENCLOAK_URL=https://your-vault.example.com

openclaw agent -m "Create a Linear issue titled 'Hello from OpenClaw' in team YOUR_TEAM_ID"
```

The agent will automatically:
1. Call `POST /device/code` to get a short code
2. Show you the verification link to sign in
3. Poll until you authorize
4. Exchange the id_token for a scoped Bearer token
5. Call the API with the Bearer token

No credentials ever enter the agent's environment.

## Deployment

### Heroku

OpenCloak deploys to Heroku with env-var-based data seeding (Heroku has an ephemeral filesystem).

```bash
# Set environment variables
heroku config:set \
  OPENCLOAK_ISSUER=https://your-app.herokuapp.com \
  GOOGLE_CLIENT_ID=... \
  GOOGLE_CLIENT_SECRET=... \
  LINEAR_CLIENT_ID=... \
  LINEAR_CLIENT_SECRET=... \
  LINEAR_TEAM_ID=<uuid>  # Team UUID, not the short key

# Deploy
git push heroku main
```

Add these redirect URIs to your Google OAuth console:
- `https://your-app.herokuapp.com/auth/google/callback`
- `https://your-app.herokuapp.com/device/callback/google`

### VPS (DigitalOcean, Hetzner, etc.)

```bash
git clone https://github.com/runnerelectrode/opencloak.git
cd opencloak
node cli.mjs start --data-dir /opt/opencloak/data --port 3422
```

Set up a reverse proxy (Caddy, nginx) for HTTPS:

```
opencloak.example.com {
    reverse_proxy localhost:3422
}
```

Run as a systemd service:

```bash
sudo tee /etc/systemd/system/opencloak.service > /dev/null <<'EOF'
[Unit]
Description=OpenCloak OAuth Vault
After=network.target

[Service]
Type=simple
User=opencloak
WorkingDirectory=/opt/opencloak
ExecStart=/usr/bin/node cli.mjs start --data-dir /opt/opencloak/data --port 3422
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now opencloak
```

### Gateway (VPS)

```bash
# Start the gateway alongside the vault
node gateway/cli.mjs start \
  --jwks-url https://id.opencloak.org/jwks \
  --port 3423

# Or with env vars
OPENCLOAK_GATEWAY_JWKS_URL=https://id.opencloak.org/jwks \
OPENCLOAK_GATEWAY_DATA_DIR=/var/lib/opencloak-gateway \
OPENCLOAK_GATEWAY_URL=https://gateway.opencloak.org \
OPENCLOAK_ENCRYPTION_KEY=<your-key> \
node gateway/cli.mjs start
```

Run as a systemd service:

```bash
sudo tee /etc/systemd/system/opencloak-gateway.service > /dev/null <<'EOF'
[Unit]
Description=OpenCloak LLM Gateway
After=network.target

[Service]
Type=simple
User=opencloak
WorkingDirectory=/opt/opencloak
EnvironmentFile=/opt/opencloak-gateway.env
ExecStart=/usr/bin/node gateway/cli.mjs start
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now opencloak-gateway
```

### Local Dev

```bash
# Vault
node cli.mjs start --port 3422

# Gateway (in another terminal)
node gateway/cli.mjs llm add openrouter --api-key sk-or-v1-...
node gateway/cli.mjs start --jwks-url http://localhost:3422/jwks --port 3423
```

Data is stored in `~/.config/opencloak` (vault) and `~/.config/opencloak-gateway` (gateway) by default.

## Identity Providers

OpenCloak accepts OIDC tokens from any standard provider:

```bash
# Google
node cli.mjs add-issuer google --issuer-url https://accounts.google.com

# Okta
node cli.mjs add-issuer okta --issuer-url https://your-org.okta.com

# Auth0
node cli.mjs add-issuer auth0 --issuer-url https://your-tenant.auth0.com/

# Any OIDC-compliant provider
node cli.mjs add-issuer custom --issuer-url https://your-idp.example.com
```

You can also set trusted issuers via `OPENCLOAK_TRUSTED_ISSUERS` env var (comma-separated URLs).

## API Endpoints

### Vault (`id.opencloak.org`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/token` | POST | RFC 8693 token exchange (OAuth + LLM) |
| `/device/code` | POST | Start device authorization flow (RFC 8628) |
| `/device/verify` | GET | Code entry page for human |
| `/device/verify` | POST | Submit device code |
| `/device/callback/:issuer` | GET | OIDC callback for device flow |
| `/device/complete` | GET | Success page after authorization |
| `/device/token` | GET | Agent polls for id_token |
| `/connect` | GET | Web UI to connect provider accounts |
| `/connect/:provider` | GET | Start OAuth connect flow (302 redirect) |
| `/providers` | GET | List configured providers |
| `/auth/:issuer` | GET | Browser-based OIDC sign-in |
| `/auth/:issuer/callback` | GET | OIDC callback for browser sign-in |
| `/oauth/callback/:provider` | GET | OAuth callback (stores connected account) |
| `/admin/accounts` | GET | Export connected accounts (for env var persistence) |
| `/health` | GET | Health check |
| `/.well-known/openid-configuration` | GET | OIDC discovery metadata |
| `/jwks` | GET | JSON Web Key Set |

### Gateway (`gateway.opencloak.org`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/*` | POST | Proxy to upstream LLM (e.g. `/v1/chat/completions`) |
| `/*` | GET | Proxy to upstream LLM (e.g. `/v1/models`) |
| `/health` | GET | Gateway health check |

## CLI Reference

### Vault (`opencloak`)

| Command | Description |
|---------|-------------|
| `start [--port 3422]` | Start the vault server |
| `add-issuer <name> --issuer-url <url> [--audience <aud>]` | Register an OIDC identity provider |
| `add-provider <name> --client-id X --client-secret Y` | Register an OAuth provider |
| `add-provider <name> --type llm` | Register an LLM provider stub (API key lives on gateway) |
| `register-agent --identity <sub>` | Register an agent by OIDC identity |
| `policy set <identity> <provider> --scopes <scopes> [--allowed-models <m>]` | Set agent permissions |
| `connect <provider> [--scopes "s1 s2"]` | Start OAuth consent flow |
| `exchange --provider <name> --scope <scope>` | Manual token exchange (dev/testing) |
| `list` | Show all registered entities |
| `help` | Show usage information |

### Gateway (`opencloak-gateway`)

| Command | Description |
|---------|-------------|
| `start [--port 3423] [--jwks-url <url>]` | Start the gateway server |
| `llm add <provider> --api-key <key>` | Register an LLM provider with API key |
| `llm add custom --api-key <key> --upstream-url <url>` | Register a custom LLM provider |
| `llm list` | List registered LLM providers |
| `llm remove <provider>` | Remove an LLM provider |

## Environment Variables

### Vault

| Variable | Description |
|----------|-------------|
| `OPENCLOAK_DATA_DIR` | Data directory path (default: `~/.config/opencloak`) |
| `OPENCLOAK_ENCRYPTION_KEY` | AES-256 key for encrypting secrets at rest |
| `OPENCLOAK_TRUSTED_ISSUERS` | Comma-separated trusted OIDC issuer URLs |
| `OPENCLOAK_ISSUER` | Public URL of the vault (for OIDC discovery) |
| `REGISTERED_AGENTS` | JSON array of agents to seed on startup (Heroku) |
| `CONNECTED_ACCOUNTS` | JSON array of connected accounts to seed on startup (Heroku) |

### Gateway

| Variable | Description |
|----------|-------------|
| `OPENCLOAK_GATEWAY_JWKS_URL` | JWKS endpoint to fetch signing keys from (e.g. `https://id.opencloak.org/jwks`) |
| `OPENCLOAK_GATEWAY_DATA_DIR` | Gateway data directory (default: `~/.config/opencloak-gateway`) |
| `OPENCLOAK_GATEWAY_URL` | Public URL of the gateway (for JWT audience validation) |
| `OPENCLOAK_ENCRYPTION_KEY` | AES-256 key for encrypting API keys at rest (shared with vault) |
| `PORT` | Gateway listen port (default: `3423`) |

## Project Structure

```
opencloak/
├── server.mjs                          # Vault HTTP server — all endpoints
├── cli.mjs                             # Vault CLI
├── config.mjs                          # Vault configuration and adapter singleton
├── policy.mjs                          # Per-agent policy evaluation
├── heroku-start.mjs                    # Heroku startup with env-var seeding
├── Procfile                            # Heroku process definition
├── gateway-sandbox-demo.mjs           # Blaxel sandbox + gateway demo
├── blaxel-openclaw-demo.mjs           # Blaxel + OpenClaw agent demo
├── e2b-openclaw-demo.mjs              # E2B + OpenClaw agent demo
├── e2b-agent-demo.mjs                 # E2B + raw DeepSeek V3 agent demo
├── e2b-demo.mjs                       # E2B + raw script demo
├── gateway/                            # LLM credential gateway (standalone)
│   ├── server.mjs                      # Gateway HTTP server
│   ├── cli.mjs                         # Gateway CLI (start, llm add/list/remove)
│   ├── proxy.mjs                       # JWT verification, API key injection, streaming
│   ├── config.mjs                      # Gateway configuration and defaults
│   └── audit.mjs                       # OCSF-aligned audit logging
├── grants/
│   └── token-exchange.mjs              # RFC 8693 token exchange (OAuth + LLM branches)
├── verifiers/
│   ├── oidc.mjs                        # OIDC token verification (JWKS)
│   └── index.mjs                       # Verifier dispatcher
├── providers/
│   ├── base.mjs                        # Provider interface
│   ├── discord.mjs                     # Discord OAuth2 connector
│   └── generic-oauth.mjs              # Generic OAuth2 provider
├── adapters/
│   ├── base.mjs                        # Storage adapter interface
│   └── json-file.mjs                   # File-based storage (atomic writes, AES-256-GCM)
├── web/
│   ├── index.html                      # Sign-in landing page
│   ├── device.html                     # Device code entry page
│   ├── device-complete.html            # "Authorization complete" page
│   ├── connect.html                    # Connect provider accounts page
│   ├── style.css                       # Shared styles
│   └── app.js                          # Client-side JS
├── skills/
│   └── opencloak-auth/
│       └── SKILL.md                    # OpenClaw skill for device flow auth
├── Dockerfile
└── package.json
```

## Security Model

- **Human-in-the-loop per sandbox** — every new `POST /device/code` starts as `pending`. A new sandbox could be malicious — each requires human approval via RFC 8628
- **Persistent device sessions** — once a human approves, the device session persists for 24h. The same sandbox can keep getting fresh `id_token`s without re-authorization
- **Fresh tokens on every poll** — the vault mints a new ES256-signed `id_token` on each `GET /device/token` poll, so the sandbox never holds an expired token
- **No stored API keys in agent environments** — OAuth refresh tokens are revocable and scoped; LLM API keys never leave the gateway
- **API keys encrypted at rest** — AES-256-GCM encryption for all secrets (OAuth tokens, LLM API keys)
- **Per-agent policy** — each agent gets independently scoped access, with optional model allowlists for LLM providers
- **Gateway JWT audience scoping** — gateway JWTs include `aud` (gateway URL), `provider_id`, and `scope` claims; the gateway validates all three
- **Short-lived gateway JWTs** — 15-minute expiry; agents re-exchange for fresh tokens
- **JWKS-based verification** — gateway validates JWTs via standard JWKS discovery (no shared secrets between vault and gateway)
- **Device codes** — 256-bit random, 10-minute expiry for pending codes
- **User codes** — no vowels (avoids offensive words), no ambiguous chars (0/O, 1/I/L)
- **Polling rate enforcement** — server-side `slow_down` per RFC 8628
- **PKCE + nonce** — all OIDC flows use PKCE and nonce validation
- **JWKS origin validation** — prevents SSRF via discovery document
- **HTTPS enforced** — non-local OIDC endpoints and upstream LLM URLs must use HTTPS
- **Request body size limit** — 1 MB max on proxied gateway requests
- **Rate limiting** — per-IP rate limiter on both vault and gateway

## License

MIT
