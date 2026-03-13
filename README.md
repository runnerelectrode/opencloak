<p align="center">
  <img src="logo.png" alt="OpenCloak" width="600">
</p>

<p align="center">
  Open-source OAuth vault for AI agents. Built for <a href="https://github.com/runnerelectrode/openclaw">OpenClaw</a>.<br>
  RFC 8693 token exchange · RFC 8628 device authorization · Pluggable OIDC identity.
</p>

Any AI agent proves who it is with a standard OIDC token (Google, Okta, Auth0, Azure AD, or any compliant provider). OpenCloak checks policy and returns a scoped, short-lived access token for third-party APIs (Discord, GitHub, Google, Slack). Your agent never sees or stores long-lived credentials.

**Zero external dependencies.** Pure Node.js 18+.

## How It Works

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
└──────────────┘  ③  │              │
       │              │              │     ┌──────────────┐
       │              │              │────>│   Discord    │
       │              └──────────────┘  ④  │     API      │
       │                     │             └──────────────┘
       │                     │
       │              ⑤ Scoped credential
       │<────────────────────┘
       │
       ▼
┌──────────────┐
│   Discord    │
│   webhook    │  Agent posts with credential it received
└──────────────┘
```

| Step | What happens |
|------|-------------|
| ① | Agent calls `POST /device/code` → gets a short code like `BCDF-GH34` |
| ② | Human enters the code at `/device/verify`, signs in with Google |
| ③ | Agent polls `GET /device/token` → gets `id_token` proving the human authorized it |
| ④ | Agent calls `POST /token` (RFC 8693 token exchange) with the `id_token` |
| ⑤ | OpenCloak checks policy, returns a scoped Discord webhook credential |

The agent never sees your Discord OAuth credentials. It only gets back what OpenCloak's policy allows. The human authorizes the agent by entering a short code — the agent never opens a browser.

## Prerequisites

- **Node.js 18+** installed
- **An OIDC identity provider** (Google, Okta, Auth0, Azure AD, etc.)
- A **third-party API** to delegate access to (Discord, GitHub, etc.)

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
node cli.mjs add-provider discord \
  --client-id <YOUR_DISCORD_CLIENT_ID> \
  --client-secret <YOUR_DISCORD_CLIENT_SECRET>
```

### 5. Register an agent and set policy

```bash
node cli.mjs register-agent --identity user@example.com
node cli.mjs policy set user@example.com discord --scopes "webhook.incoming"
```

### 6. Connect your account (one-time, human-in-the-loop)

```bash
node cli.mjs connect discord --scopes "webhook.incoming"
```

### 7. Agent performs token exchange

```bash
curl -X POST http://localhost:3422/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "actor_token=<OIDC_TOKEN>" \
  -d "actor_token_type=urn:ietf:params:oauth:token-type:id_token" \
  -d "resource=https://discord.com/api" \
  -d "scope=webhook.incoming"
```

## Device Flow for Headless Agents

When an agent can't open a browser (sandboxed, headless, CI/CD), use the device flow:

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

// 3. Exchange id_token for scoped credentials
const tokenRes = await fetch("https://vault.example.com/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    actor_token: idToken,
    actor_token_type: "urn:ietf:params:oauth:token-type:id_token",
    resource: "https://discord.com/api",
    scope: "webhook.incoming",
  }),
});
const { webhook_url } = await tokenRes.json();

// 4. Use the credential — agent never had Discord secrets
await fetch(webhook_url, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ content: "Hello from a headless agent!" }),
});
```

## Running in Daytona

OpenCloak works with [Daytona](https://www.daytona.io/) sandboxes. The agent runs inside a headless sandbox, authenticates via the device flow, and gets scoped credentials — without any secrets in its environment.

> **Heroku required for Daytona.** Daytona Tier 1/Tier 2 sandboxes restrict outbound network access to a fixed allowlist. `*.herokuapp.com` is on that allowlist, but custom domains and arbitrary VPS IPs are not. You'll need to deploy OpenCloak to Heroku (or another allowlisted host) for the sandbox to reach the vault. See the [Heroku deployment section](#heroku) below.

```
┌──────────────────────────────────────────────────────────────┐
│                       Daytona Sandbox                        │
│                                                              │
│   ┌────────────┐                                             │
│   │  OpenClaw  │─── POST /device/code ────────┐              │
│   │  (agent)   │─── GET  /device/token ───┐   │              │
│   │            │─── POST /token ───────┐  │   │              │
│   │            │                       │  │   │              │
│   │            │<── webhook_url ───────┘  │   │              │
│   │            │                          │   │              │
│   │            │─── POST webhook_url ─────│───│──────┐       │
│   └────────────┘                          │   │      │       │
│                                           │   │      │       │
└───────────────────────────────────────────│───│──────│───────┘
                                            │   │      │
                                            ▼   ▼      ▼
                                     ┌────────────┐  ┌─────────┐
                                     │  OpenCloak │  │ Discord │
                                     │  (vault)   │  │  API    │
                                     └──────┬─────┘  └─────────┘
                                            │
                                            ▼
                                     ┌────────────┐
                                     │   Google   │
                                     │   (OIDC)   │
                                     └────────────┘
```

### Daytona Demo

The `examples/daytona/device-flow-demo.mjs` script runs the full flow end-to-end:

1. Creates a Daytona sandbox
2. Agent in sandbox calls `POST /device/code` → gets a short code
3. You sign in with Google in your browser
4. Agent polls `GET /device/token` → gets `id_token`
5. Agent calls `POST /token` (RFC 8693) → gets Discord webhook credential
6. Agent posts a message to Discord

```bash
export DAYTONA_API_KEY=your_key
export DAYTONA_API_URL=https://app.daytona.io/api
export HEROKU_API_KEY=your_heroku_key

node examples/daytona/device-flow-demo.mjs
```

The agent never has Discord credentials in its environment. It gets them at runtime through human-authorized token exchange.

## Deployment

### Heroku

OpenCloak deploys to Heroku with env-var-based data seeding (Heroku has an ephemeral filesystem).

```bash
# Set environment variables
heroku config:set \
  OPENCLOAK_ISSUER=https://your-app.herokuapp.com \
  GOOGLE_CLIENT_ID=... \
  GOOGLE_CLIENT_SECRET=... \
  DISCORD_WEBHOOK_URL=... \
  DISCORD_WEBHOOK_ID=... \
  DISCORD_WEBHOOK_TOKEN=...

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

### Local Dev

```bash
node cli.mjs start --port 3422
```

Data is stored in `~/.config/opencloak` by default.

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

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/token` | POST | RFC 8693 token exchange |
| `/device/code` | POST | Start device authorization flow (RFC 8628) |
| `/device/verify` | GET | Code entry page for human |
| `/device/verify` | POST | Submit device code |
| `/device/callback/:issuer` | GET | OIDC callback for device flow |
| `/device/complete` | GET | Success page after authorization |
| `/device/token` | GET | Agent polls for id_token |
| `/auth/:issuer` | GET | Browser-based OIDC sign-in |
| `/auth/:issuer/callback` | GET | OIDC callback for browser sign-in |
| `/oauth/callback/:provider` | GET | OAuth callback (authorization codes) |
| `/health` | GET | Health check |
| `/.well-known/openid-configuration` | GET | OIDC discovery metadata |
| `/jwks` | GET | JSON Web Key Set |

## CLI Reference

| Command | Description |
|---------|-------------|
| `start [--port 3422]` | Start the vault server |
| `add-issuer <name> --issuer-url <url> [--audience <aud>]` | Register an OIDC identity provider |
| `add-provider <name> --client-id X --client-secret Y` | Register an OAuth provider |
| `register-agent --identity <sub>` | Register an agent by OIDC identity |
| `policy set <identity> <provider> --scopes <scopes>` | Set agent permissions |
| `connect <provider> [--scopes "s1 s2"]` | Start OAuth consent flow |
| `exchange --provider <name> --scope <scope>` | Manual token exchange (dev/testing) |
| `list` | Show all registered entities |
| `help` | Show usage information |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENCLOAK_DATA_DIR` | Data directory path (default: `~/.config/opencloak`) |
| `OPENCLOAK_ENCRYPTION_KEY` | AES-256 key for encrypting secrets at rest |
| `OPENCLOAK_TRUSTED_ISSUERS` | Comma-separated trusted OIDC issuer URLs |
| `OPENCLOAK_ISSUER` | Public URL of the vault (for OIDC discovery) |

## Project Structure

```
opencloak/
├── server.mjs                          # HTTP server — all endpoints
├── cli.mjs                             # CLI for vault management
├── config.mjs                          # Configuration and adapter singleton
├── policy.mjs                          # Per-agent policy evaluation
├── heroku-start.mjs                    # Heroku startup with env-var seeding
├── Procfile                            # Heroku process definition
├── grants/
│   └── token-exchange.mjs              # RFC 8693 token exchange handler
├── verifiers/
│   ├── oidc.mjs                        # OIDC token verification (JWKS)
│   └── index.mjs                       # Verifier dispatcher
├── providers/
│   ├── base.mjs                        # Provider interface
│   ├── discord.mjs                     # Discord OAuth2 connector
│   └── generic-oauth.mjs              # Generic OAuth2 provider
├── adapters/
│   ├── base.mjs                        # Storage adapter interface
│   └── json-file.mjs                   # File-based storage (atomic writes)
├── web/
│   ├── index.html                      # Sign-in landing page
│   ├── device.html                     # Device code entry page
│   ├── device-complete.html            # "Authorization complete" page
│   ├── style.css                       # Shared styles
│   └── app.js                          # Client-side JS
├── examples/
│   └── daytona/
│       └── device-flow-demo.mjs        # End-to-end Daytona demo
├── Dockerfile
└── package.json
```

## Security Model

- **Network isolation** — deploy behind a firewall, VPN, or reverse proxy
- **No stored API keys** — only OAuth refresh tokens (revocable, scoped)
- **Per-agent policy** — each agent gets independently scoped access
- **Device codes** — 256-bit random, 10-minute expiry, one-time retrieval
- **User codes** — no vowels (avoids offensive words), no ambiguous chars (0/O, 1/I/L)
- **Polling rate enforcement** — server-side `slow_down` per RFC 8628
- **PKCE + nonce** — all OIDC flows use PKCE and nonce validation
- **JWKS origin validation** — prevents SSRF via discovery document
- **HTTPS enforced** — non-local OIDC endpoints must use HTTPS

## License

MIT
