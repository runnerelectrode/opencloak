# OpenCloak

Open-source OAuth vault for AI agents. RFC 8693 token exchange via Tailscale identity.

Agents on your tailnet prove who they are with a Tailscale tsidp OIDC token. OpenCloak checks policy and returns a scoped, short-lived access token for third-party APIs (Discord, GitHub, Google, Slack). Agents never see or store long-lived credentials.

**Zero external dependencies.** Pure Node.js 18+.

## Prerequisites

- **Node.js 18+** installed
- **Tailscale** installed with your node joined to a tailnet, MagicDNS and HTTPS enabled
- **tsidp** running on your tailnet (see setup below)
- A **Discord Developer Application** (or other OAuth provider) with client ID and secret

## Setting Up tsidp (Tailscale Identity Provider)

tsidp is Tailscale's OIDC identity provider that issues tokens based on your tailnet identity. OpenCloak uses these tokens to verify which agent is making a request.

### Option A: Docker (recommended)

Create a `compose.yaml`:

```yaml
services:
  tsidp:
    container_name: tsidp
    image: ghcr.io/tailscale/tsidp:latest
    volumes:
      - tsidp-data:/data
    environment:
      - TAILSCALE_USE_WIP_CODE=1
      - TS_STATE_DIR=/data
      - TS_HOSTNAME=idp
      - TS_AUTHKEY=tskey-auth-xxxxx  # from Tailscale admin console
volumes:
  tsidp-data:
```

```bash
docker compose up -d
```

### Option B: From source (requires Go)

```bash
git clone https://github.com/tailscale/tsidp.git
cd tsidp
TAILSCALE_USE_WIP_CODE=1 go run . -hostname idp -dir ./data
```

### Configure access grants

In the Tailscale admin console (Access Controls), add a grant so your nodes can get tokens from tsidp:

```json
"grants": [
  {
    "src": ["*"],
    "dst": ["tag:idp"],
    "app": {
      "tailscale.com/cap/tsidp": [
        {
          "allow_admin_ui": true,
          "allow_dcr": true,
          "users": ["*"],
          "resources": ["*"]
        }
      ]
    }
  }
]
```

### Verify tsidp is running

Once started, tsidp is available at `https://idp.<your-tailnet>.ts.net`. Verify with:

```bash
curl https://idp.<your-tailnet>.ts.net/.well-known/openid-configuration
```

You should see an OIDC discovery document with `issuer`, `token_endpoint`, `jwks_uri`, etc.

### Getting a token from tsidp

Agents obtain OIDC tokens by authenticating through tsidp's standard OIDC flow. The token's `sub` claim contains the Tailscale identity (user email or device tag) — this is what OpenCloak uses to identify the agent.

The issuer will be `https://idp.<your-tailnet>.ts.net`, which matches OpenCloak's trusted issuer pattern (`*.ts.net`).

## Step-by-Step Setup

### Step 1: Clone and install

```bash
git clone https://github.com/runnerelectrode/opencloak.git
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

## Deployment

OpenCloak should only be accessible within your tailnet — never exposed to the public internet. Below are guides for common setups.

### Option A: VPS (Digital Ocean, Hetzner, etc.)

Your VPS joins the tailnet and runs OpenCloak. Other tailnet nodes (your AI agents) connect to it via its tailnet hostname.

**1. Install Tailscale on the VPS:**

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --hostname opencloak
```

**2. Clone and run OpenCloak:**

```bash
git clone https://github.com/runnerelectrode/opencloak.git
cd opencloak
node cli.mjs start --data-dir /opt/opencloak/data --port 3422
```

**3. Expose via Tailscale HTTPS (TLS handled automatically):**

```bash
tailscale serve https / http://localhost:3422
```

Your vault is now available at `https://opencloak.<your-tailnet>.ts.net` — only to devices on your tailnet.

**4. Set your OAuth redirect URI to the tailnet hostname:**

```
https://opencloak.<your-tailnet>.ts.net/oauth/callback/discord
```

**5. Run as a systemd service (so it survives reboots):**

```bash
sudo tee /etc/systemd/system/opencloak.service > /dev/null <<'EOF'
[Unit]
Description=OpenCloak OAuth Vault
After=network.target tailscaled.service

[Service]
Type=simple
User=opencloak
WorkingDirectory=/opt/opencloak
ExecStart=/usr/bin/node cli.mjs start --data-dir /opt/opencloak/data --port 3422
Restart=always
RestartSec=5
Environment=OPENCLOAK_ENCRYPTION_KEY=<your-encryption-key>
Environment=OPENCLOAK_TRUSTED_ISSUERS=https://idp.<your-tailnet>.ts.net

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now opencloak
```

**6. Using Docker on the VPS:**

```bash
docker build -t opencloak .
docker run -d \
  --name opencloak \
  --restart unless-stopped \
  -p 127.0.0.1:3422:3422 \
  -v opencloak-data:/data \
  -e OPENCLOAK_ENCRYPTION_KEY=<your-encryption-key> \
  -e OPENCLOAK_TRUSTED_ISSUERS=https://idp.<your-tailnet>.ts.net \
  opencloak
```

Note: bind to `127.0.0.1` so it's only accessible via Tailscale, not the public IP.

### Option B: Mac Mini (home server)

Your Mac Mini joins the tailnet and runs OpenCloak directly. Good for home labs or small teams.

**1. Install Tailscale:**

Download from https://tailscale.com/download/mac or:

```bash
brew install tailscale
```

Make sure your Mac Mini is connected to your tailnet with MagicDNS enabled.

**2. Clone and run OpenCloak:**

```bash
git clone https://github.com/runnerelectrode/opencloak.git
cd opencloak
node cli.mjs start --port 3422
```

Data is stored in `~/.config/opencloak` by default.

**3. Expose via Tailscale HTTPS:**

```bash
tailscale serve https / http://localhost:3422
```

Your vault is now at `https://<mac-mini-hostname>.<your-tailnet>.ts.net`.

**4. Set your OAuth redirect URI:**

```
https://<mac-mini-hostname>.<your-tailnet>.ts.net/oauth/callback/discord
```

**5. Run on startup with launchd:**

```bash
mkdir -p ~/Library/LaunchAgents

cat > ~/Library/LaunchAgents/com.opencloak.vault.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.opencloak.vault</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/node</string>
        <string>$(pwd)/cli.mjs</string>
        <string>start</string>
        <string>--port</string>
        <string>3422</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>OPENCLOAK_ENCRYPTION_KEY</key>
        <string>your-encryption-key</string>
        <key>OPENCLOAK_TRUSTED_ISSUERS</key>
        <string>https://idp.your-tailnet.ts.net</string>
    </dict>
    <key>StandardOutPath</key>
    <string>/tmp/opencloak.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/opencloak.err</string>
</dict>
</plist>
EOF

launchctl load ~/Library/LaunchAgents/com.opencloak.vault.plist
```

### Option C: Local dev (no Tailscale)

For testing without a tailnet, run tsidp locally and trust its issuer:

```bash
# Terminal 1: start tsidp locally
TAILSCALE_USE_WIP_CODE=1 go run . -local-port 4443

# Terminal 2: start OpenCloak, trusting the local tsidp
OPENCLOAK_TRUSTED_ISSUERS=http://localhost:4443 node cli.mjs start --port 3422
```

### Environment variables

| Variable | Description |
|----------|-------------|
| `OPENCLOAK_DATA_DIR` | Data directory path (default: `~/.config/opencloak`) |
| `OPENCLOAK_ENCRYPTION_KEY` | AES-256 key for encrypting secrets at rest |
| `OPENCLOAK_TRUSTED_ISSUERS` | Comma-separated trusted OIDC issuers (merged with defaults) |

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

## Architecture

```
┌──────────────┐     1      ┌──────────────┐     3      ┌──────────────┐
│   AI Agent   │ ──────────>│  OpenCloak   │ ──────────>│   Discord    │
│  (your bot)  │ <──────────│  (the vault) │ <──────────│     API      │
└──────────────┘     2      └──────────────┘     4      └──────────────┘
       │                          ▲
       │                          │
       └──────────────────────────┘
       │
       ▼
┌──────────────┐
│    tsidp     │
│  (identity   │
│    proof)    │
└──────────────┘
```

OpenCloak is the gateway/vault — it sits in the middle. The "agent" is whatever AI bot or service wants to talk to Discord (or any OAuth provider). In production, this is your actual AI bot running on your Tailscale network.

### What happens step by step

| Step | Who | Does what |
|------|-----|-----------|
| 1 | Agent -> tsidp | "Prove I'm on this Tailscale network" |
| 2 | Agent -> OpenCloak | "Here's my identity proof, give me Discord access" (`POST /token`, RFC 8693) |
| 3 | OpenCloak internally | Verifies identity, checks policy, fetches scoped token |
| 4 | Agent -> Discord | Uses the scoped token OpenCloak returned |

OpenCloak is the gateway that:
- Verifies the agent's Tailscale identity
- Checks if the agent is **allowed** to access Discord (policy)
- Returns only the **minimum access** needed (e.g., just a webhook, not full API)

The agent never sees your Discord OAuth credentials. It only gets back what OpenCloak's policy allows.

### In production, your AI bot's code would look like:

```javascript
// 1. Get my Tailscale identity token
const idToken = await getTsidpToken();

// 2. Ask OpenCloak for Discord access
const response = await fetch("http://opencloak:3422/token", {
  method: "POST",
  body: new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    actor_token: idToken,
    actor_token_type: "urn:ietf:params:oauth:token-type:id_token",
    resource: "https://discord.com/api",
    scope: "webhook.incoming"
  })
});

// 3. Post to Discord with the scoped token OpenCloak gave me
const { webhook_url } = await response.json();
await fetch(webhook_url, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ content: "Hello from my AI agent!" })
});
```

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
