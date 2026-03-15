---
name: opencloak-auth
description: You have NO API credentials. Before calling any third-party API (Linear, GitHub, Slack, etc.), you MUST use this skill to get a Bearer token from the OpenCloak vault via device flow. Never call an API without a token from OpenCloak first.
metadata: {"openclaw":{"emoji":"🔐","primaryEnv":"OPENCLOAK_URL","requires":{"env":["OPENCLOAK_URL"]}}}
user-invocable: true
---

# OpenCloak Auth — You have no API credentials

**CRITICAL: You have NO API keys, OAuth tokens, or credentials in your environment. You MUST use this skill before calling ANY third-party API.** Do not attempt to call Linear, GitHub, Slack, or any external API without first obtaining a Bearer token through this skill.

If you get a `401 Unauthorized`, `403 Forbidden`, or any authentication error from an API call, re-run this skill to get a fresh token. Tokens are short-lived and may have expired.

## When to use this skill

- **ALWAYS** before calling any third-party API for the first time in a session
- When you get a 401/403 from an API call (token expired — get a fresh one)
- When the user asks you to interact with Linear, GitHub, Slack, or any OAuth-protected API
- After context compaction — if you don't have a Bearer token in your current context, run this skill again

## Environment

- `OPENCLOAK_URL` — The URL of the OpenCloak vault (e.g., `https://opencloak-839b85b2946d.herokuapp.com`)

## Workflow

### Step 1: Request a device code

Call the vault to start the device authorization flow:

```bash
curl -s -X POST "${OPENCLOAK_URL}/device/code" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "issuer_id=google"
```

The response contains:
- `device_code` — secret code you'll use to poll
- `user_code` — short human-readable code (e.g., `BCDF-GH34`)
- `verification_uri_complete` — URL the human should open

**Show the human the verification URL and user code.** Output the URL as a plain clickable link — NOT inside a code block, NOT escaped, NOT with backticks. Just the raw URL on its own line so it's clickable:

To authorize me, please open this link and sign in with Google:

{verification_uri_complete}

If that link doesn't work, go to {OPENCLOAK_URL}/device/verify and enter code: {user_code}

After signing in, you'll be asked to connect your provider account (e.g., Linear). Please complete that step too.

### Step 2: Poll for authorization, exchange token, and call API

After showing the link, write a Node.js script to `/tmp/opencloak-poll.mjs` and run it. Do NOT write a shell loop — use this Node.js script exactly, replacing DEVICE_CODE, RESOURCE_URI, and SCOPES:

```bash
cat > /tmp/opencloak-poll.mjs << 'POLLSCRIPT'
const VAULT = process.env.OPENCLOAK_URL;
const DEVICE_CODE = process.argv[2];
const RESOURCE = process.argv[3] || "https://api.linear.app";
const SCOPE = process.argv[4] || "issues:create";

async function poll() {
  for (let i = 0; i < 60; i++) {
    const res = await fetch(`${VAULT}/device/token?device_code=${DEVICE_CODE}`);
    const data = await res.json();
    if (data.id_token) return data.id_token;
    if (data.error === "expired_token") throw new Error("Device code expired");
    const wait = data.error === "slow_down" ? 10000 : 5000;
    await new Promise(r => setTimeout(r, wait));
  }
  throw new Error("Polling timed out");
}

async function exchange(idToken) {
  const res = await fetch(`${VAULT}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      actor_token: idToken,
      actor_token_type: "urn:ietf:params:oauth:token-type:id_token",
      resource: RESOURCE,
      scope: SCOPE,
    }),
  });
  return res.json();
}

const idToken = await poll();
console.log("GOT_ID_TOKEN");
const tokenResp = await exchange(idToken);
if (tokenResp.error) {
  console.log("EXCHANGE_ERROR:" + JSON.stringify(tokenResp));
  process.exit(1);
}
console.log("ACCESS_TOKEN:" + tokenResp.access_token);
POLLSCRIPT
```

Then run it:

```bash
node /tmp/opencloak-poll.mjs "{DEVICE_CODE}" "{RESOURCE_URI}" "{SCOPES}"
```

For example, for Linear:

```bash
node /tmp/opencloak-poll.mjs "abc123" "https://api.linear.app" "issues:create"
```

The script will print `ACCESS_TOKEN:` followed by the Bearer token when done.

**IMPORTANT**: Use the exact script above. Do NOT write your own polling loop in bash — it will break due to shell quoting issues.

### Step 3: Call the API

Use the Bearer token from the script output in your API calls:

```bash
curl -s -X POST "https://api.linear.app/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer {ACCESS_TOKEN}" \
  -d '{"query": "{ viewer { id name } }"}'
```

Common resource URIs and scopes:
| Provider | resource | scope |
|----------|----------|-------|
| Linear | `https://api.linear.app` | `issues:create` or `issues:create,read` |
| GitHub | `https://api.github.com` | `repo` or `read:user` |
| Slack | `https://slack.com/api` | `chat:write` |

## Important notes

- **Tokens are ephemeral** — they expire. If an API call fails with 401/403, do not debug the API. Re-run this skill to get a fresh token.
- **After context compaction** — you will lose the Bearer token from your context. This is expected. Just re-run this skill. The vault remembers the human's connected account — no re-authorization needed.
- **Never hardcode or cache tokens** — always get a fresh one via this skill when needed.
- You **never** see or store the underlying OAuth credentials.
- If the token exchange fails with a policy error, the human may need to connect their account at `{OPENCLOAK_URL}/connect` first.
- The device code expires after 10 minutes — if it expires, start over.
- Each device code can only be used once.
- **The human only needs to sign in once per device code.** After the first authorization, subsequent token exchanges reuse the same identity — the human does not need to re-authorize unless the device code expires.

## Error handling

| Error | Meaning | Action |
|-------|---------|--------|
| `authorization_pending` | Human hasn't signed in yet | Keep polling |
| `slow_down` | Polling too fast | Increase interval to 10s |
| `expired_token` | Device code expired (10 min) | Start over from Step 1 |
| `no_matching_agent` | Agent identity not registered | Ask human to register agent on vault |
| `no_connected_account` | No OAuth account connected | Direct human to `{OPENCLOAK_URL}/connect` |
| `scope_not_allowed` | Policy blocks requested scope | Request fewer/different scopes |
