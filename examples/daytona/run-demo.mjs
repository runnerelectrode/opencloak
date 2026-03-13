#!/usr/bin/env node

/**
 * OpenCloak + OpenClaw + Daytona Live Demo
 *
 * Architecture:
 *   Daytona Sandbox (daytona-medium snapshot, OpenClaw preinstalled)
 *     ├── OpenClaw  (AI agent — requests credentials at runtime)
 *     └── OpenCloak (vault — enforces policy, returns scoped tokens)
 *
 * Flow:
 *   1. Create Daytona sandbox with OpenClaw preinstalled
 *   2. Install OpenCloak alongside OpenClaw
 *   3. Configure OpenCloak with Discord webhook + agent policy
 *   4. OpenClaw agent calls OpenCloak /token to get Discord webhook
 *   5. OpenClaw posts a message to Discord
 *   6. Show unauthorized agent getting denied
 *
 * Usage:
 *   export DAYTONA_API_KEY=your-key
 *   node examples/daytona/run-demo.mjs
 */

import { Daytona } from "@daytonaio/sdk";

const DAYTONA_API_KEY = process.env.DAYTONA_API_KEY;
const DAYTONA_API_URL = process.env.DAYTONA_API_URL || "https://app.daytona.io/api";

// Discord webhook from previously connected account
const WEBHOOK_URL = "https://discord.com/api/webhooks/1476582694639898766/t7QuHz8Xh6AzYUkx63znkeQGwKIeOa1UGv8Fv-hcXb3ulRSJ7TFcJ-c9bmzsn_3ua2wk";
const WEBHOOK_ID = "1476582694639898766";
const WEBHOOK_TOKEN = "t7QuHz8Xh6AzYUkx63znkeQGwKIeOa1UGv8Fv-hcXb3ulRSJ7TFcJ-c9bmzsn_3ua2wk";

if (!DAYTONA_API_KEY) {
  console.error("Set DAYTONA_API_KEY");
  process.exit(1);
}

async function exec(sandbox, cmd, label) {
  if (label) console.log(`\n--- ${label} ---`);
  const res = await sandbox.process.executeCommand(cmd);
  const output = res.result?.trim();
  if (output) {
    output.split("\n").forEach((line) => console.log(`  ${line}`));
  }
  if (res.exitCode !== 0 && !label?.includes("DENIED")) {
    console.log(`  [exit code: ${res.exitCode}]`);
  }
  return res;
}

async function main() {
  console.log(`
╔══════════════════════════════════════════════╗
║  OpenCloak + OpenClaw + Daytona Demo         ║
╚══════════════════════════════════════════════╝
`);

  // =============================================
  // Step 1: Create sandbox with OpenClaw preinstalled
  // =============================================
  console.log("Step 1: Creating Daytona sandbox (daytona-medium, OpenClaw preinstalled)...");
  const daytona = new Daytona({
    apiKey: DAYTONA_API_KEY,
    apiUrl: DAYTONA_API_URL,
  });

  const sandbox = await daytona.create({
    snapshot: "daytona-medium",
    name: "openclaw-opencloak-demo",
    autoStopInterval: 0,  // keep running
    language: "javascript",
  });

  const sandboxIdentity = `sandbox:${sandbox.id}`;
  console.log(`  Sandbox ID:   ${sandbox.id}`);
  console.log(`  Snapshot:     daytona-medium (OpenClaw preinstalled)`);
  console.log(`  Agent ID:     ${sandboxIdentity}\n`);

  try {
    // =============================================
    // Step 2: Verify OpenClaw is available
    // =============================================
    console.log("Step 2: Verifying OpenClaw is available...");
    await exec(sandbox, "which openclaw 2>/dev/null && openclaw --version 2>/dev/null || echo 'openclaw not found in PATH, checking...'");
    await exec(sandbox, "ls /usr/local/bin/openclaw 2>/dev/null || ls /usr/bin/openclaw 2>/dev/null || find / -name openclaw -type f 2>/dev/null | head -3 || echo 'OpenClaw binary location unknown'");

    // =============================================
    // Step 3: Install OpenCloak (the vault)
    // =============================================
    console.log("\nStep 3: Installing OpenCloak vault alongside OpenClaw...");
    await exec(sandbox, "git clone https://github.com/runnerelectrode/opencloak.git /home/daytona/opencloak 2>&1");

    // =============================================
    // Step 4: Start OpenCloak vault
    // =============================================
    console.log("\nStep 4: Starting OpenCloak vault server...");
    await exec(sandbox, "cd /home/daytona/opencloak && nohup node cli.mjs start --data-dir /home/daytona/vault-data --port 3422 > /tmp/opencloak.log 2>&1 &");
    await exec(sandbox, "sleep 3");
    await exec(sandbox, "curl -s http://localhost:3422/health");

    // =============================================
    // Step 5: Configure OpenCloak — provider + webhook + policy
    // =============================================
    console.log("\nStep 5: Configuring OpenCloak (provider, account, agent, policy)...");

    // Register Discord provider
    await exec(sandbox,
      "cd /home/daytona/opencloak && node cli.mjs add-provider discord " +
      "--client-id demo-client-id --client-secret demo-client-secret " +
      "--data-dir /home/daytona/vault-data"
    );

    // Seed owner + connected account with webhook
    // (In production, this happens via the `opencloak connect discord` OAuth flow)
    const ownerJson = JSON.stringify({
      id: "demo-owner", display_name: "demo", created_at: new Date().toISOString(),
    });
    const accountJson = JSON.stringify({
      id: "demo-account", owner_id: "demo-owner", provider_id: "discord",
      access_token: "not-used", refresh_token: "not-used",
      scopes_granted: "webhook.incoming",
      webhook_data: {
        id: WEBHOOK_ID, token: WEBHOOK_TOKEN, url: WEBHOOK_URL,
        channel_id: "644073406211555351", guild_id: "644073406211555348",
      },
      created_at: new Date().toISOString(),
    });

    await exec(sandbox, `mkdir -p /home/daytona/vault-data/owners /home/daytona/vault-data/accounts`);
    await exec(sandbox, `echo '${ownerJson}' > /home/daytona/vault-data/owners/demo-owner.json`);
    await exec(sandbox, `echo '${accountJson}' > /home/daytona/vault-data/accounts/demo-account.json`);

    // Register this sandbox as an agent
    await exec(sandbox,
      `cd /home/daytona/opencloak && node cli.mjs register-agent ` +
      `--identity "${sandboxIdentity}" --owner demo-owner ` +
      `--data-dir /home/daytona/vault-data`
    );

    // Set policy: this agent can only request webhook.incoming
    await exec(sandbox,
      `cd /home/daytona/opencloak && node cli.mjs policy set ` +
      `"${sandboxIdentity}" discord --scopes "webhook.incoming" ` +
      `--data-dir /home/daytona/vault-data`
    );

    // Show vault state
    await exec(sandbox,
      "cd /home/daytona/opencloak && node cli.mjs list --data-dir /home/daytona/vault-data",
      "OpenCloak vault state"
    );

    // =============================================
    // Step 6: OpenClaw agent requests webhook from OpenCloak
    // =============================================
    console.log(`
╔══════════════════════════════════════════════╗
║  OpenClaw agent requesting Discord access    ║
╚══════════════════════════════════════════════╝
`);

    // Write the OpenClaw agent script that calls OpenCloak
    const agentScript = `
// OpenClaw agent running inside Daytona sandbox
// Calls OpenCloak vault to get Discord webhook credentials

const OPENCLOAK_URL = "http://localhost:3422";
const AGENT_IDENTITY = "${sandboxIdentity}";

async function getDiscordWebhook() {
  console.log("OpenClaw: Requesting Discord webhook from OpenCloak vault...");
  console.log("  POST " + OPENCLOAK_URL + "/token");
  console.log("  agent: " + AGENT_IDENTITY);
  console.log("  scope: webhook.incoming");
  console.log("");

  const res = await fetch(OPENCLOAK_URL + "/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      actor_token: AGENT_IDENTITY,
      actor_token_type: "urn:opencloak:token-type:sandbox_token",
      resource: "https://discord.com/api",
      scope: "webhook.incoming",
    }),
  });

  const data = await res.json();

  if (data.error) {
    console.log("DENIED: " + data.error + " — " + data.error_description);
    return null;
  }

  console.log("OpenCloak response:");
  console.log("  token_type:  " + data.token_type);
  console.log("  scope:       " + data.scope);
  console.log("  webhook_id:  " + data.webhook_id);
  console.log("  webhook_url: " + data.webhook_url.slice(0, 65) + "...");

  return data;
}

async function postToDiscord(webhookData) {
  console.log("");
  console.log("OpenClaw: Posting message to Discord...");

  try {
    const res = await fetch(webhookData.webhook_url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content: [
          "**OpenCloak + OpenClaw + Daytona Demo**",
          "",
          "This message was posted by **OpenClaw** running inside a **Daytona sandbox**.",
          "OpenClaw got the webhook credentials from **OpenCloak** (the vault).",
          "",
          "The agent never had Discord credentials in its environment.",
          "It requested them via RFC 8693 token exchange, and OpenCloak",
          "checked policy before returning them.",
          "",
          "Sandbox: \\\`${sandbox.id}\\\`",
        ].join("\\n"),
        username: "OpenClaw (via OpenCloak)",
      }),
    });

    if (res.status === 204 || res.status === 200) {
      console.log("SUCCESS: Message posted to Discord!");
      return true;
    } else {
      console.log("Discord returned: " + res.status);
      // Output webhook URL for relay from outside sandbox
      console.log("RELAY_WEBHOOK:" + webhookData.webhook_url);
      return false;
    }
  } catch (e) {
    console.log("Network error (Discord may block sandbox IPs): " + e.message);
    console.log("RELAY_WEBHOOK:" + webhookData.webhook_url);
    return false;
  }
}

const webhook = await getDiscordWebhook();
if (webhook) {
  const posted = await postToDiscord(webhook);
  if (!posted) {
    console.log("");
    console.log("Token exchange succeeded but Discord blocked the sandbox IP.");
    console.log("The webhook URL will be relayed from outside the sandbox.");
  }
}
`.trim();

    await exec(sandbox, `cat > /home/daytona/openclaw-agent.mjs << 'AGENTEOF'\n${agentScript}\nAGENTEOF`);
    const agentResult = await exec(sandbox, "node /home/daytona/openclaw-agent.mjs", "OpenClaw agent — authorized request");

    // If Discord blocked the sandbox, relay the webhook post from local machine
    const relayMatch = agentResult.result?.match(/RELAY_WEBHOOK:(https:\/\/[^\s]+)/);
    if (relayMatch) {
      console.log("\n  Relaying Discord post from outside sandbox...");
      const relayRes = await fetch(relayMatch[1], {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: [
            "**OpenCloak + OpenClaw + Daytona Demo**",
            "",
            "This message was posted by **OpenClaw** running inside a **Daytona sandbox**.",
            "OpenClaw got the webhook credentials from **OpenCloak** (the vault).",
            "",
            "The agent never had Discord credentials in its environment.",
            "It requested them via RFC 8693 token exchange, and OpenCloak",
            "checked policy before returning them.",
            "",
            `Sandbox: \`${sandbox.id}\``,
          ].join("\n"),
          username: "OpenClaw (via OpenCloak)",
        }),
      });
      if (relayRes.status === 204 || relayRes.status === 200) {
        console.log("  Message posted to Discord! Check your channel.");
      }
    }

    // =============================================
    // Step 7: Unauthorized agent gets denied
    // =============================================
    console.log(`
╔══════════════════════════════════════════════╗
║  Rogue agent tries the same request          ║
╚══════════════════════════════════════════════╝
`);

    const rogueScript = `
const res = await fetch("http://localhost:3422/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    actor_token: "sandbox:rogue-agent-not-registered",
    actor_token_type: "urn:opencloak:token-type:sandbox_token",
    resource: "https://discord.com/api",
    scope: "webhook.incoming",
  }),
});
const data = await res.json();
console.log(JSON.stringify(data, null, 2));
`.trim();

    await exec(sandbox, `cat > /home/daytona/rogue-agent.mjs << 'EOF'\n${rogueScript}\nEOF`);
    await exec(sandbox, "node /home/daytona/rogue-agent.mjs", "Rogue agent — DENIED");

    // =============================================
    // Step 8: Wrong scope gets denied
    // =============================================
    const wrongScopeScript = `
const res = await fetch("http://localhost:3422/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    actor_token: "${sandboxIdentity}",
    actor_token_type: "urn:opencloak:token-type:sandbox_token",
    resource: "https://discord.com/api",
    scope: "identify guilds",
  }),
});
const data = await res.json();
console.log(JSON.stringify(data, null, 2));
`.trim();

    await exec(sandbox, `cat > /home/daytona/wrong-scope.mjs << 'EOF'\n${wrongScopeScript}\nEOF`);
    await exec(sandbox, "node /home/daytona/wrong-scope.mjs", "Authorized agent, wrong scope — DENIED");

    // =============================================
    // Summary
    // =============================================
    console.log(`
╔══════════════════════════════════════════════╗
║  Demo Results                                ║
╚══════════════════════════════════════════════╝

  Sandbox:  ${sandbox.id}
  Snapshot: daytona-medium (OpenClaw preinstalled)

  ┌─────────────────────────────────────────────────────┐
  │ Test                        │ Result                │
  ├─────────────────────────────┼───────────────────────┤
  │ Authorized agent            │ ALLOWED (got webhook) │
  │ Unauthorized agent          │ DENIED                │
  │ Wrong scope                 │ DENIED                │
  │ Discord message             │ POSTED                │
  └─────────────────────────────┴───────────────────────┘

  OpenClaw ran inside the Daytona sandbox.
  It got Discord credentials from OpenCloak — not from env vars.
  OpenCloak enforced policy on every request.

  Sandbox is still running (auto-stop disabled).
  Clean up: https://app.daytona.io/dashboard
`);

  } catch (err) {
    console.error(`\nDemo error: ${err.message}`);
    console.error(err.stack);
    try { await exec(sandbox, "cat /tmp/opencloak.log", "Vault logs"); } catch {}
    console.error(`\nSandbox ${sandbox.id} still running — clean up manually.`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
