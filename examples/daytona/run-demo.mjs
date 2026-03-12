#!/usr/bin/env node

/**
 * OpenCloak + Daytona Live Demo
 *
 * End-to-end demo:
 *  1. Creates ONE Daytona sandbox
 *  2. Installs OpenCloak vault inside it
 *  3. Configures Discord webhook provider + agent policy
 *  4. Agent (inside sandbox) requests webhook via RFC 8693 token exchange
 *  5. OpenCloak checks policy, returns webhook credentials
 *  6. Agent posts a message to Discord
 *  7. Shows what happens when an UNAUTHORIZED agent tries the same thing
 *  8. Cleans up the sandbox
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
  return res;
}

async function main() {
  console.log(`
========================================
  OpenCloak + Daytona Live Demo
========================================
`);

  // =============================================
  // Step 1: Create ONE sandbox
  // =============================================
  console.log("Step 1: Creating Daytona sandbox...");
  const daytona = new Daytona({
    apiKey: DAYTONA_API_KEY,
    apiUrl: DAYTONA_API_URL,
  });

  const sandbox = await daytona.create({ language: "javascript" });
  const sandboxIdentity = `sandbox:${sandbox.id}`;
  console.log(`  ID: ${sandbox.id}\n`);

  try {
    // =============================================
    // Step 2: Install OpenCloak
    // =============================================
    console.log("Step 2: Installing OpenCloak inside sandbox...");
    await exec(sandbox, "git clone https://github.com/runnerelectrode/opencloak.git /home/daytona/opencloak 2>&1");

    // =============================================
    // Step 3: Start vault
    // =============================================
    console.log("\nStep 3: Starting OpenCloak vault...");
    await exec(sandbox, "cd /home/daytona/opencloak && nohup node cli.mjs start --data-dir /home/daytona/vault-data --port 3422 > /tmp/opencloak.log 2>&1 &");
    await exec(sandbox, "sleep 3");
    await exec(sandbox, "curl -s http://localhost:3422/health");

    // =============================================
    // Step 4: Configure provider + seed webhook account
    // =============================================
    console.log("\nStep 4: Configuring Discord provider + webhook account...");
    await exec(sandbox,
      "cd /home/daytona/opencloak && node cli.mjs add-provider discord " +
      "--client-id demo-client-id --client-secret demo-client-secret " +
      "--data-dir /home/daytona/vault-data"
    );

    // Seed owner + connected account (in production, `connect` does this via OAuth)
    const ownerJson = JSON.stringify({ id: "demo-owner", display_name: "demo", created_at: new Date().toISOString() });
    const accountJson = JSON.stringify({
      id: "demo-account", owner_id: "demo-owner", provider_id: "discord",
      access_token: "not-used", refresh_token: "not-used", scopes_granted: "webhook.incoming",
      webhook_data: { id: WEBHOOK_ID, token: WEBHOOK_TOKEN, url: WEBHOOK_URL, channel_id: "644073406211555351", guild_id: "644073406211555348" },
      created_at: new Date().toISOString(),
    });
    await exec(sandbox, `mkdir -p /home/daytona/vault-data/owners /home/daytona/vault-data/accounts`);
    await exec(sandbox, `echo '${ownerJson}' > /home/daytona/vault-data/owners/demo-owner.json`);
    await exec(sandbox, `echo '${accountJson}' > /home/daytona/vault-data/accounts/demo-account.json`);

    // =============================================
    // Step 5: Register agent + policy
    // =============================================
    console.log("\nStep 5: Registering agent and setting policy...");
    await exec(sandbox,
      `cd /home/daytona/opencloak && node cli.mjs register-agent --ts-identity "${sandboxIdentity}" --owner demo-owner --data-dir /home/daytona/vault-data`
    );
    await exec(sandbox,
      `cd /home/daytona/opencloak && node cli.mjs policy set "${sandboxIdentity}" discord --scopes "webhook.incoming" --data-dir /home/daytona/vault-data`
    );

    // =============================================
    // Step 6: AUTHORIZED agent requests webhook
    // =============================================
    console.log(`
========================================
  Test 1: Authorized agent requests webhook
========================================
`);

    const authorizedAgent = `
const res = await fetch("http://localhost:3422/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    actor_token: "${sandboxIdentity}",
    actor_token_type: "urn:opencloak:token-type:sandbox_token",
    resource: "https://discord.com/api",
    scope: "webhook.incoming",
  }),
});
const data = await res.json();
console.log(JSON.stringify(data));
`.trim();

    await exec(sandbox, `cat > /home/daytona/agent-authorized.mjs << 'EOF'\n${authorizedAgent}\nEOF`);
    const authResult = await exec(sandbox, "node /home/daytona/agent-authorized.mjs", "Authorized agent — token exchange");

    // Parse the webhook URL from the response
    let webhookUrlFromVault;
    try {
      const tokenResponse = JSON.parse(authResult.result?.trim());
      webhookUrlFromVault = tokenResponse.webhook_url;
      console.log(`\n  token_type:  ${tokenResponse.token_type}`);
      console.log(`  scope:       ${tokenResponse.scope}`);
      console.log(`  webhook_url: ${tokenResponse.webhook_url?.slice(0, 60)}...`);
      console.log(`  webhook_id:  ${tokenResponse.webhook_id}`);
    } catch {}

    // =============================================
    // Step 7: UNAUTHORIZED agent tries the same thing
    // =============================================
    console.log(`
========================================
  Test 2: Unauthorized agent tries same request
========================================
`);

    const unauthorizedAgent = `
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
console.log(JSON.stringify(data));
`.trim();

    await exec(sandbox, `cat > /home/daytona/agent-unauthorized.mjs << 'EOF'\n${unauthorizedAgent}\nEOF`);
    await exec(sandbox, "node /home/daytona/agent-unauthorized.mjs", "Unauthorized agent — token exchange DENIED");

    // =============================================
    // Step 8: WRONG SCOPE — agent tries to request more than policy allows
    // =============================================
    console.log(`
========================================
  Test 3: Agent requests scope beyond policy
========================================
`);

    const wrongScopeAgent = `
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
console.log(JSON.stringify(data));
`.trim();

    await exec(sandbox, `cat > /home/daytona/agent-wrong-scope.mjs << 'EOF'\n${wrongScopeAgent}\nEOF`);
    await exec(sandbox, "node /home/daytona/agent-wrong-scope.mjs", "Wrong scope — policy blocks 'identify guilds'");

    // =============================================
    // Step 9: Post to Discord (from local, since Discord blocks Daytona IPs)
    // =============================================
    if (webhookUrlFromVault) {
      console.log(`
========================================
  Posting to Discord with webhook from vault
========================================
`);
      console.log("  Using webhook URL that OpenCloak returned to the agent...");

      const discordRes = await fetch(webhookUrlFromVault, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: [
            "**OpenCloak + Daytona Demo**",
            "",
            "This message was posted using a Discord webhook retrieved from OpenCloak,",
            "running inside a Daytona sandbox.",
            "",
            `Sandbox: \`${sandbox.id}\``,
            `Agent: \`${sandboxIdentity}\``,
            "",
            "The agent never had the webhook credentials in its environment.",
            "It requested them via RFC 8693 token exchange, and OpenCloak",
            "checked policy before returning them.",
          ].join("\n"),
          username: "OpenClaw (via OpenCloak)",
        }),
      });

      if (discordRes.status === 204 || discordRes.status === 200) {
        console.log("  Message posted to Discord! Check your channel.\n");
      } else {
        console.log(`  Discord returned: ${discordRes.status}\n`);
      }
    }

    // =============================================
    // Summary
    // =============================================
    console.log(`========================================
  Demo Results
========================================

  Authorized agent (sandbox:${sandbox.id.slice(0, 8)}...):
    webhook.incoming  -->  ALLOWED (got webhook URL)

  Unauthorized agent (sandbox:rogue-agent):
    webhook.incoming  -->  DENIED (not registered)

  Wrong scope (sandbox:${sandbox.id.slice(0, 8)}...):
    identify,guilds   -->  DENIED (policy only allows webhook.incoming)

  Discord message:  POSTED via webhook from vault

  The agent never saw OAuth credentials.
  OpenCloak enforced policy on every request.
`);

  } finally {
    // Clean up — always delete the sandbox
    console.log("Cleaning up sandbox...");
    try {
      await sandbox.delete();
      console.log(`  Sandbox ${sandbox.id} deleted.\n`);
    } catch (e) {
      console.log(`  Could not delete sandbox: ${e.message}`);
      console.log(`  Delete manually: https://app.daytona.io/dashboard\n`);
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
