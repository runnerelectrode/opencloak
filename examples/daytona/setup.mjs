#!/usr/bin/env node

/**
 * OpenCloak + Daytona Demo
 *
 * This script provisions a Daytona sandbox, installs OpenCloak inside it,
 * configures OAuth providers, and demonstrates how an agent running in
 * the sandbox can request scoped tokens without ever seeing long-lived credentials.
 *
 * Prerequisites:
 *   - Daytona account + API key (https://app.daytona.io)
 *   - Discord/GitHub OAuth app credentials
 *
 * Usage:
 *   export DAYTONA_API_KEY=your-daytona-key
 *   export GITHUB_CLIENT_ID=your-github-client-id
 *   export GITHUB_CLIENT_SECRET=your-github-client-secret
 *   node examples/daytona/setup.mjs
 */

import { Daytona } from "@daytonaio/sdk";

const DAYTONA_API_KEY = process.env.DAYTONA_API_KEY;
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;

if (!DAYTONA_API_KEY) {
  console.error("Missing DAYTONA_API_KEY. Get one at https://app.daytona.io/dashboard/keys");
  process.exit(1);
}

async function run(sandbox, cmd) {
  console.log(`  $ ${cmd}`);
  const res = await sandbox.process.executeCommand(cmd);
  if (res.result?.trim()) console.log(`    ${res.result.trim()}`);
  if (res.exitCode !== 0) {
    console.error(`    [exit ${res.exitCode}]`);
  }
  return res;
}

async function main() {
  console.log("\n=== OpenCloak + Daytona Demo ===\n");

  // --- Step 1: Create Daytona sandbox ---
  console.log("1. Creating Daytona sandbox...");
  const daytona = new Daytona({ apiKey: DAYTONA_API_KEY });

  const sandbox = await daytona.create({
    language: "javascript",
    env_vars: {
      NODE_ENV: "production",
    },
  });

  console.log(`   Sandbox created: ${sandbox.id}\n`);

  // --- Step 2: Install OpenCloak inside the sandbox ---
  console.log("2. Installing OpenCloak inside the sandbox...");
  await run(sandbox, "git clone https://github.com/runnerelectrode/opencloak.git /home/daytona/opencloak");
  await run(sandbox, "cd /home/daytona/opencloak && npm install 2>/dev/null || true");
  console.log();

  // --- Step 3: Start the OpenCloak vault server ---
  console.log("3. Starting OpenCloak vault server...");
  await run(sandbox, "cd /home/daytona/opencloak && node cli.mjs start --data-dir /home/daytona/opencloak-data --port 3422 &");
  // Give it a moment to start
  await run(sandbox, "sleep 2");
  const health = await run(sandbox, "curl -s http://localhost:3422/health");
  console.log();

  // --- Step 4: Register OAuth providers ---
  console.log("4. Registering OAuth providers...");

  if (GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET) {
    await run(sandbox, [
      "cd /home/daytona/opencloak && node cli.mjs add-provider github",
      `--client-id ${GITHUB_CLIENT_ID}`,
      `--client-secret ${GITHUB_CLIENT_SECRET}`,
      "--authorize-url https://github.com/login/oauth/authorize",
      "--token-url https://github.com/login/oauth/access_token",
      "--resource-uri https://api.github.com",
      "--data-dir /home/daytona/opencloak-data",
    ].join(" "));
  } else {
    console.log("   Skipping GitHub (no GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET set)");
    // Register a demo Discord provider as fallback example
    await run(sandbox, [
      "cd /home/daytona/opencloak && node cli.mjs add-provider discord",
      "--client-id demo-client-id",
      "--client-secret demo-client-secret",
      "--data-dir /home/daytona/opencloak-data",
    ].join(" "));
  }
  console.log();

  // --- Step 5: Register an agent identity ---
  console.log("5. Registering sandbox as an agent...");
  await run(sandbox, [
    "cd /home/daytona/opencloak && node cli.mjs register-agent",
    `--identity sandbox:${sandbox.id}`,
    "--data-dir /home/daytona/opencloak-data",
  ].join(" "));
  console.log();

  // --- Step 6: Set agent policy ---
  console.log("6. Setting agent policy...");
  const provider = GITHUB_CLIENT_ID ? "github" : "discord";
  const scopes = GITHUB_CLIENT_ID ? "repo,read:user" : "identify,guilds";
  await run(sandbox, [
    `cd /home/daytona/opencloak && node cli.mjs policy set sandbox:${sandbox.id} ${provider}`,
    `--scopes "${scopes}"`,
    "--data-dir /home/daytona/opencloak-data",
  ].join(" "));
  console.log();

  // --- Step 7: Show what the agent sees ---
  console.log("7. Listing configured resources...");
  await run(sandbox, "cd /home/daytona/opencloak && node cli.mjs list --data-dir /home/daytona/opencloak-data");
  console.log();

  // --- Step 8: Show the token exchange endpoint ---
  console.log("8. OpenCloak is ready. An agent in this sandbox can now request tokens:\n");
  console.log(`   curl -X POST http://localhost:3422/token \\`);
  console.log(`     -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \\`);
  console.log(`     -d "actor_token=<IDENTITY_TOKEN>" \\`);
  console.log(`     -d "actor_token_type=urn:ietf:params:oauth:token-type:id_token" \\`);
  console.log(`     -d "resource=https://api.github.com" \\`);
  console.log(`     -d "scope=repo"`);
  console.log();
  console.log(`   The agent never sees the GitHub OAuth credentials.`);
  console.log(`   OpenCloak checks policy and returns only what the agent is allowed to access.\n`);

  // --- Cleanup instructions ---
  console.log("=== Sandbox Info ===");
  console.log(`   ID:     ${sandbox.id}`);
  console.log(`   Vault:  http://localhost:3422 (inside sandbox)`);
  console.log(`   Data:   /home/daytona/opencloak-data`);
  console.log();
  console.log("   To keep the sandbox running, don't call sandbox.delete()");
  console.log("   To clean up: sandbox.delete() or delete from Daytona dashboard\n");
}

main().catch((err) => {
  console.error("Demo failed:", err.message);
  process.exit(1);
});
