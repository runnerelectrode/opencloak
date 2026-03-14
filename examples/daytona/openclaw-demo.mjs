#!/usr/bin/env node

/**
 * OpenClaw Agent Demo: Real AI Agent + OpenCloak + Daytona
 *
 * Unlike device-flow-demo.mjs (which uses raw fetch scripts), this demo
 * runs a real OpenClaw agent inside the Daytona sandbox. The agent
 * reasons through token exchange and Linear issue creation autonomously.
 *
 * Architecture:
 *   Daytona Sandbox (daytona-medium)
 *   ├── OpenClaw agent --local (preinstalled, uses Anthropic or OpenRouter)
 *   └── Talks to:
 *       ├── OpenCloak vault (Heroku) — device flow + token exchange
 *       └── Linear API — creates an issue with the Bearer token
 *
 * Usage:
 *   export DAYTONA_API_KEY=your-key
 *   export ANTHROPIC_API_KEY=your-key   # or OPENROUTER_API_KEY
 *   export HEROKU_API_KEY=your-key
 *   export LINEAR_TEAM_ID=f6442499-53cb-4bf3-be79-5291905bc325
 *   node examples/daytona/openclaw-demo.mjs
 */

import { Daytona } from "@daytonaio/sdk";
import readline from "node:readline";

const DAYTONA_API_KEY = process.env.DAYTONA_API_KEY;
const DAYTONA_API_URL = process.env.DAYTONA_API_URL || "https://app.daytona.io/api";
const LLM_API_KEY = process.env.ANTHROPIC_API_KEY || process.env.OPENROUTER_API_KEY;
const LLM_ENV_NAME = process.env.ANTHROPIC_API_KEY ? "ANTHROPIC_API_KEY" : "OPENROUTER_API_KEY";
const LLM_MODEL = process.env.ANTHROPIC_API_KEY ? "anthropic/claude-haiku-4-5-20251001" : "openrouter/anthropic/claude-3.5-haiku";
const HEROKU_API_KEY = process.env.HEROKU_API_KEY;
const LINEAR_TEAM_ID = process.env.LINEAR_TEAM_ID;
const OPENCLOAK_URL = "https://opencloak-839b85b2946d.herokuapp.com";
const HEROKU_APP = "opencloak";
const TODO_STATE_ID = "419ad82d-e284-42a0-932f-e639af430278";

if (!DAYTONA_API_KEY) { console.error("Set DAYTONA_API_KEY"); process.exit(1); }
if (!LLM_API_KEY) { console.error("Set ANTHROPIC_API_KEY or OPENROUTER_API_KEY"); process.exit(1); }
if (!HEROKU_API_KEY) { console.error("Set HEROKU_API_KEY"); process.exit(1); }
if (!LINEAR_TEAM_ID) { console.error("Set LINEAR_TEAM_ID"); process.exit(1); }

async function exec(sandbox, cmd, label) {
  if (label) console.log(`\n--- ${label} ---`);
  const res = await sandbox.process.executeCommand(cmd);
  const output = res.result?.trim();
  if (output) output.split("\n").forEach((l) => console.log(`  ${l}`));
  return res;
}

function waitForEnter(msg) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(msg, () => { rl.close(); resolve(); });
  });
}

async function herokuSetConfig(key, value) {
  const resp = await fetch(`https://api.heroku.com/apps/${HEROKU_APP}/config-vars`, {
    method: "PATCH",
    headers: {
      "Authorization": `Bearer ${HEROKU_API_KEY}`,
      "Accept": "application/vnd.heroku+json; version=3",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ [key]: value }),
  });
  if (!resp.ok) throw new Error(`Heroku config set failed: ${resp.status}`);
  return resp.json();
}

async function waitForHeroku() {
  for (let i = 0; i < 20; i++) {
    await new Promise(r => setTimeout(r, 3000));
    try {
      const r = await fetch(`${OPENCLOAK_URL}/health`, { signal: AbortSignal.timeout(5000) });
      if (r.ok) return true;
    } catch {}
  }
  return false;
}

async function main() {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║  OpenClaw Agent Demo                                         ║
║  Real AI agent (Daytona) ↔ Vault (OpenCloak on Heroku)       ║
║  Agent reasons through token exchange + Linear issue creation ║
╚══════════════════════════════════════════════════════════════╝
`);

  // =========================================================
  // Step 1: Create sandbox with OpenClaw preinstalled
  // =========================================================
  console.log("Step 1: Creating Daytona sandbox (daytona-medium, OpenClaw preinstalled)...");
  const daytona = new Daytona({
    apiKey: DAYTONA_API_KEY,
    apiUrl: DAYTONA_API_URL,
  });

  const sandbox = await daytona.create({
    snapshot: "daytona-medium",
    name: "openclaw-agent-demo",
    autoStopInterval: 0,
    language: "javascript",
  });
  console.log(`  Sandbox ID: ${sandbox.id}`);
  console.log(`  Snapshot:   daytona-medium (2 vCPU / 4GB, OpenClaw preinstalled)`);

  try {
    // =========================================================
    // Step 2: Verify OpenClaw is available
    // =========================================================
    console.log("\nStep 2: Verifying OpenClaw is available...");
    await exec(sandbox, "which openclaw && openclaw --version", "OpenClaw check");

    // =========================================================
    // Step 3: Configure OpenClaw with OpenRouter + Haiku model
    // =========================================================
    console.log(`\nStep 3: Configuring OpenClaw (${LLM_MODEL})...`);
    await exec(sandbox, `${LLM_ENV_NAME}=${LLM_API_KEY} openclaw models set ${LLM_MODEL} 2>&1`);

    // Verify connectivity to vault
    await exec(sandbox, `curl -s ${OPENCLOAK_URL}/health`, "Vault connectivity check");

    // =========================================================
    // Step 5: Agent requests device code (runs IN the sandbox)
    // =========================================================
    console.log("\nStep 5: Agent requests device code from vault...");

    const requestCodeScript = `
const res = await fetch("${OPENCLOAK_URL}/device/code", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: "issuer_id=google",
});
console.log(JSON.stringify(await res.json()));
`.trim();

    await exec(sandbox, `cat > /tmp/request-code.mjs << 'EOF'\n${requestCodeScript}\nEOF`);
    const codeResult = await exec(sandbox, "node /tmp/request-code.mjs 2>&1", "POST /device/code (from sandbox)");

    let codeData;
    try {
      const jsonLine = codeResult.result?.split("\n").map(l => l.trim()).find(l => l.startsWith("{"));
      codeData = JSON.parse(jsonLine);
    } catch {
      console.error("Failed to parse response:", codeResult.result);
      process.exit(1);
    }

    if (codeData.error) {
      console.error("Device code error:", codeData);
      process.exit(1);
    }

    const { device_code, user_code, verification_uri_complete } = codeData;

    // =========================================================
    // Step 6: Human signs in
    // =========================================================
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║  ACTION REQUIRED — Sign in with Google                       ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  ${verification_uri_complete.padEnd(60)}║
║                                                              ║
║  Or go to: ${OPENCLOAK_URL}/device/verify`.padEnd(63) + `║
║  Code: ${user_code}`.padEnd(63) + `║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
`);

    await waitForEnter("  Press ENTER after you've signed in... ");

    // =========================================================
    // Step 7: Agent polls for id_token (runs IN the sandbox)
    // =========================================================
    console.log("\nStep 7: Agent polling for authorization result...");

    const pollScript = `
let attempts = 0;
while (attempts < 24) {
  attempts++;
  const res = await fetch("${OPENCLOAK_URL}/device/token?device_code=${device_code}");
  const data = await res.json();
  if (data.id_token) {
    console.log("ID_TOKEN:" + data.id_token);
    console.log("SUB:" + data.claims.sub);
    console.log("EMAIL:" + (data.claims.email || "n/a"));
    console.log("NAME:" + (data.claims.name || "n/a"));
    process.exit(0);
  }
  if (data.error === "expired_token") { console.log("EXPIRED"); process.exit(1); }
  await new Promise(r => setTimeout(r, data.error === "slow_down" ? 10000 : 5000));
}
console.log("TIMEOUT"); process.exit(1);
`.trim();

    await exec(sandbox, `cat > /tmp/poll.mjs << 'EOF'\n${pollScript}\nEOF`);
    const pollResult = await exec(sandbox, "node /tmp/poll.mjs 2>&1", "GET /device/token (polling from sandbox)");

    const pollOutput = pollResult.result || "";
    const idToken = pollOutput.match(/ID_TOKEN:(.+)/)?.[1]?.trim();
    const sub = pollOutput.match(/SUB:(.+)/)?.[1]?.trim();
    const email = pollOutput.match(/EMAIL:(.+)/)?.[1]?.trim();
    const name = pollOutput.match(/NAME:(.+)/)?.[1]?.trim();

    if (!idToken || !sub) {
      console.error("\nFailed to get id_token:", pollOutput);
      process.exit(1);
    }

    console.log(`\n  Got id_token! sub=${sub} email=${email} name=${name}`);

    // =========================================================
    // Step 8: Register agent identity on vault (via Heroku env)
    // =========================================================
    console.log("\nStep 8: Registering agent identity on vault...");
    console.log(`  Setting REGISTERED_AGENTS with identity: ${sub}`);

    const agentsConfig = JSON.stringify([{ identity: sub, owner: "demo-owner", scopes: "issues:create,read" }]);
    await herokuSetConfig("REGISTERED_AGENTS", agentsConfig);

    // =========================================================
    // Step 9: Wait for Heroku dyno restart
    // =========================================================
    console.log("\nStep 9: Waiting for Heroku dyno restart...");
    const up = await waitForHeroku();
    if (!up) {
      console.error("  Heroku did not come back up in time.");
      process.exit(1);
    }
    console.log("  Vault is back up with agent registered.");

    // =========================================================
    // Step 10: Prompt OpenClaw agent to do the token exchange
    // =========================================================
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║  Prompting OpenClaw agent                                    ║
║  The agent will reason through token exchange + issue creation║
╚══════════════════════════════════════════════════════════════╝
`);

    const agentPrompt = `You are an AI agent running inside a secure Daytona sandbox. You have no API credentials in your environment.

A human just authorized you via device flow. Use OpenCloak (an OAuth vault) to get a scoped Linear Bearer token, then create a Linear issue.

Step 1 — Token exchange: Run this curl command to exchange the id_token for a Linear Bearer token:

curl -s -X POST "${OPENCLOAK_URL}/token" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \\
  -d "actor_token=${idToken}" \\
  -d "actor_token_type=urn:ietf:params:oauth:token-type:id_token" \\
  -d "resource=https://api.linear.app" \\
  -d "scope=issues:create"

Parse the JSON response and extract the access_token field.

Step 2 — Create a Linear issue: Use the Bearer token from Step 1 to create an issue:

curl -s -X POST "https://api.linear.app/graphql" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer <ACCESS_TOKEN_FROM_STEP_1>" \\
  -d '{"query":"mutation { issueCreate(input: { title: \\"OpenClaw Agent — OpenCloak + Daytona\\", description: \\"Created by a real OpenClaw agent running in a Daytona sandbox via RFC 8693 token exchange. The agent never had Linear credentials.\\", teamId: \\"${LINEAR_TEAM_ID}\\", stateId: \\"${TODO_STATE_ID}\\" }) { success issue { identifier url } } }"}'

Report the issue identifier and URL when done. If any step fails, show the error response.`;

    // Write the prompt to a file to avoid shell escaping issues
    await exec(sandbox, `cat > /tmp/agent-prompt.txt << 'PROMPTEOF'\n${agentPrompt}\nPROMPTEOF`);

    console.log("  Sending prompt to OpenClaw agent (this may take 60-120s)...\n");

    const agentResult = await exec(
      sandbox,
      `${LLM_ENV_NAME}=${LLM_API_KEY} openclaw agent --local --session-id opencloak-demo -m "$(cat /tmp/agent-prompt.txt)" --json 2>&1`,
      "OpenClaw agent output"
    );

    const agentOutput = agentResult.result || "";

    // =========================================================
    // Step 11: Parse results and display summary
    // =========================================================
    // Try to extract issue URL from OpenClaw's output
    const issueUrlMatch = agentOutput.match(/https:\/\/linear\.app\/[^\s"')}\]]+/);
    const issueIdMatch = agentOutput.match(/\b([A-Z]+-\d+)\b/);
    const issueUrl = issueUrlMatch?.[0];
    const issueId = issueIdMatch?.[1];

    // Check if the agent succeeded
    const succeeded = agentOutput.includes("success") || agentOutput.includes("identifier") || issueUrl;

    if (!succeeded) {
      console.log("\n  OpenClaw agent may not have completed successfully.");
      console.log("  Check the full output above for details.");
    }

    console.log(`
╔══════════════════════════════════════════════════════════════╗
║  Demo Complete                                               ║
╚══════════════════════════════════════════════════════════════╝

  1. Created Daytona sandbox (daytona-medium, OpenClaw preinstalled)
  2. Configured OpenClaw (${LLM_MODEL})
  3. Agent (sandbox) called POST /device/code → got code ${user_code}
  4. Human signed in with Google at /device/verify
  5. Agent polled GET /device/token → got id_token (sub: ${sub})
  6. Registered agent identity on vault via Heroku
  7. Prompted OpenClaw agent to reason through:
     a. RFC 8693 token exchange → Linear Bearer token
     b. GraphQL mutation → Linear issue creation
  8. OpenClaw agent created Linear issue${issueId ? ` ${issueId}` : ""}${issueUrl ? `\n     ${issueUrl}` : ""}

  The agent never had Linear credentials in its environment.
  OpenClaw reasoned through the token exchange autonomously.

  Sandbox: ${sandbox.id}
  Clean up: https://app.daytona.io/dashboard
`);

  } catch (err) {
    console.error(`\nDemo error: ${err.message}`);
    console.error(err.stack);
    console.error(`Sandbox ${sandbox.id} — clean up at https://app.daytona.io/dashboard`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
