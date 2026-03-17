const BL_API_KEY = "bl_aaabjzxlwkbmupofh2feby4269sbjgrc";
const OPENROUTER_KEY = "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";
const VAULT = "https://id.opencloak.org";
const TEAM_ID = "f6442499-53cb-4bf3-be79-5291905bc325";
const STATE_ID = "419ad82d-e284-42a0-932f-e639af430278";
const MODEL = "openrouter/anthropic/claude-sonnet-4.5";

// Set env vars BEFORE importing SDK
process.env.BL_API_KEY = BL_API_KEY;
process.env.BL_WORKSPACE = "attach";

const { SandboxInstance } = await import("@blaxel/core");

const RUN = Date.now().toString(36);

console.log("=== OpenClaw + OpenRouter + OpenCloak in Blaxel ===\n");

// 1. Create sandbox
console.log("1. Creating Blaxel sandbox...");
const sandbox = await SandboxInstance.createIfNotExists({
  name: "openclaw-opencloak",
  image: "blaxel/node:latest",
  memory: 4096,
  ports: [{ target: 18789, protocol: "HTTP" }],
  region: "us-pdx-1",
});
const sbxUrl = sandbox.sandbox.metadata.url;
console.log(`   Sandbox created: ${sbxUrl}\n`);

// Auth headers for direct REST API calls to sandbox
const authHeaders = { "Authorization": `Bearer ${BL_API_KEY}` };

// Helper: run command via sandbox REST API directly (avoids h2 session issues)
async function run(label, command, maxWaitMs = 60000) {
  const name = `${label}-${RUN}`;

  // Start process (fire and forget)
  const startRes = await fetch(`${sbxUrl}/process`, {
    method: "POST",
    headers: { ...authHeaders, "Content-Type": "application/json" },
    body: JSON.stringify({ name, command, waitForCompletion: false }),
  });
  if (!startRes.ok) {
    const err = await startRes.text();
    throw new Error(`Failed to start ${name}: ${err}`);
  }

  // Poll for completion
  const deadline = Date.now() + maxWaitMs;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 2000));
    try {
      const statusRes = await fetch(`${sbxUrl}/process/${name}`, {
        headers: authHeaders,
      });
      if (statusRes.ok) {
        const data = await statusRes.json();
        if (data.status !== "running") return name;
      }
    } catch {
      // connection hiccup, retry
    }
  }
  throw new Error(`Process ${name} timed out after ${maxWaitMs}ms`);
}

// 2. Install OpenClaw
console.log("2. Checking/installing OpenClaw...");
try {
  await run("check", "which openclaw > /tmp/which-oc.txt 2>&1 || echo NOT_FOUND > /tmp/which-oc.txt", 10000);
} catch { /* may timeout if sandbox waking up */ }

let whichResult = "";
try { whichResult = await sandbox.fs.read("/tmp/which-oc.txt"); } catch {}

if (!whichResult.trim() || whichResult.includes("NOT_FOUND")) {
  console.log("   Installing openclaw (this takes ~60s)...");
  await run("install", "npm install -g openclaw@latest", 180000);
  console.log("   OpenClaw installed.\n");
} else {
  console.log(`   OpenClaw already at ${whichResult.trim()}\n`);
}

// 3. Configure OpenClaw with OpenRouter
console.log("3. Configuring OpenClaw...");
await run("onboard", `openclaw onboard --quickstart --provider openrouter --api-key ${OPENROUTER_KEY}`, 30000);
await run("model", `openclaw config set agents.defaults.model.primary ${MODEL}`, 15000);
console.log(`   Model set to ${MODEL}.\n`);

// 4. Request device code (use Node.js fetch inside sandbox — more reliable than curl)
console.log("4. Agent requesting device code from OpenCloak vault...");
const dcScript = `
import fs from "node:fs";
const res = await fetch("${VAULT}/device/code", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: "issuer_id=google",
});
const data = await res.json();
fs.writeFileSync("/tmp/device-code.json", JSON.stringify(data));
`;
await sandbox.fs.write("/tmp/dc-script.mjs", dcScript);
await run("dc", "node /tmp/dc-script.mjs", 15000);
// Small delay for file flush
await new Promise(r => setTimeout(r, 1000));
const deviceData = JSON.parse(await sandbox.fs.read("/tmp/device-code.json"));
console.log(`   User code: ${deviceData.user_code}`);
console.log(`\n   *** HUMAN ACTION REQUIRED ***`);
console.log(`   Open this URL and sign in with Google:`);
console.log(`   ${deviceData.verification_uri_complete}\n`);

// 5. Poll for human approval
console.log("5. Polling for human approval...");
const pollScript = `
import fs from "node:fs";
const dc = process.argv[2];
const res = await fetch("${VAULT}/device/token?device_code=" + dc);
const data = await res.json();
fs.writeFileSync("/tmp/poll-result.json", JSON.stringify(data));
`;
await sandbox.fs.write("/tmp/poll-script.mjs", pollScript);

let idToken = null;
for (let i = 0; i < 60; i++) {
  await new Promise(r => setTimeout(r, 5000));
  await run(`poll-${i}`, `node /tmp/poll-script.mjs "${deviceData.device_code}"`, 15000);
  const pollData = JSON.parse(await sandbox.fs.read("/tmp/poll-result.json"));
  if (pollData.id_token) {
    idToken = pollData.id_token;
    console.log("   Approved! Got id_token.\n");
    break;
  }
  if (pollData.error === "authorization_pending" || pollData.error === "slow_down") {
    process.stdout.write("   .");
    continue;
  }
  console.error("\n   Error:", JSON.stringify(pollData));
  process.exit(1);
}
if (!idToken) {
  console.error("\n   Timed out.");
  process.exit(1);
}

// Save id_token to sandbox
await sandbox.fs.write("/tmp/opencloak-id-token", idToken);

// 6. Write auth helper script
console.log("6. Preparing auth + issue creation script for OpenClaw agent...\n");

const authScript = `
import fs from "node:fs";
const VAULT = "${VAULT}";
const TEAM_ID = "${TEAM_ID}";
const STATE_ID = "${STATE_ID}";
const ID_TOKEN = process.env.OPENCLOAK_ID_TOKEN || fs.readFileSync("/tmp/opencloak-id-token", "utf-8").trim();

async function main() {
  const exRes = await fetch(VAULT + "/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      actor_token: ID_TOKEN,
      actor_token_type: "urn:ietf:params:oauth:token-type:id_token",
      resource: "https://api.linear.app",
      scope: "issues:create",
    }).toString(),
  });
  const ex = await exRes.json();
  if (ex.error) { console.log("EXCHANGE_ERROR:" + JSON.stringify(ex)); process.exit(1); }
  console.log("GOT_ACCESS_TOKEN");
  const issueRes = await fetch("https://api.linear.app/graphql", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + ex.access_token,
    },
    body: JSON.stringify({
      query: \`mutation { issueCreate(input: { title: "Blaxel sandbox — OpenClaw + OpenCloak", description: "Created autonomously by OpenClaw (Sonnet 4.5 via OpenRouter) in Blaxel sandbox. Human authorized via RFC 8628 device flow. Token via RFC 8693 exchange. Zero credentials in agent.", teamId: "\${TEAM_ID}", stateId: "\${STATE_ID}" }) { success issue { identifier url } } }\`
    }),
  });
  const issue = await issueRes.json();
  if (issue.data?.issueCreate?.success) {
    console.log("SUCCESS:" + issue.data.issueCreate.issue.identifier);
    console.log("URL:" + issue.data.issueCreate.issue.url);
  } else {
    console.log("ISSUE_ERROR:" + JSON.stringify(issue));
  }
}
main();
`;
await sandbox.fs.write("/tmp/opencloak-auth.mjs", authScript);

const prompt = `You are a fully autonomous AI agent running in a secure Blaxel sandbox. A human just authorized you via OAuth device flow (RFC 8628). You now have an id_token proving the human's identity, available as the env var OPENCLOAK_ID_TOKEN.

A helper script at /tmp/opencloak-auth.mjs will:
1. Exchange the id_token for a scoped Linear Bearer token (RFC 8693)
2. Create a Linear issue

Run it now:
OPENCLOAK_ID_TOKEN="$OPENCLOAK_ID_TOKEN" node /tmp/opencloak-auth.mjs

Report the issue identifier and URL from its output. Execute immediately without asking for confirmation.`;

await sandbox.fs.write("/tmp/agent-prompt.txt", prompt);

// 7. Run OpenClaw agent
console.log("7. OpenClaw agent (Sonnet 4.5 via OpenRouter) taking over...\n");

const agentName = `agent-${RUN}`;
await run(
  "agent",
  `OPENCLOAK_ID_TOKEN="${idToken}" OPENROUTER_API_KEY="${OPENROUTER_KEY}" openclaw agent --local --session-id blaxel-demo -m "$(cat /tmp/agent-prompt.txt)"`,
  300000
);

// Get agent output
try {
  const logsRes = await fetch(`${sbxUrl}/process/${agentName}/logs`, { headers: authHeaders });
  if (logsRes.ok) {
    const logsData = await logsRes.json();
    console.log(logsData.logs || logsData.stdout || "Agent completed.");
  }
} catch {
  console.log("Agent completed.");
}

console.log(`\n=== Done. Blaxel sandbox is still running. ===`);
console.log(`Sandbox URL: ${sbxUrl}`);
