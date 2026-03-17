import { Sandbox } from "e2b";

const E2B_KEY = "e2b_6a3a93a3cdc027461665efb483e8c2499ca903eb";
const OPENROUTER_KEY = "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";
const VAULT = "https://id.opencloak.org";
const TEAM_ID = "f6442499-53cb-4bf3-be79-5291905bc325";
const STATE_ID = "419ad82d-e284-42a0-932f-e639af430278";
const MODEL = "openrouter/deepseek/deepseek-chat-v3-0324";

console.log("=== OpenClaw + OpenRouter + OpenCloak in E2B ===\n");

// 1. Create sandbox
console.log("1. Creating E2B sandbox (openclaw template)...");
const sandbox = await Sandbox.create("openclaw", {
  apiKey: E2B_KEY,
  envs: { OPENROUTER_API_KEY: OPENROUTER_KEY, OPENCLOAK_URL: VAULT },
  timeoutMs: 3600000, // 1 hour
});
console.log(`   Sandbox: ${sandbox.sandboxId}\n`);

// 2. Configure OpenClaw model
console.log("2. Configuring OpenClaw...");
await sandbox.commands.run(`bash -lc 'openclaw config set agents.defaults.model.primary ${MODEL}'`);
try {
  const r = await sandbox.commands.run(`bash -lc 'openclaw models 2>&1 | head -15'`);
  console.log(r.stdout);
} catch (e) { console.log(e.result?.stdout); }

// 3. Agent requests device code from the sandbox (zero credentials)
console.log("3. Agent requesting device code from OpenCloak vault...");
const dcRes = await sandbox.commands.run(
  `curl -s -X POST "${VAULT}/device/code" -H "Content-Type: application/x-www-form-urlencoded" -d "issuer_id=google"`,
  { timeoutMs: 15000 }
);
const deviceData = JSON.parse(dcRes.stdout);
console.log(`   User code: ${deviceData.user_code}`);
console.log(`\n   *** HUMAN ACTION REQUIRED ***`);
console.log(`   Open this URL and sign in with Google:`);
console.log(`   ${deviceData.verification_uri_complete}\n`);

// 4. Poll for human approval (from sandbox)
console.log("4. Polling for human approval...");
let idToken = null;
for (let i = 0; i < 60; i++) {
  await new Promise((r) => setTimeout(r, 5000));
  const pollRes = await sandbox.commands.run(
    `curl -s "${VAULT}/device/token?device_code=${deviceData.device_code}"`,
    { timeoutMs: 15000 }
  );
  const pollData = JSON.parse(pollRes.stdout);
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
  await sandbox.kill();
  process.exit(1);
}
if (!idToken) {
  console.error("\n   Timed out.");
  await sandbox.kill();
  process.exit(1);
}

// 5. Persist the id_token in the sandbox so subsequent runs can reuse it
await sandbox.files.write("/tmp/opencloak-id-token", idToken);
console.log("5. Preparing auth + issue creation script for OpenClaw agent...\n");

const authScript = `
const VAULT = "${VAULT}";
const TEAM_ID = "${TEAM_ID}";
const STATE_ID = "${STATE_ID}";
const ID_TOKEN = process.env.OPENCLOAK_ID_TOKEN || require("fs").readFileSync("/tmp/opencloak-id-token", "utf-8").trim();

async function main() {
  // Token exchange (RFC 8693)
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

  // Create Linear issue
  const issueRes = await fetch("https://api.linear.app/graphql", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + ex.access_token,
    },
    body: JSON.stringify({
      query: \`mutation { issueCreate(input: { title: "OpenClaw agent — E2B + OpenRouter + OpenCloak", description: "Created autonomously by OpenClaw (DeepSeek V3 via OpenRouter) in E2B sandbox. Human authorized via RFC 8628 device flow. Token via RFC 8693 exchange. Zero credentials in agent.", teamId: "\${TEAM_ID}", stateId: "\${STATE_ID}" }) { success issue { identifier url } } }\`
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
await sandbox.files.write("/tmp/opencloak-auth.mjs", authScript);

const prompt = `You are a fully autonomous AI agent running in a secure E2B sandbox. A human just authorized you via OAuth device flow (RFC 8628). You now have an id_token proving the human's identity, available as the env var OPENCLOAK_ID_TOKEN.

A helper script at /tmp/opencloak-auth.mjs will:
1. Exchange the id_token for a scoped Linear Bearer token (RFC 8693)
2. Create a Linear issue

Run it now:
OPENCLOAK_ID_TOKEN="$OPENCLOAK_ID_TOKEN" node /tmp/opencloak-auth.mjs

Report the issue identifier and URL from its output. Execute immediately without asking for confirmation.`;

await sandbox.files.write("/tmp/agent-prompt.txt", prompt);

// 6. Run OpenClaw agent with the id_token as env var
console.log("6. OpenClaw agent (DeepSeek V3 via OpenRouter) taking over...\n");

try {
  const res = await sandbox.commands.run(
    `bash -lc 'OPENCLOAK_ID_TOKEN="${idToken}" openclaw agent --local --session-id opencloak-demo -m "$(cat /tmp/agent-prompt.txt)" 2>&1'`,
    { timeoutMs: 300000 }
  );
  console.log(res.stdout);
} catch (err) {
  console.log(err.result?.stdout?.slice(-3000) || "no output");
  if (err.result?.stderr) console.log("STDERR:", err.result.stderr.slice(-500));
}

console.log(`\n=== Done. Sandbox ${sandbox.sandboxId} is still running. ===`);
console.log(`Reuse it with: Sandbox.connect("${sandbox.sandboxId}")`);
