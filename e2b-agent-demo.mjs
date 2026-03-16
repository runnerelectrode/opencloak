import { Sandbox } from "e2b";

const E2B_KEY = "e2b_6a3a93a3cdc027461665efb483e8c2499ca903eb";
const NEBIUS_KEY = "v1.CmQKHHN0YXRpY2tleS1lMDBwdjJ3MHFlZW5kZGhyMzcSIXNlcnZpY2VhY2NvdW50LWUwMGcycWUyY3hiemVxM2pxdzIMCPqE3c0GELyOt8IBOgwI-Yf1mAcQgJfjiwNAAloDZTAw.AAAAAAAAAAERtgaiKym1fWhCz775jQ3Fscrp3FGdCLmnMSFIvDN6Gu-qcnWsOsZ6WFkG4TLPE83o8NSHpGReGQXYzFYOgQgD";
const VAULT = "https://id.opencloak.org";
const TEAM_ID = "f6442499-53cb-4bf3-be79-5291905bc325";
const STATE_ID = "419ad82d-e284-42a0-932f-e639af430278";
const MODEL = "deepseek-ai/DeepSeek-V3-0324-fast";

// --- E2B Sandbox ---
console.log("=== Real Agent Demo — DeepSeek V3 in E2B Sandbox ===\n");
console.log("1. Creating E2B sandbox...");
const sandbox = await Sandbox.create({ apiKey: E2B_KEY });
console.log(`   Sandbox: ${sandbox.sandboxId}\n`);

// --- Step 1: Agent requests device code (runs in sandbox) ---
console.log("2. Agent requests device code from OpenCloak...");
const deviceRes = await sandbox.commands.run(
  `curl -s -X POST "${VAULT}/device/code" -H "Content-Type: application/x-www-form-urlencoded" -d "issuer_id=google"`,
  { timeoutMs: 15000 }
);
const deviceData = JSON.parse(deviceRes.stdout);
console.log(`   User code: ${deviceData.user_code}`);
console.log(`\n   *** HUMAN ACTION REQUIRED ***`);
console.log(`   Open this URL and approve the code:`);
console.log(`   ${deviceData.verification_uri_complete}\n`);

// --- Step 2: Poll for approval (runs in sandbox, waits for human) ---
console.log("3. Polling for human approval...");
let idToken = null;
for (let i = 0; i < 60; i++) {
  await new Promise((r) => setTimeout(r, 5000)); // 5s interval per RFC 8628
  const pollRes = await sandbox.commands.run(
    `curl -s "${VAULT}/device/token?device_code=${deviceData.device_code}"`,
    { timeoutMs: 15000 }
  );
  const pollData = JSON.parse(pollRes.stdout);
  if (pollData.id_token) {
    idToken = pollData.id_token;
    console.log("   Approved! Got id_token from human authorization.\n");
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
  console.error("\n   Timed out waiting for approval.");
  await sandbox.kill();
  process.exit(1);
}

// --- Step 3-4: Hand off to DeepSeek V3 agent with the id_token ---
// Now the agent has a human-approved identity. Let it reason autonomously.

const tools = [
  {
    type: "function",
    function: {
      name: "run_command",
      description: "Execute a shell command in the secure sandbox.",
      parameters: {
        type: "object",
        properties: {
          command: { type: "string", description: "The shell command to execute" },
        },
        required: ["command"],
      },
    },
  },
];

const systemPrompt = `You are an autonomous AI agent running inside a secure E2B sandbox. A human just authorized you via the OAuth device flow (RFC 8628). You now have an id_token proving the human's identity.

Your task: Use the id_token to get a scoped Linear API token via token exchange (RFC 8693), then create a Linear issue.

Here is what you have:
- id_token: ${idToken}
- OpenCloak vault URL: ${VAULT}
- Linear team ID: ${TEAM_ID}
- Linear state ID (Todo): ${STATE_ID}

Step 1 — Exchange the id_token for a scoped Linear Bearer token:
  POST ${VAULT}/token
  Content-Type: application/x-www-form-urlencoded
  Body:
    grant_type=urn:ietf:params:oauth:grant-type:token-exchange
    actor_token=<id_token>
    actor_token_type=urn:ietf:params:oauth:token-type:id_token
    resource=https://api.linear.app
    scope=issues:create

Step 2 — Create a Linear issue with the Bearer token:
  POST https://api.linear.app/graphql
  Authorization: Bearer <access_token>
  Content-Type: application/json
  Body: {"query":"mutation { issueCreate(input: { title: \\"Autonomous agent — DeepSeek V3 + E2B + OpenCloak\\", description: \\"Created autonomously by DeepSeek V3 in E2B sandbox. Human authorized via RFC 8628 device flow. Token obtained via RFC 8693 exchange. Zero credentials in agent environment.\\", teamId: \\"${TEAM_ID}\\", stateId: \\"${STATE_ID}\\" }) { success issue { identifier url } } }"}

Report the issue identifier and URL when done.`;

const messages = [
  { role: "system", content: systemPrompt },
  { role: "user", content: "You have the human's authorization. Exchange the token and create the Linear issue." },
];

console.log("4. DeepSeek V3 agent taking over...\n");

for (let turn = 0; turn < 10; turn++) {
  const res = await fetch("https://api.tokenfactory.nebius.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${NEBIUS_KEY}`,
    },
    body: JSON.stringify({
      model: MODEL,
      messages,
      tools,
      tool_choice: "auto",
      max_tokens: 2000,
    }),
  });

  const data = await res.json();
  const choice = data.choices?.[0];
  if (!choice) {
    console.error("No response from model:", JSON.stringify(data).substring(0, 300));
    break;
  }

  const msg = choice.message;
  messages.push(msg);

  if (msg.tool_calls && msg.tool_calls.length > 0) {
    for (const tc of msg.tool_calls) {
      const args = JSON.parse(tc.function.arguments);
      console.log(`   [Agent → Tool] ${args.command.substring(0, 200)}`);

      let output;
      try {
        const result = await sandbox.commands.run(args.command, { timeoutMs: 30000 });
        output = result.stdout || result.stderr || "(no output)";
      } catch (err) {
        output = err.result?.stdout || err.result?.stderr || err.message;
      }
      console.log(`   [Tool → Agent] ${output.substring(0, 200)}`);

      messages.push({
        role: "tool",
        tool_call_id: tc.id,
        content: output,
      });
    }
  }

  if (choice.finish_reason === "stop" && (!msg.tool_calls || msg.tool_calls.length === 0)) {
    console.log(`\n5. Agent finished:\n`);
    console.log(msg.content);
    break;
  }
}

await sandbox.kill();
console.log("\n=== Done. Human-in-the-loop → autonomous agent. ===");
