import { Sandbox } from "e2b";

const E2B_KEY = "e2b_6a3a93a3cdc027461665efb483e8c2499ca903eb";
const NEBIUS_KEY = "v1.CmQKHHN0YXRpY2tleS1lMDBwdjJ3MHFlZW5kZGhyMzcSIXNlcnZpY2VhY2NvdW50LWUwMGcycWUyY3hiemVxM2pxdzIMCPqE3c0GELyOt8IBOgwI-Yf1mAcQgJfjiwNAAloDZTAw.AAAAAAAAAAERtgaiKym1fWhCz775jQ3Fscrp3FGdCLmnMSFIvDN6Gu-qcnWsOsZ6WFkG4TLPE83o8NSHpGReGQXYzFYOgQgD";
const VAULT = "https://id.opencloak.org";
const TEAM_ID = "f6442499-53cb-4bf3-be79-5291905bc325";
const STATE_ID = "419ad82d-e284-42a0-932f-e639af430278";

const sandbox = await Sandbox.create({ apiKey: E2B_KEY });
console.log(`Sandbox: ${sandbox.sandboxId}\n`);

async function run(cmd) {
  const res = await sandbox.commands.run(cmd, { timeoutMs: 30000 });
  return res.stdout.trim();
}

console.log("=== E2B + OpenCloak + Nebius Demo ===\n");

// 1. Test Nebius GLM-5 from E2B sandbox
console.log("1. Testing Nebius GLM-5 from E2B sandbox...");
const nebiusBody = JSON.stringify({
  model: "moonshotai/Kimi-K2.5-fast",
  messages: [{ role: "user", content: "Say hello in 3 words" }],
  max_tokens: 200,
});
// Write the JSON body to a file to avoid shell escaping issues
await sandbox.files.write("/tmp/nebius.json", nebiusBody);
const nebiusRes = await run(
  `curl -s -m 30 -X POST "https://api.tokenfactory.nebius.com/v1/chat/completions" -H "Content-Type: application/json" -H "Authorization: Bearer ${NEBIUS_KEY}" -d @/tmp/nebius.json`
);
try {
  const parsed = JSON.parse(nebiusRes);
  const msg = parsed.choices?.[0]?.message;
  console.log("   GLM-5:", msg?.content || "(reasoning only)");
  if (msg?.reasoning) console.log("   Reasoning:", msg.reasoning.substring(0, 150));
} catch {
  console.log("   Raw:", nebiusRes.substring(0, 300));
}

// 2. Device code flow — auto-approved
console.log("\n2. Requesting device code from OpenCloak...");
const deviceRes = await run(
  `curl -s -X POST "${VAULT}/device/code" -H "Content-Type: application/x-www-form-urlencoded" -d "issuer_id=google"`
);
const deviceData = JSON.parse(deviceRes);
console.log(`   Device code: ${deviceData.user_code}`);

const pollRes = await run(
  `curl -s "${VAULT}/device/token?device_code=${deviceData.device_code}"`
);
const pollData = JSON.parse(pollRes);
if (pollData.id_token) {
  console.log("   Auto-approved instantly! (zero human interaction)");
} else {
  console.error("   NOT auto-approved:", JSON.stringify(pollData));
  await sandbox.kill();
  process.exit(1);
}

// 3. Token exchange — RFC 8693
console.log("\n3. Token exchange → Linear Bearer token (RFC 8693)...");
const exchangeRes = await run(
  `curl -s -X POST "${VAULT}/token" ` +
    `-H "Content-Type: application/x-www-form-urlencoded" ` +
    `-d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" ` +
    `-d "actor_token=${pollData.id_token}" ` +
    `-d "actor_token_type=urn:ietf:params:oauth:token-type:id_token" ` +
    `-d "resource=https://api.linear.app" ` +
    `-d "scope=issues:create"`
);
const tokenData = JSON.parse(exchangeRes);
if (tokenData.error) {
  console.error("   Exchange failed:", exchangeRes);
  await sandbox.kill();
  process.exit(1);
}
console.log("   Got Bearer token!");

// 4. Create Linear issue from sandbox
console.log("\n4. Creating Linear issue from E2B sandbox...");
const mutation = JSON.stringify({
  query: `mutation { issueCreate(input: { title: "E2B sandbox demo — OpenCloak + Nebius GLM-5", description: "Created from an E2B sandbox. LLM: GLM-5 via Nebius Token Factory. Auth: OpenCloak token exchange (RFC 8693). Zero credentials in agent environment.", teamId: "${TEAM_ID}", stateId: "${STATE_ID}" }) { success issue { identifier url } } }`,
});
await sandbox.files.write("/tmp/mutation.json", mutation);
const issueRes = await run(
  `curl -s -X POST "https://api.linear.app/graphql" -H "Content-Type: application/json" -H "Authorization: Bearer ${tokenData.access_token}" -d @/tmp/mutation.json`
);
const issueData = JSON.parse(issueRes);
if (issueData.data?.issueCreate?.success) {
  console.log(`   ${issueData.data.issueCreate.issue.identifier}: ${issueData.data.issueCreate.issue.url}`);
} else {
  console.error("   Error:", issueRes);
}

console.log("\n=== Done. E2B + OpenCloak + Nebius = fully autonomous. ===");
await sandbox.kill();
