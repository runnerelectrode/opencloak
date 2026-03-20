#!/usr/bin/env node

/**
 * OpenClaw + OpenCloak Gateway — Blaxel Sandbox with Chat UI
 *
 * Flow:
 *   Browser → Chat UI (Blaxel preview) → OpenClaw gateway mode →
 *   gateway.opencloak.org (injects real API key) → OpenRouter → Sonnet
 *
 * The agent never sees the real API key.
 */

const BL_API_KEY = "bl_aaabjzxlwkbmupofh2feby4269sbjgrc";
const VAULT = "https://id.opencloak.org";
const GATEWAY = "https://gateway.opencloak.org";
const MODEL = "anthropic/claude-sonnet-4-20250514";

process.env.BL_API_KEY = BL_API_KEY;
process.env.BL_WORKSPACE = "attach";

const { SandboxInstance } = await import("@blaxel/core");

const RUN = Date.now().toString(36);
const SBX_NAME = "openclaw-gateway";

console.log("=== OpenClaw + OpenCloak Gateway in Blaxel ===\n");

// --- 1. Create sandbox ---
console.log("1. Creating Blaxel sandbox...");
const sandbox = await SandboxInstance.createIfNotExists({
  name: SBX_NAME,
  image: "blaxel/node:latest",
  memory: 4096,
  ports: [{ target: 18789, protocol: "HTTP" }],
  region: "us-pdx-1",
});
const sbxUrl = sandbox.sandbox.metadata.url;
console.log(`   Sandbox: ${sbxUrl}\n`);

const auth = { Authorization: `Bearer ${BL_API_KEY}` };

async function run(label, command, maxWaitMs = 120000) {
  const name = `${label}-${RUN}`;
  const startRes = await fetch(`${sbxUrl}/process`, {
    method: "POST",
    headers: { ...auth, "Content-Type": "application/json" },
    body: JSON.stringify({ name, command, waitForCompletion: false }),
  });
  if (!startRes.ok) throw new Error(`Failed to start ${name}: ${await startRes.text()}`);

  const deadline = Date.now() + maxWaitMs;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 2000));
    try {
      const res = await fetch(`${sbxUrl}/process/${name}`, { headers: auth });
      if (res.ok) {
        const d = await res.json();
        if (d.status !== "running") {
          const logsRes = await fetch(`${sbxUrl}/process/${name}/logs`, { headers: auth });
          const logs = await logsRes.json();
          return { name, status: d.status, stdout: logs.stdout || "", stderr: logs.stderr || "" };
        }
      }
    } catch {}
  }
  throw new Error(`Process ${name} timed out`);
}

// --- 2. Install OpenClaw ---
console.log("2. Checking OpenClaw...");
try {
  await run("check", "which openclaw > /tmp/which-oc.txt 2>&1 || echo NOT_FOUND > /tmp/which-oc.txt", 10000);
} catch {}
let whichResult = "";
try { whichResult = await sandbox.fs.read("/tmp/which-oc.txt"); } catch {}

if (!whichResult.trim() || whichResult.includes("NOT_FOUND")) {
  console.log("   Installing openclaw (~60s)...");
  await run("install", "npm install -g openclaw@latest", 180000);
  console.log("   Installed.\n");
} else {
  console.log(`   Already at ${whichResult.trim()}\n`);
}

// --- 3. Device flow — human signs in ---
console.log("3. Starting device flow (RFC 8628)...");
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
await new Promise((r) => setTimeout(r, 1000));
const deviceData = JSON.parse(await sandbox.fs.read("/tmp/device-code.json"));
console.log(`   User code: ${deviceData.user_code}`);
console.log(`\n   *** SIGN IN WITH GOOGLE ***`);
console.log(`   ${deviceData.verification_uri_complete}\n`);

// --- 4. Poll for approval ---
console.log("4. Waiting for approval...");
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
  await new Promise((r) => setTimeout(r, 5000));
  await run(`poll-${i}`, `node /tmp/poll-script.mjs "${deviceData.device_code}"`, 15000);
  const pollData = JSON.parse(await sandbox.fs.read("/tmp/poll-result.json"));
  if (pollData.id_token) {
    idToken = pollData.id_token;
    console.log("   Approved!\n");
    break;
  }
  if (pollData.error === "authorization_pending" || pollData.error === "slow_down") {
    process.stdout.write(".");
    continue;
  }
  console.error("\n   Error:", JSON.stringify(pollData));
  process.exit(1);
}
if (!idToken) { console.error("\n   Timed out."); process.exit(1); }

// --- 5. Token exchange → gateway JWT ---
console.log("5. Exchanging id_token for gateway JWT (scope=llm:openrouter)...");
const exchangeScript = `
import fs from "node:fs";
const idToken = fs.readFileSync("/tmp/opencloak-id-token", "utf-8").trim();
const res = await fetch("${VAULT}/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    actor_token: idToken,
    actor_token_type: "urn:ietf:params:oauth:token-type:id_token",
    resource: "${GATEWAY}",
    scope: "llm:openrouter",
  }).toString(),
});
const data = await res.json();
fs.writeFileSync("/tmp/gateway-jwt.json", JSON.stringify(data));
`;
await sandbox.fs.write("/tmp/opencloak-id-token", idToken);
await sandbox.fs.write("/tmp/exchange-script.mjs", exchangeScript);
await run("exchange", "node /tmp/exchange-script.mjs", 15000);
await new Promise((r) => setTimeout(r, 1000));
const exchangeData = JSON.parse(await sandbox.fs.read("/tmp/gateway-jwt.json"));

if (exchangeData.error) {
  console.error("   Token exchange failed:", JSON.stringify(exchangeData));
  process.exit(1);
}

const gatewayJwt = exchangeData.access_token;
console.log(`   Got gateway JWT (expires in ${exchangeData.expires_in}s)\n`);

// --- 6. Configure OpenClaw to use the gateway ---
console.log("6. Configuring OpenClaw...");

// Write openclaw.json with a custom provider pointing to our gateway
const openclawConfig = {
  models: {
    mode: "merge",
    providers: {
      "opencloak": {
        baseUrl: `${GATEWAY}/v1`,
        apiKey: "${OPENCLOAK_GATEWAY_JWT}",
        api: "openai-completions",
        models: [
          {
            id: `${MODEL}`,
            name: "Claude Sonnet (via OpenCloak Gateway)",
            reasoning: false,
            input: ["text", "image"],
            contextWindow: 200000,
            maxTokens: 8192,
          },
        ],
      },
    },
  },
  agents: {
    defaults: {
      model: {
        primary: `opencloak/${MODEL}`,
      },
      models: {
        [`opencloak/${MODEL}`]: { alias: "Sonnet" },
      },
    },
  },
  gateway: {
    mode: "local",
  },
};

const configScript = `
const fs = require("fs");
const path = require("path");

// Ensure config dir exists
const configDir = "/blaxel/.openclaw";
fs.mkdirSync(configDir, { recursive: true });
fs.mkdirSync(path.join(configDir, "agents/main/agent"), { recursive: true });

// Write openclaw.json
fs.writeFileSync(
  path.join(configDir, "openclaw.json"),
  JSON.stringify(${JSON.stringify(openclawConfig)}, null, 2)
);

// Write auth-profiles.json with gateway JWT as the API key
const authProfiles = {
  version: 1,
  profiles: {
    "opencloak:default": {
      provider: "opencloak",
      type: "api_key",
      key: process.env.GATEWAY_JWT,
    },
  },
};
fs.writeFileSync(
  path.join(configDir, "agents/main/agent/auth-profiles.json"),
  JSON.stringify(authProfiles, null, 2)
);

// Write .env with gateway JWT
fs.writeFileSync(
  path.join(configDir, ".env"),
  "OPENCLOAK_GATEWAY_JWT=" + process.env.GATEWAY_JWT + "\\n"
);

console.log("Config written.");
`;
await sandbox.fs.write("/tmp/configure-openclaw.cjs", configScript);
await run("config", `GATEWAY_JWT="${gatewayJwt}" node /tmp/configure-openclaw.cjs`, 15000);

console.log(`   Provider:  opencloak (custom, via gateway)`);
console.log(`   Base URL:  ${GATEWAY}/v1`);
console.log(`   Model:     opencloak/${MODEL}`);
console.log(`   API key:   <gateway JWT, not real key>\n`);

// --- 7. Create Blaxel preview URL ---
console.log("7. Creating preview URL...");
const preview = await sandbox.previews.createIfNotExists({
  metadata: { name: `preview-${SBX_NAME}` },
  spec: { port: 18789, public: true },
});

// Find preview URL from response
let previewUrl;
function findUrl(obj, depth = 0) {
  if (depth > 3 || previewUrl) return;
  if (typeof obj === "string" && obj.includes("preview.bl.run")) {
    previewUrl = obj.startsWith("https") ? obj : `https://${obj}`;
    return;
  }
  if (obj && typeof obj === "object") {
    for (const v of Object.values(obj)) findUrl(v, depth + 1);
  }
}
findUrl(preview);

if (!previewUrl) {
  console.error("   Could not determine preview URL");
  console.log("   Preview object keys:", Object.keys(preview));
  process.exit(1);
}
console.log(`   Preview: ${previewUrl}\n`);

// --- 8. Configure CORS for preview URL ---
console.log("8. Configuring CORS...");
const corsScript = `
const fs = require("fs");
const cfgPath = "/blaxel/.openclaw/openclaw.json";
let config = {};
try { config = JSON.parse(fs.readFileSync(cfgPath, "utf-8")); } catch {}
if (!config.gateway) config.gateway = {};
config.gateway.controlUi = { allowedOrigins: ["${previewUrl}"] };
fs.writeFileSync(cfgPath, JSON.stringify(config, null, 2));
console.log("CORS set for", "${previewUrl}");
`;
await sandbox.fs.write("/tmp/fix-cors.cjs", corsScript);
await run("cors", "node /tmp/fix-cors.cjs", 15000);
console.log("   Done.\n");

// --- 9. Start OpenClaw gateway (serves chat UI on port 18789) ---
console.log("9. Starting OpenClaw gateway...");
const gwName = `gw-${RUN}`;
await fetch(`${sbxUrl}/process`, {
  method: "POST",
  headers: { ...auth, "Content-Type": "application/json" },
  body: JSON.stringify({
    name: gwName,
    command: `OPENCLOAK_GATEWAY_JWT="${gatewayJwt}" openclaw gateway --bind lan --verbose`,
    waitForCompletion: false,
  }),
});

// Wait for gateway to be ready
for (let i = 0; i < 30; i++) {
  await new Promise((r) => setTimeout(r, 3000));
  try {
    const check = await fetch(previewUrl, { signal: AbortSignal.timeout(5000) });
    if (check.status !== 502) {
      console.log(`   Gateway is up! (HTTP ${check.status})\n`);
      break;
    }
  } catch {}
  process.stdout.write(".");
}

// --- 10. Get OpenClaw gateway token for chat UI ---
console.log("10. Getting chat UI token...");
const tokenResult = await run("token", "openclaw gateway token 2>&1", 15000);
const tokenMatch = tokenResult.stdout.match(/[a-f0-9]{48}/);
const gatewayToken = tokenMatch ? tokenMatch[0] : tokenResult.stdout.trim().split("\n").pop();
console.log(`   Token: ${gatewayToken}\n`);

console.log("=== READY ===\n");
console.log(`Chat UI:  ${previewUrl}`);
console.log(`Token:    ${gatewayToken}`);
console.log(`\nOpen the Chat UI in your browser and enter the token.`);
console.log(`All LLM calls route through: ${GATEWAY}`);
console.log(`The real OpenRouter API key never leaves the gateway server.\n`);
console.log(`Gateway JWT expires in ${exchangeData.expires_in}s — re-run to refresh.`);
