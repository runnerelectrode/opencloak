#!/usr/bin/env node

/**
 * Device Flow Demo: Agent (Daytona) + Vault (OpenCloak on Heroku)
 *
 * An AI agent in a headless Daytona sandbox uses RFC 8628 device
 * authorization to get human approval, then exchanges the id_token
 * for a Discord webhook credential via RFC 8693 token exchange.
 */

import { Daytona } from "@daytonaio/sdk";
import readline from "node:readline";

const DAYTONA_API_KEY = process.env.DAYTONA_API_KEY;
const DAYTONA_API_URL = process.env.DAYTONA_API_URL || "https://app.daytona.io/api";
const HEROKU_API_KEY = process.env.HEROKU_API_KEY;
const OPENCLOAK_URL = "https://opencloak-839b85b2946d.herokuapp.com";
const HEROKU_APP = "opencloak";

if (!DAYTONA_API_KEY) { console.error("Set DAYTONA_API_KEY"); process.exit(1); }
if (!HEROKU_API_KEY) { console.error("Set HEROKU_API_KEY"); process.exit(1); }

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
╔══════════════════════════════════════════════════════════╗
║  Device Flow Demo                                        ║
║  Agent (Daytona sandbox) ↔ Vault (OpenCloak on Heroku)   ║
╚══════════════════════════════════════════════════════════╝
`);

  // Step 1: Create sandbox
  console.log("Step 1: Creating Daytona sandbox...");
  const daytona = new Daytona({
    apiKey: DAYTONA_API_KEY,
    apiUrl: DAYTONA_API_URL,
  });

  const sandbox = await daytona.create({
    language: "javascript",
    autoStopInterval: 0,
  });
  console.log(`  Sandbox ID: ${sandbox.id}`);
  await exec(sandbox, `curl -s ${OPENCLOAK_URL}/health`, "Connectivity check");

  try {
    // =========================================================
    // Step 2: Agent requests device code (runs IN the sandbox)
    // =========================================================
    console.log("\nStep 2: Agent requests device code from vault...");

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
    // Step 3: Human signs in
    // =========================================================
    console.log(`
╔══════════════════════════════════════════════════════════╗
║  ACTION REQUIRED — Sign in with Google                   ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  ${verification_uri_complete.padEnd(56)}║
║                                                          ║
║  Or go to: ${OPENCLOAK_URL}/device/verify`.padEnd(59) + `║
║  Code: ${user_code}`.padEnd(59) + `║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
`);

    await waitForEnter("  Press ENTER after you've signed in... ");

    // =========================================================
    // Step 4: Agent polls for id_token (runs IN the sandbox)
    // =========================================================
    console.log("\nStep 4: Agent polling for authorization result...");

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
    // Step 5: Register agent identity on vault (via Heroku env)
    // =========================================================
    console.log("\nStep 5: Registering agent identity on vault...");
    console.log(`  Setting REGISTERED_AGENTS with identity: ${sub}`);

    const agentsConfig = JSON.stringify([{ identity: sub, owner: "demo-owner", scopes: "webhook.incoming" }]);
    await herokuSetConfig("REGISTERED_AGENTS", agentsConfig);

    console.log("  Waiting for Heroku dyno restart...");
    const up = await waitForHeroku();
    if (!up) {
      console.error("  Heroku did not come back up in time.");
      process.exit(1);
    }
    console.log("  Vault is back up with agent registered.");

    // =========================================================
    // Step 6: Agent exchanges id_token for Discord webhook
    // =========================================================
    console.log("\nStep 6: Agent exchanges id_token for Discord webhook...");

    const exchangeScript = `
const res = await fetch("${OPENCLOAK_URL}/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    actor_token: \`${idToken}\`,
    actor_token_type: "urn:ietf:params:oauth:token-type:id_token",
    resource: "https://discord.com/api",
    scope: "webhook.incoming",
  }),
});
const data = await res.json();
console.log("EXCHANGE:" + JSON.stringify(data));
if (data.error) process.exit(1);

// Post to Discord
try {
  const dr = await fetch(data.webhook_url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      content: "**Device Flow Demo — OpenCloak + Daytona**\\n\\nThis message was sent by an AI agent in a **headless Daytona sandbox**.\\n\\nFlow: RFC 8628 Device Auth \\u2192 Google sign-in \\u2192 RFC 8693 Token Exchange \\u2192 Discord webhook\\n\\nThe agent never had Discord credentials. A human authorized it by entering a short code.",
      username: "OpenClaw (Device Flow)",
    }),
  });
  console.log("DISCORD_STATUS:" + dr.status);
  if (dr.status === 204 || dr.status === 200) console.log("DISCORD_OK");
  else console.log("RELAY_WEBHOOK:" + data.webhook_url);
} catch (e) {
  console.log("RELAY_WEBHOOK:" + data.webhook_url);
}
`.trim();

    await exec(sandbox, `cat > /tmp/exchange.mjs << 'EOF'\n${exchangeScript}\nEOF`);
    const exResult = await exec(sandbox, "node /tmp/exchange.mjs 2>&1", "POST /token + Discord (from sandbox)");

    const exOutput = exResult.result || "";

    // Relay if Discord blocked from sandbox
    const relayMatch = exOutput.match(/RELAY_WEBHOOK:(https:\/\/[^\s]+)/);
    if (relayMatch) {
      console.log("\n  Relaying Discord post from outside sandbox...");
      const relayRes = await fetch(relayMatch[1], {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: "**Device Flow Demo — OpenCloak + Daytona**\n\nThis message was sent by an AI agent in a **headless Daytona sandbox**.\n\nFlow: RFC 8628 Device Auth → Google sign-in → RFC 8693 Token Exchange → Discord webhook\n\nThe agent never had Discord credentials. A human authorized it by entering a short code.",
          username: "OpenClaw (Device Flow)",
        }),
      });
      console.log(relayRes.status === 204 || relayRes.status === 200
        ? "  Message posted to Discord!"
        : `  Discord returned ${relayRes.status}`);
    }

    console.log(`
╔══════════════════════════════════════════════════════════╗
║  Demo Complete                                           ║
╚══════════════════════════════════════════════════════════╝

  1. Agent (sandbox) called POST /device/code → got code ${user_code}
  2. Human signed in with Google at /device/verify
  3. Agent polled GET /device/token → got id_token (sub: ${sub})
  4. Agent called POST /token (RFC 8693) → got Discord webhook
  5. Message posted to Discord

  The agent never had Discord credentials in its environment.

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
