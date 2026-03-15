#!/usr/bin/env node

/**
 * OpenClaw Skill Demo: Agent discovers OpenCloak auth skill autonomously
 *
 * Unlike openclaw-demo.mjs (which gives the agent explicit curl commands),
 * this demo installs the opencloak-auth SKILL.md and prompts the agent with
 * just "create a Linear issue" — the agent discovers the skill and handles
 * device flow + token exchange on its own.
 *
 * Architecture:
 *   Daytona Sandbox (daytona-medium)
 *   ├── OpenClaw agent --local (preinstalled, uses Anthropic or OpenRouter)
 *   ├── opencloak-auth skill (installed in ~/.openclaw/skills/)
 *   └── Talks to:
 *       ├── OpenCloak vault (Heroku) — device flow + token exchange
 *       └── Linear API — creates an issue with the Bearer token
 *
 * Usage:
 *   export DAYTONA_API_KEY=your-key
 *   export ANTHROPIC_API_KEY=your-key   # or OPENROUTER_API_KEY
 *   export HEROKU_API_KEY=your-key
 *   export LINEAR_TEAM_ID=f6442499-53cb-4bf3-be79-5291905bc325
 *   node examples/daytona/openclaw-skill-demo.mjs
 */

import { Daytona } from "@daytonaio/sdk";
import readline from "node:readline";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const DAYTONA_API_KEY = process.env.DAYTONA_API_KEY;
const DAYTONA_API_URL = process.env.DAYTONA_API_URL || "https://app.daytona.io/api";
const LLM_API_KEY = process.env.ANTHROPIC_API_KEY || process.env.OPENROUTER_API_KEY;
const LLM_ENV_NAME = process.env.ANTHROPIC_API_KEY ? "ANTHROPIC_API_KEY" : "OPENROUTER_API_KEY";
const LLM_MODEL = process.env.ANTHROPIC_API_KEY ? "anthropic/claude-haiku-4-5-20251001" : "openrouter/anthropic/claude-3.5-haiku";
const HEROKU_API_KEY = process.env.HEROKU_API_KEY;
const LINEAR_TEAM_ID = process.env.LINEAR_TEAM_ID;
const OPENCLOAK_URL = process.env.OPENCLOAK_URL || "https://opencloak-839b85b2946d.herokuapp.com";
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

async function herokuGetConfig() {
  const resp = await fetch(`https://api.heroku.com/apps/${HEROKU_APP}/config-vars`, {
    headers: {
      "Authorization": `Bearer ${HEROKU_API_KEY}`,
      "Accept": "application/vnd.heroku+json; version=3",
    },
  });
  if (!resp.ok) throw new Error(`Heroku config get failed: ${resp.status}`);
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
║  OpenClaw Skill Demo                                         ║
║  Agent discovers opencloak-auth skill autonomously            ║
║  No explicit curl commands — just "create a Linear issue"     ║
╚══════════════════════════════════════════════════════════════╝
`);

  // =========================================================
  // Step 1: Check if agent identity is already registered
  // =========================================================
  console.log("Step 1: Checking vault for existing agent registration...");
  const config = await herokuGetConfig();
  let needsRegistration = !config.REGISTERED_AGENTS;
  if (config.REGISTERED_AGENTS) {
    try {
      const agents = JSON.parse(config.REGISTERED_AGENTS);
      console.log(`  Found ${agents.length} registered agent(s): ${agents.map(a => a.identity).join(", ")}`);
    } catch {
      needsRegistration = true;
    }
  }

  // =========================================================
  // Step 2: Create sandbox
  // =========================================================
  console.log("\nStep 2: Creating Daytona sandbox (daytona-medium, OpenClaw preinstalled)...");
  const daytona = new Daytona({
    apiKey: DAYTONA_API_KEY,
    apiUrl: DAYTONA_API_URL,
  });

  const sandbox = await daytona.create({
    snapshot: "daytona-medium",
    name: `openclaw-skill-demo-${Date.now()}`,
    autoStopInterval: 0,
    language: "javascript",
  });
  console.log(`  Sandbox ID: ${sandbox.id}`);

  try {
    // =========================================================
    // Step 3: Verify OpenClaw + configure model
    // =========================================================
    console.log("\nStep 3: Configuring OpenClaw...");
    await exec(sandbox, "which openclaw && openclaw --version", "OpenClaw check");
    await exec(sandbox, `${LLM_ENV_NAME}=${LLM_API_KEY} openclaw models set ${LLM_MODEL} 2>&1`);
    await exec(sandbox, `curl -s ${OPENCLOAK_URL}/health`, "Vault connectivity check");

    // =========================================================
    // Step 4: If no agent registered, do identity discovery
    // =========================================================
    if (needsRegistration) {
      console.log("\nStep 4: No agent registered — running identity discovery...");
      console.log("  (This is a one-time setup. Future runs will skip this step.)");

      const requestCodeScript = `
const res = await fetch("${OPENCLOAK_URL}/device/code", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: "issuer_id=google",
});
console.log(JSON.stringify(await res.json()));
`.trim();

      await exec(sandbox, `cat > /tmp/request-code.mjs << 'EOF'\n${requestCodeScript}\nEOF`);
      const codeResult = await exec(sandbox, "node /tmp/request-code.mjs 2>&1", "POST /device/code");

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

      console.log(`
╔══════════════════════════════════════════════════════════════╗
║  ONE-TIME SETUP — Sign in to register your identity          ║
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

      const pollScript = `
let attempts = 0;
while (attempts < 24) {
  attempts++;
  const res = await fetch("${OPENCLOAK_URL}/device/token?device_code=${device_code}");
  const data = await res.json();
  if (data.id_token) {
    console.log("SUB:" + data.claims.sub);
    console.log("EMAIL:" + (data.claims.email || "n/a"));
    process.exit(0);
  }
  if (data.error === "expired_token") { console.log("EXPIRED"); process.exit(1); }
  await new Promise(r => setTimeout(r, data.error === "slow_down" ? 10000 : 5000));
}
console.log("TIMEOUT"); process.exit(1);
`.trim();

      await exec(sandbox, `cat > /tmp/poll.mjs << 'EOF'\n${pollScript}\nEOF`);
      const pollResult = await exec(sandbox, "node /tmp/poll.mjs 2>&1", "Polling for identity");

      const pollOutput = pollResult.result || "";
      const sub = pollOutput.match(/SUB:(.+)/)?.[1]?.trim();
      const email = pollOutput.match(/EMAIL:(.+)/)?.[1]?.trim();

      if (!sub) {
        console.error("\nFailed to get identity:", pollOutput);
        process.exit(1);
      }

      console.log(`\n  Identity discovered: sub=${sub} email=${email}`);
      console.log("  Registering agent on vault...");

      const agentsConfig = JSON.stringify([{ identity: sub, owner: "demo-owner", scopes: "issues:create,read" }]);
      await herokuSetConfig("REGISTERED_AGENTS", agentsConfig);

      console.log("  Waiting for Heroku dyno restart...");
      const up = await waitForHeroku();
      if (!up) {
        console.error("  Heroku did not come back up in time.");
        process.exit(1);
      }
      console.log("  Vault is back up with agent registered.");
    } else {
      console.log("\nStep 4: Agent already registered — skipping identity discovery.");
    }

    // =========================================================
    // Step 5: Install opencloak-auth skill in sandbox
    // =========================================================
    console.log("\nStep 5: Installing opencloak-auth skill in sandbox...");

    const skillPath = path.resolve(__dirname, "../../skills/opencloak-auth/SKILL.md");
    const skillContent = await fs.readFile(skillPath, "utf-8");

    await exec(sandbox, "mkdir -p ~/.openclaw/skills/opencloak-auth");

    // Write SKILL.md via heredoc — use a unique delimiter to avoid conflicts with content
    await exec(sandbox, `cat > ~/.openclaw/skills/opencloak-auth/SKILL.md << 'SKILLEOF'\n${skillContent}\nSKILLEOF`);
    await exec(sandbox, "cat ~/.openclaw/skills/opencloak-auth/SKILL.md | head -5", "Skill installed");

    // =========================================================
    // Step 6: Prompt agent — skill handles auth autonomously
    // =========================================================
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║  Prompting OpenClaw agent                                    ║
║  The agent has NO credentials and NO explicit instructions    ║
║  It must discover the opencloak-auth skill on its own         ║
╚══════════════════════════════════════════════════════════════╝
`);

    const agentPrompt = `Create a Linear issue with title "OpenClaw Skill Demo — Autonomous Auth" and description "Created by an OpenClaw agent that discovered the opencloak-auth skill autonomously. No credentials were provided — the agent used RFC 8628 device flow and RFC 8693 token exchange via OpenCloak." in team ${LINEAR_TEAM_ID} with state ${TODO_STATE_ID}. Report the issue identifier and URL when done.`;

    await exec(sandbox, `cat > /tmp/agent-prompt.txt << 'PROMPTEOF'\n${agentPrompt}\nPROMPTEOF`);

    // Write the agent command to a shell script to avoid quoting issues
    const agentScript = `#!/bin/bash
export ${LLM_ENV_NAME}="${LLM_API_KEY}"
export OPENCLOAK_URL="${OPENCLOAK_URL}"
openclaw agent --local --session-id opencloak-skill-demo -m "$(cat /tmp/agent-prompt.txt)" --json 2>&1
`;
    console.log("  Starting agent (running in background to monitor output)...\n");

    await exec(sandbox, `cat > /tmp/run-agent.sh << 'SCRIPTEOF'\n${agentScript}\nSCRIPTEOF`);
    await exec(sandbox, "chmod +x /tmp/run-agent.sh");
    await exec(sandbox, "nohup /tmp/run-agent.sh > /tmp/agent-output.log 2>&1 &");

    // Give the process a moment to start
    await new Promise(r => setTimeout(r, 5000));

    // Monitor agent output for verification URL (silent reads — no labels)
    let verificationShown = false;
    let agentDone = false;
    let agentOutput = "";
    const startTime = Date.now();
    const MAX_WAIT_MS = 300000; // 5 minutes

    while (!agentDone && (Date.now() - startTime) < MAX_WAIT_MS) {
      await new Promise(r => setTimeout(r, 3000));

      const logResult = await sandbox.process.executeCommand("cat /tmp/agent-output.log 2>/dev/null");
      agentOutput = logResult.result?.trim() || "";

      // Check if agent surfaced a verification URL
      if (!verificationShown) {
        const urlMatch = agentOutput.match(/https?:\/\/[^\s"']+device\/verify[^\s"']*/);
        const codeMatch = agentOutput.match(/[A-Z0-9]{4}-[A-Z0-9]{4}/);

        if (urlMatch || codeMatch) {
          verificationShown = true;
          console.log(`
╔══════════════════════════════════════════════════════════════╗
║  AGENT NEEDS AUTHORIZATION — Sign in with Google             ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  The agent discovered the skill and started the device flow!  ║
║                                                              ║`);
          if (urlMatch) {
            console.log(`║  ${urlMatch[0].padEnd(60)}║`);
          }
          if (codeMatch) {
            console.log(`║  Code: ${codeMatch[0]}`.padEnd(63) + `║`);
          }
          console.log(`║                                                              ║
╚══════════════════════════════════════════════════════════════╝
`);
          await waitForEnter("  Press ENTER after you've signed in... ");
          console.log("\n  Waiting for agent to complete token exchange + issue creation...\n");
        }
      }

      // Check if agent process finished (silent — no label)
      const psResult = await sandbox.process.executeCommand("pgrep -f 'run-agent.sh' > /dev/null 2>&1 && echo RUNNING || echo DONE");
      if (psResult.result?.trim() === "DONE") {
        const finalLog = await sandbox.process.executeCommand("cat /tmp/agent-output.log 2>/dev/null");
        agentOutput = finalLog.result?.trim() || "";
        agentDone = true;
      } else {
        // Show progress dots
        process.stdout.write(".");
      }
    }

    if (!agentDone) {
      console.log("\n  Agent timed out. Killing process...");
      await exec(sandbox, "pkill -f 'run-agent.sh' 2>/dev/null; pkill -f 'openclaw agent' 2>/dev/null || true");
      const finalLog = await sandbox.process.executeCommand("cat /tmp/agent-output.log 2>/dev/null");
      agentOutput = finalLog.result?.trim() || "";
    }

    // =========================================================
    // Step 7: Parse results
    // =========================================================
    console.log("\n--- Agent output ---");
    agentOutput.split("\n").forEach((l) => console.log(`  ${l}`));

    const issueUrlMatch = agentOutput.match(/https:\/\/linear\.app\/[^\s"')}\]]+/);
    const issueIdMatch = agentOutput.match(/\b([A-Z]+-\d+)\b/);
    const issueUrl = issueUrlMatch?.[0];
    const issueId = issueIdMatch?.[1];

    const succeeded = agentOutput.includes("success") || agentOutput.includes("identifier") || issueUrl;

    if (!succeeded) {
      console.log("\n  Agent may not have completed successfully.");
      console.log("  Check the full output above for details.");
    }

    console.log(`
╔══════════════════════════════════════════════════════════════╗
║  Skill Demo Complete                                         ║
╚══════════════════════════════════════════════════════════════╝

  What happened:
  1. Created Daytona sandbox (daytona-medium, OpenClaw preinstalled)
  2. Configured OpenClaw (${LLM_MODEL})
  3. Installed opencloak-auth SKILL.md in ~/.openclaw/skills/
  4. Prompted agent: "Create a Linear issue" (no curl commands, no tokens)
  5. Agent discovered the opencloak-auth skill autonomously
  6. Agent ran device flow → human signed in → got id_token
  7. Agent exchanged id_token for Linear Bearer token (RFC 8693)
  8. Agent created Linear issue${issueId ? ` ${issueId}` : ""}${issueUrl ? `\n     ${issueUrl}` : ""}

  Key difference from openclaw-demo.mjs:
  - The agent was NOT given explicit curl commands or an id_token
  - It discovered the skill and figured out the auth flow on its own
  - The only input was: "Create a Linear issue"

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
