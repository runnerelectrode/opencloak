#!/usr/bin/env node

import { getAdapter, genId, DEFAULTS } from "./config.mjs";
import { startServer, getProviderInstance } from "./server.mjs";
import crypto from "node:crypto";

const COMMANDS = {
  start,
  "add-provider": addProvider,
  connect,
  exchange,
  list,
  policy: policyCmd,
  "register-agent": registerAgent,
  help,
};

let adapter;

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  if (!cmd || cmd === "--help" || cmd === "-h") return help();

  const handler = COMMANDS[cmd];
  if (!handler) {
    console.error(`Unknown command: ${cmd}`);
    console.error(`Run 'opencloak help' for usage.`);
    process.exit(1);
  }

  const opts = parseArgs(args);

  // Resolve data directory: --data-dir flag > OPENCLOAK_DATA_DIR env > default
  const dataDir = opts["data-dir"] || process.env.OPENCLOAK_DATA_DIR || undefined;
  adapter = getAdapter(dataDir);

  await handler(opts);
}

// --- Command handlers ---

async function start(opts) {
  const port = parseInt(opts.port || DEFAULTS.port, 10);
  const issuer = opts.issuer || `http://localhost:${port}`;
  const dataDir = opts["data-dir"] || process.env.OPENCLOAK_DATA_DIR || undefined;
  await startServer({ port, issuer, dataDir });
}

async function addProvider(opts) {
  const name = opts._positional[0];
  if (!name) {
    console.error("Usage: opencloak add-provider <name> --client-id X --client-secret Y");
    process.exit(1);
  }

  if (!opts["client-id"] || !opts["client-secret"]) {
    console.error("--client-id and --client-secret are required");
    process.exit(1);
  }

  const providerData = {
    name,
    client_id: opts["client-id"],
    client_secret: opts["client-secret"],
    created_at: new Date().toISOString(),
  };

  // Set provider-specific endpoints
  if (name === "discord") {
    providerData.authorize_url = "https://discord.com/oauth2/authorize";
    providerData.token_url = "https://discord.com/api/oauth2/token";
    providerData.revoke_url = "https://discord.com/api/oauth2/token/revoke";
    providerData.resource_uri = "https://discord.com/api";
  } else {
    // Generic provider — require endpoints
    if (!opts["authorize-url"] || !opts["token-url"]) {
      console.error("Generic providers require --authorize-url and --token-url");
      process.exit(1);
    }
    // Validate URLs are HTTPS
    for (const urlOpt of ["authorize-url", "token-url", "revoke-url"]) {
      const val = opts[urlOpt];
      if (val && !val.startsWith("https://")) {
        console.error(`--${urlOpt} must use HTTPS`);
        process.exit(1);
      }
    }
    providerData.authorize_url = opts["authorize-url"];
    providerData.token_url = opts["token-url"];
    providerData.revoke_url = opts["revoke-url"] || null;
    providerData.resource_uri = opts["resource-uri"] || null;
    providerData.provider_id = name;
  }

  const id = name; // use name as ID for simplicity (discord, github, etc.)
  await adapter.upsert("providers", id, providerData);
  console.log(`Provider '${name}' registered (id: ${id})`);
}

async function registerAgent(opts) {
  const tsIdentity = opts["ts-identity"];
  if (!tsIdentity) {
    console.error(
      "Usage: opencloak register-agent --ts-identity <email-or-tag> [--owner <owner-id>]"
    );
    process.exit(1);
  }

  // Find or create owner
  let ownerId = opts.owner;
  if (!ownerId) {
    // Auto-create a default owner
    const owners = await adapter.findAll("owners");
    let owner = owners[0]; // use first owner as default
    if (!owner) {
      ownerId = genId();
      owner = await adapter.upsert("owners", ownerId, {
        display_name: "default",
        created_at: new Date().toISOString(),
      });
      console.log(`Created default owner (id: ${ownerId})`);
    } else {
      ownerId = owner.id;
    }
  }

  const agentId = genId();
  await adapter.upsert("agents", agentId, {
    owner_id: ownerId,
    ts_identity: tsIdentity,
    created_at: new Date().toISOString(),
  });

  console.log(`Agent registered:`);
  console.log(`  id:          ${agentId}`);
  console.log(`  ts_identity: ${tsIdentity}`);
  console.log(`  owner_id:    ${ownerId}`);
}

async function policyCmd(opts) {
  const action = opts._positional[0];
  if (action !== "set") {
    console.error("Usage: opencloak policy set <ts-identity> <provider> --scopes <scopes>");
    process.exit(1);
  }

  const tsIdentity = opts._positional[1];
  const providerId = opts._positional[2];
  const scopes = opts.scopes;

  if (!tsIdentity || !providerId || !scopes) {
    console.error(
      "Usage: opencloak policy set <ts-identity> <provider> --scopes <comma-separated-scopes>"
    );
    process.exit(1);
  }

  // Find agent by ts_identity
  const agents = await adapter.findBy("agents", "ts_identity", tsIdentity);
  if (agents.length === 0) {
    console.error(
      `No agent found with ts_identity '${tsIdentity}'. Register one first.`
    );
    process.exit(1);
  }
  const agent = agents[0];

  const scopeList = scopes.split(",").map((s) => s.trim());
  const policyId = `${agent.id}:${providerId}`;

  await adapter.upsert("policies", policyId, {
    agent_id: agent.id,
    provider_id: providerId,
    allowed_scopes: scopeList,
    created_at: new Date().toISOString(),
  });

  console.log(`Policy set:`);
  console.log(`  agent:    ${tsIdentity} (${agent.id})`);
  console.log(`  provider: ${providerId}`);
  console.log(`  scopes:   ${scopeList.join(", ")}`);
}

async function connect(opts) {
  const providerName = opts._positional[0];
  if (!providerName) {
    console.error("Usage: opencloak connect <provider> [--scopes 'scope1 scope2']");
    process.exit(1);
  }

  const providerConfig = await adapter.find("providers", providerName);
  if (!providerConfig) {
    console.error(
      `Provider '${providerName}' not registered. Run 'opencloak add-provider' first.`
    );
    process.exit(1);
  }

  const scopes = opts.scopes ? opts.scopes.split(" ") : ["identify"];
  const state = crypto.randomBytes(16).toString("hex");
  const port = parseInt(opts.port || DEFAULTS.port, 10);
  const issuer = opts.issuer || `http://localhost:${port}`;
  const redirectUri = `${issuer}/oauth/callback/${providerName}`;

  // Ensure we have an owner
  let owners = await adapter.findAll("owners");
  let owner = owners[0];
  if (!owner) {
    const ownerId = genId();
    owner = await adapter.upsert("owners", ownerId, {
      display_name: "default",
      created_at: new Date().toISOString(),
    });
    console.log(`Created default owner (id: ${ownerId})`);
  }

  // Store pending session for state validation on callback
  await adapter.upsert("sessions", state, {
    provider_id: providerConfig.id,
    owner_id: owner.id,
    scopes: scopes.join(" "),
    created_at: new Date().toISOString(),
  });

  const providerInstance = getProviderInstance(providerConfig);
  const authorizeUrl = providerInstance.getAuthorizeUrl(scopes, state, redirectUri);

  console.log(`\nOpen this URL in your browser to authorize:\n`);
  console.log(`  ${authorizeUrl}\n`);
  console.log(`Callback will be received at: ${redirectUri}`);
  console.log(`Make sure the vault server is running (opencloak start)`);
}

async function exchange(opts) {
  const provider = opts.provider;
  const scope = opts.scope;
  const actorToken = opts["actor-token"];
  const port = parseInt(opts.port || DEFAULTS.port, 10);

  if (!provider || !scope) {
    console.error(
      "Usage: opencloak exchange --provider <name> --scope <scope> [--actor-token <token>]"
    );
    process.exit(1);
  }

  const providerConfig = await adapter.find("providers", provider);
  if (!providerConfig) {
    console.error(`Provider '${provider}' not found`);
    process.exit(1);
  }

  const body = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    actor_token: actorToken || "dev-token",
    actor_token_type: "urn:ietf:params:oauth:token-type:id_token",
    resource: providerConfig.resource_uri || `https://${provider}.com/api`,
    scope,
  });

  try {
    const res = await fetch(`http://localhost:${port}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    const data = await res.json();
    // Redact sensitive tokens in CLI output
    const display = { ...data };
    if (display.access_token) {
      display.access_token = display.access_token.slice(0, 8) + "...REDACTED";
    }
    console.log(JSON.stringify(display, null, 2));
  } catch (err) {
    console.error(`Exchange request failed: ${err.message}`);
    console.error("Make sure the vault server is running (opencloak start)");
    process.exit(1);
  }
}

async function list() {
  console.log("\n=== Providers ===");
  const providers = await adapter.findAll("providers");
  if (providers.length === 0) {
    console.log("  (none)");
  } else {
    for (const p of providers) {
      console.log(`  ${p.id} (${p.name}) — client_id: ${p.client_id}`);
    }
  }

  console.log("\n=== Owners ===");
  const owners = await adapter.findAll("owners");
  if (owners.length === 0) {
    console.log("  (none)");
  } else {
    for (const o of owners) {
      console.log(`  ${o.id} — ${o.display_name}`);
    }
  }

  console.log("\n=== Agents ===");
  const agents = await adapter.findAll("agents");
  if (agents.length === 0) {
    console.log("  (none)");
  } else {
    for (const a of agents) {
      console.log(`  ${a.id} — ts_identity: ${a.ts_identity}, owner: ${a.owner_id}`);
    }
  }

  console.log("\n=== Connected Accounts ===");
  const accounts = await adapter.findAll("accounts");
  if (accounts.length === 0) {
    console.log("  (none)");
  } else {
    for (const a of accounts) {
      console.log(
        `  ${a.id} — provider: ${a.provider_id}, owner: ${a.owner_id}, scopes: ${a.scopes_granted}`
      );
    }
  }

  console.log("\n=== Policies ===");
  const policies = await adapter.findAll("policies");
  if (policies.length === 0) {
    console.log("  (none)");
  } else {
    for (const p of policies) {
      console.log(
        `  ${p.id} — agent: ${p.agent_id}, provider: ${p.provider_id}, scopes: ${p.allowed_scopes?.join(", ")}`
      );
    }
  }

  console.log("");
}

function help() {
  console.log(`
OpenCloak — OAuth vault for AI agents

Usage: opencloak <command> [options]

Global Options:
  --data-dir <path>                                Data directory (default: ~/.config/opencloak)
                                                   Also settable via OPENCLOAK_DATA_DIR env var

Commands:
  start [--port 3422]                              Start the vault server
  add-provider <name> --client-id X --client-secret Y
                                                   Register an OAuth provider
  register-agent --ts-identity <email-or-tag>      Register an agent by Tailscale identity
  policy set <ts-identity> <provider> --scopes <s>  Set agent permissions
  connect <provider> [--scopes "s1 s2"]            Start OAuth consent flow
  exchange --provider <name> --scope <scope>       Manual token exchange (dev)
  list                                             Show all registered entities
  help                                             Show this help

Examples:
  opencloak start --data-dir ./local-data --port 3422
  opencloak add-provider discord --client-id 123 --client-secret abc --data-dir ./local-data
  opencloak register-agent --ts-identity user@example.com
  opencloak policy set user@example.com discord --scopes "identify,guilds"
  opencloak connect discord --scopes "identify guilds"
`);
}

// --- Arg parser ---

function parseArgs(args) {
  const result = { _positional: [] };
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      const key = args[i].slice(2);
      const next = args[i + 1];
      if (next && !next.startsWith("--")) {
        result[key] = next;
        i++;
      } else {
        result[key] = true;
      }
    } else {
      result._positional.push(args[i]);
    }
  }
  return result;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
