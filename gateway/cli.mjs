#!/usr/bin/env node

import { getGatewayAdapter, resolveConfig } from "./config.mjs";
import { startGateway } from "./server.mjs";

// --- Provider presets ---
const PRESETS = {
  anthropic: {
    upstream_base_url: "https://api.anthropic.com",
    auth_header: "x-api-key",
    auth_scheme: null,
    extra_headers: { "anthropic-version": "2023-06-01" },
    allowed_paths: ["/v1/messages", "/v1/complete"],
  },
  openai: {
    upstream_base_url: "https://api.openai.com",
    auth_header: "Authorization",
    auth_scheme: "Bearer",
    extra_headers: {},
    allowed_paths: ["/v1/chat/completions", "/v1/responses"],
  },
  openrouter: {
    upstream_base_url: "https://openrouter.ai/api",
    auth_header: "Authorization",
    auth_scheme: "Bearer",
    extra_headers: {},
    allowed_paths: ["/v1/chat/completions"],
  },
};

const COMMANDS = {
  start,
  llm: llmCmd,
  help,
};

let adapter;

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  if (!cmd || cmd === "--help" || cmd === "-h") return help();

  const handler = COMMANDS[cmd];
  if (!handler) {
    console.error(`Unknown command: ${cmd}`);
    console.error(`Run 'opencloak-gateway help' for usage.`);
    process.exit(1);
  }

  const opts = parseArgs(args);
  const config = resolveConfig(opts);
  adapter = getGatewayAdapter(config.dataDir);

  await handler(opts, config);
}

// --- Command handlers ---

async function start(opts, config) {
  if (!config.jwksUrl) {
    console.error("--jwks-url is required (or set OPENCLOAK_GATEWAY_JWKS_URL)");
    process.exit(1);
  }
  await startGateway(config);
}

async function llmCmd(opts) {
  const action = opts._positional[0];
  if (action === "add") return llmAdd(opts);
  if (action === "list") return llmList();
  if (action === "remove") return llmRemove(opts);
  console.error("Usage: opencloak-gateway llm <add|list|remove>");
  process.exit(1);
}

async function llmAdd(opts) {
  const name = opts._positional[1];
  if (!name) {
    console.error("Usage: opencloak-gateway llm add <provider> --api-key <key>");
    process.exit(1);
  }

  const apiKey = opts["api-key"];
  if (!apiKey) {
    console.error("--api-key is required");
    process.exit(1);
  }

  const preset = PRESETS[name];
  let providerData;

  if (preset) {
    // Known provider — use preset
    providerData = {
      type: "llm",
      api_key: apiKey,
      ...preset,
    };
  } else {
    // Custom provider
    const upstreamUrl = opts["upstream-url"];
    if (!upstreamUrl) {
      console.error("Custom providers require --upstream-url");
      process.exit(1);
    }
    // Validate HTTPS (or localhost for dev)
    try {
      const parsed = new URL(upstreamUrl);
      const isLocal = parsed.protocol === "http:" &&
        (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1");
      if (parsed.protocol !== "https:" && !isLocal) {
        console.error("--upstream-url must use HTTPS (or http://localhost for dev)");
        process.exit(1);
      }
    } catch {
      console.error("--upstream-url must be a valid URL");
      process.exit(1);
    }

    providerData = {
      type: "llm",
      api_key: apiKey,
      upstream_base_url: upstreamUrl,
      auth_header: opts["auth-header"] || "Authorization",
      auth_scheme: opts["auth-scheme"] || "Bearer",
      extra_headers: {},
      allowed_paths: [], // custom: allow all by default
    };
  }

  await adapter.upsert("providers", name, providerData);
  console.log(`LLM provider '${name}' registered:`);
  console.log(`  upstream: ${providerData.upstream_base_url}`);
  console.log(`  auth:     ${providerData.auth_header}${providerData.auth_scheme ? ` (${providerData.auth_scheme})` : " (raw)"}`);
  if (providerData.allowed_paths.length > 0) {
    console.log(`  paths:    ${providerData.allowed_paths.join(", ")}`);
  } else {
    console.log(`  paths:    (all allowed)`);
  }
}

async function llmList() {
  const providers = await adapter.findAll("providers");
  const llmProviders = providers.filter((p) => p.type === "llm");

  if (llmProviders.length === 0) {
    console.log("No LLM providers configured.");
    return;
  }

  console.log("\nLLM Providers:");
  for (const p of llmProviders) {
    const keyPreview = p.api_key
      ? (p.api_key.startsWith("enc:") ? "(encrypted)" : p.api_key.slice(0, 8) + "...REDACTED")
      : "(none)";
    console.log(`  ${p.id}`);
    console.log(`    upstream: ${p.upstream_base_url}`);
    console.log(`    api_key:  ${keyPreview}`);
    if (p.allowed_paths && p.allowed_paths.length > 0) {
      console.log(`    paths:    ${p.allowed_paths.join(", ")}`);
    }
  }
  console.log("");
}

async function llmRemove(opts) {
  const name = opts._positional[1];
  if (!name) {
    console.error("Usage: opencloak-gateway llm remove <provider>");
    process.exit(1);
  }
  await adapter.destroy("providers", name);
  console.log(`LLM provider '${name}' removed.`);
}

function help() {
  console.log(`
OpenCloak Gateway — LLM credential proxy

Usage: opencloak-gateway <command> [options]

Commands:
  start --jwks-url <url> [--port 3423] [--data-dir DIR]
                                         Start the gateway server
  llm add <provider> --api-key <key>     Register an LLM provider
  llm add <name> --api-key <key> --upstream-url <url> [--auth-header H] [--auth-scheme S]
                                         Register a custom LLM provider
  llm list                               List registered LLM providers
  llm remove <provider>                  Remove an LLM provider
  help                                   Show this help

Built-in presets: anthropic, openai, openrouter

Environment variables:
  OPENCLOAK_GATEWAY_JWKS_URL     JWKS endpoint for JWT verification
  OPENCLOAK_GATEWAY_DATA_DIR     Data directory (default: ~/.config/opencloak-gateway)
  OPENCLOAK_ENCRYPTION_KEY       Encryption key for API keys at rest
  PORT                           Server port (default: 3423)

Examples:
  opencloak-gateway llm add anthropic --api-key sk-ant-...
  opencloak-gateway llm add openai --api-key sk-...
  opencloak-gateway start --jwks-url http://localhost:3422/jwks
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
