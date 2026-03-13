#!/usr/bin/env node

/**
 * Heroku startup script — seeds data directory then starts the server.
 * Heroku has an ephemeral filesystem, so we recreate the data on each dyno start.
 */

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { startServer } from "./server.mjs";

const DATA_DIR = process.env.OPENCLOAK_DATA_DIR || "/tmp/opencloak-data";
const PORT = parseInt(process.env.PORT || "3422", 10);
const ISSUER = process.env.OPENCLOAK_ISSUER || `http://localhost:${PORT}`;

// --- Seed data from environment variables ---

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

async function writeJson(collection, id, data) {
  const dir = path.join(DATA_DIR, collection);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(
    path.join(dir, `${id}.json`),
    JSON.stringify({ id, ...data }, null, 2),
    { mode: 0o600 }
  );
}

async function seed() {
  console.log(`Seeding data in ${DATA_DIR}...`);

  // Google issuer (for OIDC sign-in + device flow)
  if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
    await writeJson("issuers", "google", {
      issuer_url: "https://accounts.google.com",
      audience: GOOGLE_CLIENT_ID,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
    console.log("  Seeded issuer: google");
  }

  // Linear provider
  await writeJson("providers", "linear", {
    name: "linear",
    client_id: process.env.LINEAR_CLIENT_ID || "demo",
    client_secret: process.env.LINEAR_CLIENT_SECRET || "demo",
    authorize_url: "https://linear.app/oauth/authorize",
    token_url: "https://api.linear.app/oauth/token",
    revoke_url: "https://api.linear.app/oauth/revoke",
    resource_uri: "https://api.linear.app",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });
  console.log("  Seeded provider: linear");

  // Owner
  await writeJson("owners", "demo-owner", {
    display_name: "Gaurav",
    created_at: new Date().toISOString(),
  });
  console.log("  Seeded owner: demo-owner");

  // Registered agents (JSON: [{"identity":"...","owner":"..."},...])
  const agentsJson = process.env.REGISTERED_AGENTS;
  if (agentsJson) {
    try {
      const agents = JSON.parse(agentsJson);
      for (const a of agents) {
        const agentId = crypto.randomUUID();
        await writeJson("agents", agentId, {
          owner_id: a.owner || "demo-owner",
          identity: a.identity,
          created_at: new Date().toISOString(),
        });
        await writeJson("policies", `${agentId}:linear`, {
          agent_id: agentId,
          provider_id: "linear",
          allowed_scopes: (a.scopes || "issues:create,read").split(","),
          created_at: new Date().toISOString(),
        });
        console.log(`  Seeded agent: ${a.identity} → linear (${a.scopes || "issues:create,read"})`);
      }
    } catch (e) {
      console.error("  Failed to parse REGISTERED_AGENTS:", e.message);
    }
  }

  console.log("  Seed complete.\n");
}

async function main() {
  await seed();
  await startServer({
    port: PORT,
    issuer: ISSUER,
    dataDir: DATA_DIR,
  });
}

main().catch((err) => {
  console.error("Startup failed:", err);
  process.exit(1);
});
