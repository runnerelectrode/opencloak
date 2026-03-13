#!/usr/bin/env node

/**
 * Heroku startup script — seeds data directory then starts the server.
 * Heroku has an ephemeral filesystem, so we recreate the data on each dyno start.
 */

import fs from "node:fs/promises";
import path from "node:path";
import { startServer } from "./server.mjs";

const DATA_DIR = process.env.OPENCLOAK_DATA_DIR || "/tmp/opencloak-data";
const PORT = parseInt(process.env.PORT || "3422", 10);
const ISSUER = process.env.OPENCLOAK_ISSUER || `http://localhost:${PORT}`;

// --- Seed data from environment variables ---

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL;
const DISCORD_WEBHOOK_ID = process.env.DISCORD_WEBHOOK_ID;
const DISCORD_WEBHOOK_TOKEN = process.env.DISCORD_WEBHOOK_TOKEN;

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

  // Discord provider
  await writeJson("providers", "discord", {
    name: "discord",
    client_id: "demo-client-id",
    client_secret: "demo-client-secret",
    authorize_url: "https://discord.com/oauth2/authorize",
    token_url: "https://discord.com/api/oauth2/token",
    revoke_url: "https://discord.com/api/oauth2/token/revoke",
    resource_uri: "https://discord.com/api",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });
  console.log("  Seeded provider: discord");

  // Owner
  await writeJson("owners", "demo-owner", {
    display_name: "Gaurav",
    created_at: new Date().toISOString(),
  });
  console.log("  Seeded owner: demo-owner");

  // Discord webhook account
  if (DISCORD_WEBHOOK_URL && DISCORD_WEBHOOK_ID && DISCORD_WEBHOOK_TOKEN) {
    await writeJson("accounts", "demo-account", {
      owner_id: "demo-owner",
      provider_id: "discord",
      access_token: "not-used",
      refresh_token: "not-used",
      scopes_granted: "webhook.incoming",
      webhook_data: {
        id: DISCORD_WEBHOOK_ID,
        token: DISCORD_WEBHOOK_TOKEN,
        url: DISCORD_WEBHOOK_URL,
        channel_id: "644073406211555351",
        guild_id: "644073406211555348",
      },
      created_at: new Date().toISOString(),
    });
    console.log("  Seeded account: demo-account (discord webhook)");
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
