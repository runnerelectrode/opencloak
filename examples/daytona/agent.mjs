#!/usr/bin/env node

/**
 * Example: Agent running inside a Daytona sandbox
 *
 * This is what your AI agent's code looks like when using OpenCloak.
 * It runs INSIDE the Daytona sandbox where OpenCloak is installed.
 * The agent never touches OAuth credentials — it only talks to OpenCloak.
 *
 * Flow:
 *   Agent → OpenCloak (localhost:3422) → gets scoped token → calls GitHub/Discord/Slack
 */

const OPENCLOAK_URL = process.env.OPENCLOAK_URL || "http://localhost:3422";

/**
 * Request a scoped token from OpenCloak via RFC 8693 token exchange.
 *
 * @param {string} identityToken - The agent's identity proof (OIDC token, sandbox token, etc.)
 * @param {string} resource - The API to access (e.g., "https://api.github.com")
 * @param {string} scope - The scope to request (e.g., "repo", "webhook.incoming")
 * @returns {object} Token response with access_token, scope, expires_in, etc.
 */
async function getToken(identityToken, resource, scope) {
  const res = await fetch(`${OPENCLOAK_URL}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      actor_token: identityToken,
      actor_token_type: "urn:ietf:params:oauth:token-type:id_token",
      resource,
      scope,
    }),
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(`OpenCloak error: ${err.error} — ${err.error_description}`);
  }

  return res.json();
}

// --- Example usage ---

async function main() {
  // In production, this token comes from your identity provider
  // (Daytona workspace token, OIDC token, etc.)
  const identityToken = process.env.AGENT_IDENTITY_TOKEN || "demo-token";

  console.log("=== Agent requesting GitHub access via OpenCloak ===\n");

  try {
    // Request a scoped GitHub token — agent only gets what policy allows
    const tokenResponse = await getToken(
      identityToken,
      "https://api.github.com",
      "read:user"
    );

    console.log("Token received from OpenCloak:");
    console.log(`  scope:      ${tokenResponse.scope}`);
    console.log(`  expires_in: ${tokenResponse.expires_in}s`);
    console.log(`  token_type: ${tokenResponse.token_type}`);
    console.log();

    // Use the scoped token to call GitHub
    const userRes = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${tokenResponse.access_token}`,
        "User-Agent": "OpenClaw-Agent",
      },
    });

    if (userRes.ok) {
      const user = await userRes.json();
      console.log(`GitHub user: ${user.login} (${user.name})`);
      console.log(`Public repos: ${user.public_repos}`);
    } else {
      console.log(`GitHub API returned: ${userRes.status}`);
    }
  } catch (err) {
    console.error(err.message);
  }

  console.log("\n=== Agent requesting Discord webhook via OpenCloak ===\n");

  try {
    // Request a Discord webhook — agent can only post messages, nothing else
    const webhookResponse = await getToken(
      identityToken,
      "https://discord.com/api",
      "webhook.incoming"
    );

    console.log("Webhook received from OpenCloak:");
    console.log(`  scope: ${webhookResponse.scope}`);

    if (webhookResponse.webhook_url) {
      // Post a message using the webhook
      await fetch(webhookResponse.webhook_url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: "Hello from OpenClaw via OpenCloak!",
        }),
      });
      console.log("  Message posted to Discord.");
    }
  } catch (err) {
    console.error(err.message);
  }
}

main();
