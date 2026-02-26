import { verifyActorToken } from "../verifiers/index.mjs";
import { evaluatePolicy, findAgentByIdentity } from "../policy.mjs";
import { getProviderInstance } from "../server.mjs";

const TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token";

/**
 * Handle an RFC 8693 token exchange request.
 *
 * @param {object} params - Parsed URL-encoded body
 * @param {object} adapter - Storage adapter
 * @returns {{ status: number, body: object }}
 */
export async function handleTokenExchange(params, adapter) {
  const {
    actor_token,
    actor_token_type,
    subject_token,
    subject_token_type,
    resource,
    scope,
  } = params;

  // --- Validate required parameters ---
  if (!actor_token) {
    return error(400, "invalid_request", "actor_token is required");
  }
  if (!actor_token_type) {
    return error(400, "invalid_request", "actor_token_type is required");
  }
  if (!resource) {
    return error(400, "invalid_request", "resource is required");
  }

  // --- 1. Verify actor token (tsidp OIDC) ---
  let identity;
  try {
    identity = await verifyActorToken(actor_token, actor_token_type);
  } catch (err) {
    console.error("Actor token verification failed:", err.message);
    return error(401, "invalid_grant", "actor_token verification failed");
  }

  // --- 2. Look up agent by Tailscale identity ---
  const agent = await findAgentByIdentity(adapter, identity.sub);
  if (!agent) {
    return error(403, "invalid_grant", "agent not authorized");
  }

  // --- 3. Resolve provider from resource URI ---
  const providers = await adapter.findAll("providers");
  let providerConfig = null;
  let providerInstance = null;

  for (const p of providers) {
    const inst = getProviderInstance(p);
    if (inst && inst.matchesResource(resource)) {
      providerConfig = p;
      providerInstance = inst;
      break;
    }
  }

  if (!providerInstance) {
    return error(
      400,
      "invalid_target",
      "no provider configured for the requested resource"
    );
  }

  // --- 4. Evaluate policy ---
  const requestedScopes = scope ? scope.split(" ") : [];
  if (requestedScopes.length === 0) {
    return error(400, "invalid_scope", "at least one scope is required");
  }

  const policyResult = await evaluatePolicy(
    adapter,
    agent.id,
    providerConfig.id,
    requestedScopes
  );

  if (!policyResult.allowed) {
    return error(403, "invalid_scope", policyResult.error);
  }

  const account = policyResult.account;

  // --- 5. Handle webhook mode ---
  if (
    policyResult.scopes.includes("webhook.incoming") &&
    account.webhook_data
  ) {
    return {
      status: 200,
      body: {
        access_token: account.webhook_data.token,
        issued_token_type: TOKEN_TYPE_ACCESS,
        token_type: "webhook",
        scope: "webhook.incoming",
        webhook_url: account.webhook_data.url,
        webhook_id: account.webhook_data.id,
      },
    };
  }

  // --- 6. Refresh access token from provider ---
  if (!account.refresh_token) {
    return error(
      400,
      "invalid_grant",
      "connected account has no refresh token — re-connect the provider"
    );
  }

  let tokenData;
  try {
    tokenData = await providerInstance.refreshToken(account.refresh_token);
  } catch (err) {
    console.error("Provider token refresh failed:", err.message);
    return error(502, "invalid_grant", "provider token refresh failed");
  }

  // --- 7. Persist new tokens atomically ---
  const expiresAt = tokenData.expires_in
    ? new Date(Date.now() + tokenData.expires_in * 1000).toISOString()
    : null;

  try {
    if (
      tokenData.refresh_token &&
      tokenData.refresh_token !== account.refresh_token
    ) {
      await adapter.rotateRefreshToken(
        account.id,
        account.refresh_token,
        tokenData.refresh_token,
        tokenData.access_token,
        expiresAt
      );
    } else {
      await adapter.updateAccessToken(
        account.id,
        tokenData.access_token,
        expiresAt
      );
    }
  } catch (err) {
    console.error("Token persistence failed:", err.message);
    // Still return the token — it's valid even if persistence failed
  }

  // --- 8. Return RFC 8693 response ---
  return {
    status: 200,
    body: {
      access_token: tokenData.access_token,
      issued_token_type: TOKEN_TYPE_ACCESS,
      token_type: "Bearer",
      expires_in: tokenData.expires_in || 604800,
      scope: policyResult.scopes.join(" "),
    },
  };
}

function error(status, code, description) {
  return {
    status,
    body: { error: code, error_description: description },
  };
}
