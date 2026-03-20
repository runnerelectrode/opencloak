import crypto from "node:crypto";
import { verifyActorToken } from "../verifiers/index.mjs";
import { evaluatePolicy, findAgentByIdentity } from "../policy.mjs";
import { getProviderInstance } from "../server.mjs";

const TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token";
const TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt";

/**
 * Handle an RFC 8693 token exchange request.
 *
 * @param {object} params - Parsed URL-encoded body
 * @param {object} adapter - Storage adapter
 * @param {string} [issuer] - Vault issuer URL (for LLM JWT minting)
 * @param {object} [jwksData] - Vault JWKS data (for LLM JWT signing)
 * @returns {{ status: number, body: object }}
 */
export async function handleTokenExchange(params, adapter, issuer, jwksData) {
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

  // --- 1. Verify actor token (OIDC) ---
  let identity;
  try {
    identity = await verifyActorToken(actor_token, actor_token_type);
  } catch (err) {
    console.error("Actor token verification failed:", err.message);
    return error(401, "invalid_grant", "actor_token verification failed");
  }

  // --- 2. Look up agent by identity ---
  const agent = await findAgentByIdentity(adapter, identity.sub);
  if (!agent) {
    return error(403, "invalid_grant", "agent not authorized");
  }

  // --- 3. Check for LLM scope → LLM branch (before OAuth instantiation) ---
  const requestedScopes = scope ? scope.split(" ") : [];
  if (requestedScopes.length === 0) {
    return error(400, "invalid_scope", "at least one scope is required");
  }

  const llmScope = requestedScopes.find((s) => s.startsWith("llm:"));
  if (llmScope) {
    return handleLlmExchange(
      llmScope, requestedScopes, resource, agent, identity, adapter, issuer, jwksData
    );
  }

  // --- 4. Resolve OAuth provider from resource URI ---
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

  // --- 5. Evaluate policy (OAuth — with account lookup) ---
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

  // --- 6. Handle webhook mode ---
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

  // --- 7. Refresh access token from provider ---
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

  // --- 8. Persist new tokens atomically ---
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

  // --- 9. Return RFC 8693 response ---
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

// --- LLM token exchange branch ---

/**
 * Handle LLM-scoped token exchange: mint a gateway JWT (RFC 9068).
 * Runs before any OAuth provider instantiation.
 */
async function handleLlmExchange(
  llmScope, requestedScopes, resource, agent, identity, adapter, issuer, jwksData
) {
  if (!issuer || !jwksData) {
    return error(500, "server_error", "vault not configured for LLM token minting");
  }

  // Parse provider_id from scope (e.g. "llm:anthropic" → "anthropic")
  const providerId = llmScope.split(":")[1];
  if (!providerId) {
    return error(400, "invalid_scope", "malformed LLM scope — expected llm:<provider>");
  }

  // Look up stub provider in vault storage
  const provider = await adapter.find("providers", providerId);
  if (!provider || provider.type !== "llm") {
    return error(400, "invalid_target", `no LLM provider '${providerId}' registered`);
  }

  // Evaluate policy (LLM — skips account lookup)
  const policyResult = await evaluatePolicy(
    adapter,
    agent.id,
    providerId,
    requestedScopes,
    { providerType: "llm" }
  );

  if (!policyResult.allowed) {
    return error(403, "invalid_scope", policyResult.error);
  }

  // Mint gateway JWT (RFC 9068)
  const gatewayJwt = mintGatewayToken(issuer, jwksData, {
    sub: identity.sub,
    email: identity.email,
    aud: resource,
    scope: policyResult.scopes.join(" "),
    agent_id: agent.id,
    provider_id: providerId,
    allowed_models: policyResult.allowed_models || [],
  });

  return {
    status: 200,
    body: {
      access_token: gatewayJwt,
      issued_token_type: TOKEN_TYPE_JWT,
      token_type: "Bearer",
      expires_in: 900, // 15 minutes
      scope: policyResult.scopes.join(" "),
    },
  };
}

/**
 * Mint a gateway JWT (RFC 9068 access token profile).
 */
function mintGatewayToken(vaultIssuer, jwksData, claims) {
  const privateJwk = jwksData.keys[0];
  const header = { alg: "ES256", typ: "at+jwt", kid: privateJwk.kid };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: vaultIssuer,
    sub: claims.sub,
    aud: claims.aud,
    exp: now + 900, // 15 minutes
    iat: now,
    jti: crypto.randomUUID(),
    scope: claims.scope,
    agent_id: claims.agent_id,
    provider_id: claims.provider_id,
  };

  if (claims.email) payload.email = claims.email;
  if (claims.allowed_models && claims.allowed_models.length > 0) {
    payload.allowed_models = claims.allowed_models;
  }

  const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signingInput = `${headerB64}.${payloadB64}`;

  const key = crypto.createPrivateKey({ key: privateJwk, format: "jwk" });
  const signature = crypto.sign("SHA256", Buffer.from(signingInput), {
    key,
    dsaEncoding: "ieee-p1363",
  });
  const sigB64 = signature.toString("base64url");

  return `${headerB64}.${payloadB64}.${sigB64}`;
}

function error(status, code, description) {
  return {
    status,
    body: { error: code, error_description: description },
  };
}
