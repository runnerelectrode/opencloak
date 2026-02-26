/**
 * Policy enforcement for agent token exchange.
 *
 * Checks that an agent is allowed to request the given provider + scopes,
 * and returns the intersection of requested scopes and allowed scopes.
 */

/**
 * Evaluate whether an agent can access a provider with the requested scopes.
 *
 * @param {object} adapter  - storage adapter
 * @param {string} agentId  - agent ID (looked up by tsidp sub claim)
 * @param {string} providerId - target provider ID
 * @param {string[]} requestedScopes - scopes the agent is requesting
 * @returns {{ allowed: boolean, scopes: string[], error?: string, account?: object }}
 */
export async function evaluatePolicy(
  adapter,
  agentId,
  providerId,
  requestedScopes
) {
  // 1. Find agent
  const agent = await adapter.find("agents", agentId);
  if (!agent) {
    return { allowed: false, scopes: [], error: "agent not registered" };
  }

  // 2. Find agent's owner
  const owner = await adapter.find("owners", agent.owner_id);
  if (!owner) {
    return { allowed: false, scopes: [], error: "agent owner not found" };
  }

  // 3. Find owner's connected account for this provider
  const accounts = await adapter.findBy("accounts", "owner_id", owner.id);
  const account = accounts.find((a) => a.provider_id === providerId);
  if (!account) {
    return {
      allowed: false,
      scopes: [],
      error: `owner has no connected account for provider '${providerId}'`,
    };
  }

  // 4. Find agent policy for this provider
  const policies = await adapter.findBy("policies", "agent_id", agentId);
  const policy = policies.find((p) => p.provider_id === providerId);
  if (!policy) {
    return {
      allowed: false,
      scopes: [],
      error: `no policy found for agent '${agentId}' on provider '${providerId}'`,
    };
  }

  // 5. Intersect requested scopes with allowed scopes
  const allowedSet = new Set(policy.allowed_scopes);
  const granted = requestedScopes.filter((s) => allowedSet.has(s));
  const denied = requestedScopes.filter((s) => !allowedSet.has(s));

  if (granted.length === 0) {
    return {
      allowed: false,
      scopes: [],
      error: `scope '${denied.join(", ")}' not allowed for this agent`,
    };
  }

  if (denied.length > 0) {
    // Partial grant — return only the intersection
    return { allowed: true, scopes: granted, account, partial: true, denied };
  }

  return { allowed: true, scopes: granted, account };
}

/**
 * Look up an agent by their Tailscale identity (sub claim from tsidp).
 */
export async function findAgentByIdentity(adapter, tsIdentity) {
  const agents = await adapter.findBy("agents", "ts_identity", tsIdentity);
  return agents[0] || null;
}
