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
 * @param {string} agentId  - agent ID (looked up by OIDC sub claim)
 * @param {string} providerId - target provider ID
 * @param {string[]} requestedScopes - scopes the agent is requesting
 * @param {object} [options] - additional options
 * @param {string} [options.providerType] - "llm" to skip account lookup
 * @returns {{ allowed: boolean, scopes: string[], error?: string, account?: object, allowed_models?: string[] }}
 */
export async function evaluatePolicy(
  adapter,
  agentId,
  providerId,
  requestedScopes,
  options = {}
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
  //    LLM providers have no connected accounts — skip this step.
  let account = null;
  if (options.providerType !== "llm") {
    const accounts = await adapter.findBy("accounts", "owner_id", owner.id);
    account = accounts.find((a) => a.provider_id === providerId);
    if (!account) {
      return {
        allowed: false,
        scopes: [],
        error: `owner has no connected account for provider '${providerId}'`,
      };
    }
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

  const result = { allowed: true, scopes: granted };
  if (account) result.account = account;
  if (policy.allowed_models) result.allowed_models = policy.allowed_models;
  if (denied.length > 0) {
    result.partial = true;
    result.denied = denied;
  }

  return result;
}

/**
 * Look up an agent by their OIDC identity (sub claim).
 */
export async function findAgentByIdentity(adapter, identity) {
  const agents = await adapter.findBy("agents", "identity", identity);
  return agents[0] || null;
}
