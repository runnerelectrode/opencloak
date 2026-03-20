/**
 * OCSF-aligned audit event emitter for the OpenCloak gateway.
 *
 * Emits NDJSON to stdout using OCSF category/class UIDs for structure.
 * Does not claim full OCSF v1.7.0 conformance — uses OCSF as an alignment
 * target for structured audit logging.
 *
 * OCSF class: 6003 (API Activity)
 * OCSF category: 6 (Application Activity)
 */

const PRODUCT = { name: "opencloak-gateway", version: "0.1.0" };

/**
 * Emit an OCSF-aligned audit event to stdout.
 *
 * @param {object} params
 * @param {object} params.actor - JWT claims (sub, email, jti, agent_id)
 * @param {object} params.resource - Provider info (uid, name, upstream URL)
 * @param {object} params.request - HTTP request info (method, path, model)
 * @param {object} params.response - HTTP response info (status, tokens_in, tokens_out)
 * @param {number} params.startTime - request start timestamp (ms)
 * @param {boolean} [params.modelAllowed] - whether the model passed the allowlist
 * @param {boolean} [params.pathAllowed] - whether the path passed the allowlist
 */
export function emitAuditEvent({ actor, resource, request, response, startTime, modelAllowed, pathAllowed }) {
  const now = Date.now();
  const isSuccess = response.status >= 200 && response.status < 400;

  const event = {
    activity_id: 1,
    category_uid: 6,
    class_uid: 6003,
    severity_id: isSuccess ? 1 : 3,
    status_id: isSuccess ? 1 : 2,
    time: now,
    actor: {
      user: {
        uid: actor.sub || null,
        email_addr: actor.email || null,
      },
      session: { uid: actor.jti || null },
      agent: { uid: actor.agent_id || null },
    },
    resource: {
      uid: resource.provider_id || null,
      name: resource.provider_id ? `${resource.provider_id}-api` : null,
      url: resource.upstream_url || null,
    },
    metadata: {
      version: "1.7.0",
      product: PRODUCT,
    },
    unmapped: {
      activity: "gateway.request.proxied",
      model: request.model || null,
      http_method: request.method,
      http_path: request.path,
      http_status: response.status,
      duration_ms: now - startTime,
      scope: actor.scope || null,
      model_allowed: modelAllowed ?? null,
      path_allowed: pathAllowed ?? null,
    },
  };

  // Token counts from upstream response (non-streaming only)
  if (response.tokens_in != null) event.unmapped.tokens_in = response.tokens_in;
  if (response.tokens_out != null) event.unmapped.tokens_out = response.tokens_out;

  process.stdout.write(JSON.stringify(event) + "\n");
}
