import { JsonFileAdapter } from "../adapters/json-file.mjs";
import path from "node:path";
import os from "node:os";

const DEFAULT_DATA_DIR = path.join(os.homedir(), ".config", "opencloak-gateway");

export const GATEWAY_DEFAULTS = {
  port: 3423,
  jwksUrl: null, // must be configured
  dataDir: DEFAULT_DATA_DIR,
};

let _adapter = null;

/**
 * Get the gateway's storage adapter (singleton).
 */
export function getGatewayAdapter(root) {
  if (!_adapter) {
    const encryptionKey = process.env.OPENCLOAK_ENCRYPTION_KEY || null;
    _adapter = new JsonFileAdapter(
      root || process.env.OPENCLOAK_GATEWAY_DATA_DIR || GATEWAY_DEFAULTS.dataDir,
      encryptionKey
    );
  }
  return _adapter;
}

/**
 * Resolve gateway configuration from flags + env vars + defaults.
 */
export function resolveConfig(opts = {}) {
  const port = parseInt(opts.port || process.env.PORT || GATEWAY_DEFAULTS.port, 10);
  return {
    port,
    jwksUrl: opts["jwks-url"] || process.env.OPENCLOAK_GATEWAY_JWKS_URL || GATEWAY_DEFAULTS.jwksUrl,
    dataDir: opts["data-dir"] || process.env.OPENCLOAK_GATEWAY_DATA_DIR || GATEWAY_DEFAULTS.dataDir,
    gatewayUrl: opts["gateway-url"] || process.env.OPENCLOAK_GATEWAY_URL || `http://localhost:${port}`,
  };
}
