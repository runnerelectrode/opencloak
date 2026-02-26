import { JsonFileAdapter } from "./adapters/json-file.mjs";
import crypto from "node:crypto";

let _adapter = null;

/**
 * Get the shared storage adapter (singleton).
 */
export function getAdapter(root) {
  if (!_adapter) {
    _adapter = new JsonFileAdapter(root);
  }
  return _adapter;
}

/**
 * Generate a crypto-random ID.
 */
export function genId() {
  return crypto.randomUUID();
}

/**
 * Vault-wide defaults.
 */
export const DEFAULTS = {
  port: 3422,
  issuer: "http://localhost:3422",
};
