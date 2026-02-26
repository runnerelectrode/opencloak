import { VaultAdapter } from "./base.mjs";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import os from "node:os";

const DEFAULT_ROOT = path.join(os.homedir(), ".config", "opencloak");

const COLLECTIONS = [
  "owners",
  "accounts",
  "agents",
  "policies",
  "providers",
  "sessions",
  "keys",
];

export class JsonFileAdapter extends VaultAdapter {
  constructor(root) {
    super();
    this.root = root || DEFAULT_ROOT;
    this._ensureDirs();
  }

  _ensureDirs() {
    fs.mkdirSync(this.root, { recursive: true, mode: 0o700 });
    for (const col of COLLECTIONS) {
      fs.mkdirSync(path.join(this.root, col), { recursive: true, mode: 0o700 });
    }
  }

  _filePath(collection, id) {
    return path.join(this.root, collection, `${id}.json`);
  }

  /**
   * Atomic write: write to a temp file in the same directory, then rename.
   * fs.renameSync is atomic on the same filesystem.
   */
  _atomicWrite(filePath, data) {
    const tmp = filePath + `.${crypto.randomUUID()}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), {
      mode: 0o600,
      encoding: "utf-8",
    });
    fs.renameSync(tmp, filePath);
  }

  async upsert(collection, id, data) {
    const filePath = this._filePath(collection, id);
    const record = { id, ...data, updated_at: new Date().toISOString() };
    this._atomicWrite(filePath, record);
    return record;
  }

  async find(collection, id) {
    const filePath = this._filePath(collection, id);
    try {
      return JSON.parse(fs.readFileSync(filePath, "utf-8"));
    } catch {
      return undefined;
    }
  }

  async findAll(collection) {
    const dir = path.join(this.root, collection);
    try {
      const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json"));
      return files.map((f) =>
        JSON.parse(fs.readFileSync(path.join(dir, f), "utf-8"))
      );
    } catch {
      return [];
    }
  }

  async findBy(collection, field, value) {
    const all = await this.findAll(collection);
    return all.filter((item) => item[field] === value);
  }

  async destroy(collection, id) {
    const filePath = this._filePath(collection, id);
    try {
      fs.unlinkSync(filePath);
    } catch {
      // already gone
    }
  }

  // --- Atomic token rotation ---

  async rotateRefreshToken(
    accountId,
    _oldToken,
    newToken,
    accessToken,
    expiresAt
  ) {
    const account = await this.find("accounts", accountId);
    if (!account) throw new Error(`account ${accountId} not found`);
    account.refresh_token = newToken;
    account.access_token = accessToken;
    account.access_token_expires_at = expiresAt;
    account.last_refreshed = new Date().toISOString();
    this._atomicWrite(this._filePath("accounts", accountId), account);
    return account;
  }

  async updateAccessToken(accountId, accessToken, expiresAt) {
    const account = await this.find("accounts", accountId);
    if (!account) throw new Error(`account ${accountId} not found`);
    account.access_token = accessToken;
    account.access_token_expires_at = expiresAt;
    account.last_refreshed = new Date().toISOString();
    this._atomicWrite(this._filePath("accounts", accountId), account);
    return account;
  }
}
