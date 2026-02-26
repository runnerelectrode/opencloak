import { VaultAdapter } from "./base.mjs";
import fs from "node:fs/promises";
import { mkdirSync, existsSync } from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import os from "node:os";

const DEFAULT_ROOT = path.join(os.homedir(), ".config", "opencloak");

const COLLECTIONS = new Set([
  "owners",
  "accounts",
  "agents",
  "policies",
  "providers",
  "sessions",
  "keys",
]);

// Fields that contain secrets — encrypted at rest
const SECRET_FIELDS = new Set([
  "client_secret",
  "access_token",
  "refresh_token",
]);

// Regex for safe IDs: alphanumeric, hyphens, underscores, dots, colons, @
const SAFE_ID = /^[a-zA-Z0-9_@.:+-]+$/;

export class JsonFileAdapter extends VaultAdapter {
  constructor(root, encryptionKey) {
    super();
    this.root = root || DEFAULT_ROOT;
    // Derive 256-bit encryption key from env or generate one
    this._encKey = encryptionKey
      ? crypto.createHash("sha256").update(encryptionKey).digest()
      : null;
    this._ensureDirs();
  }

  _ensureDirs() {
    mkdirSync(this.root, { recursive: true, mode: 0o700 });
    for (const col of COLLECTIONS) {
      mkdirSync(path.join(this.root, col), { recursive: true, mode: 0o700 });
    }
  }

  /**
   * Validate and construct a safe file path.
   * Rejects any ID containing path separators or traversal sequences.
   */
  _filePath(collection, id) {
    if (!COLLECTIONS.has(collection)) {
      throw new Error(`invalid collection: ${collection}`);
    }
    const idStr = String(id);
    if (!idStr || !SAFE_ID.test(idStr) || idStr.length > 255) {
      throw new Error(`invalid id: contains disallowed characters or is too long`);
    }
    const resolved = path.join(this.root, collection, `${idStr}.json`);
    // Belt-and-suspenders: verify resolved path is inside root
    if (!resolved.startsWith(this.root + path.sep)) {
      throw new Error("path traversal detected");
    }
    return resolved;
  }

  // --- Encryption helpers ---

  _encrypt(plaintext) {
    if (!this._encKey) return plaintext;
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", this._encKey, iv);
    const enc = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `enc:${iv.toString("base64")}:${tag.toString("base64")}:${enc.toString("base64")}`;
  }

  _decrypt(ciphertext) {
    if (!this._encKey || typeof ciphertext !== "string" || !ciphertext.startsWith("enc:")) {
      return ciphertext;
    }
    const [, ivB64, tagB64, dataB64] = ciphertext.split(":");
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      this._encKey,
      Buffer.from(ivB64, "base64")
    );
    decipher.setAuthTag(Buffer.from(tagB64, "base64"));
    return decipher.update(Buffer.from(dataB64, "base64"), null, "utf-8") + decipher.final("utf-8");
  }

  _encryptRecord(data) {
    if (!this._encKey) return data;
    const copy = { ...data };
    for (const field of SECRET_FIELDS) {
      if (copy[field] && typeof copy[field] === "string") {
        copy[field] = this._encrypt(copy[field]);
      }
    }
    return copy;
  }

  _decryptRecord(data) {
    if (!this._encKey || !data) return data;
    const copy = { ...data };
    for (const field of SECRET_FIELDS) {
      if (copy[field] && typeof copy[field] === "string") {
        copy[field] = this._decrypt(copy[field]);
      }
    }
    return copy;
  }

  /**
   * Atomic write: write to a temp file in the same directory, then rename.
   */
  async _atomicWrite(filePath, data) {
    const tmp = filePath + `.${crypto.randomUUID()}.tmp`;
    const encrypted = this._encryptRecord(data);
    await fs.writeFile(tmp, JSON.stringify(encrypted, null, 2), {
      mode: 0o600,
      encoding: "utf-8",
    });
    await fs.rename(tmp, filePath);
  }

  async upsert(collection, id, data) {
    const filePath = this._filePath(collection, id);
    const record = { id, ...data, updated_at: new Date().toISOString() };
    await this._atomicWrite(filePath, record);
    return record;
  }

  async find(collection, id) {
    const filePath = this._filePath(collection, id);
    try {
      const raw = await fs.readFile(filePath, "utf-8");
      return this._decryptRecord(JSON.parse(raw));
    } catch {
      return undefined;
    }
  }

  async findAll(collection) {
    if (!COLLECTIONS.has(collection)) {
      throw new Error(`invalid collection: ${collection}`);
    }
    const dir = path.join(this.root, collection);
    try {
      const files = (await fs.readdir(dir)).filter((f) => f.endsWith(".json"));
      const results = [];
      for (const f of files) {
        try {
          const raw = await fs.readFile(path.join(dir, f), "utf-8");
          results.push(this._decryptRecord(JSON.parse(raw)));
        } catch {
          // skip corrupted files
        }
      }
      return results;
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
      await fs.unlink(filePath);
    } catch {
      // already gone
    }
  }

  // --- Atomic token rotation with optimistic locking ---

  async rotateRefreshToken(
    accountId,
    oldToken,
    newToken,
    accessToken,
    expiresAt
  ) {
    const account = await this.find("accounts", accountId);
    if (!account) throw new Error(`account ${accountId} not found`);
    // Optimistic lock: verify the stored token matches what we expect
    if (account.refresh_token !== oldToken) {
      throw new Error("concurrent refresh detected — token already rotated");
    }
    account.refresh_token = newToken;
    account.access_token = accessToken;
    account.access_token_expires_at = expiresAt;
    account.last_refreshed = new Date().toISOString();
    await this._atomicWrite(this._filePath("accounts", accountId), account);
    return account;
  }

  async updateAccessToken(accountId, accessToken, expiresAt) {
    const account = await this.find("accounts", accountId);
    if (!account) throw new Error(`account ${accountId} not found`);
    account.access_token = accessToken;
    account.access_token_expires_at = expiresAt;
    account.last_refreshed = new Date().toISOString();
    await this._atomicWrite(this._filePath("accounts", accountId), account);
    return account;
  }

  // --- Session cleanup (removes expired sessions) ---

  async cleanExpiredSessions(maxAgeMs = 10 * 60 * 1000) {
    const sessions = await this.findAll("sessions");
    const now = Date.now();
    for (const s of sessions) {
      const created = new Date(s.created_at || 0).getTime();
      if (now - created > maxAgeMs) {
        await this.destroy("sessions", s.id);
      }
    }
  }
}
