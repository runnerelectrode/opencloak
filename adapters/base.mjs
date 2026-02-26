/**
 * Base storage adapter interface for the vault.
 * All adapters must implement these methods.
 */
export class VaultAdapter {
  // --- CRUD for any entity type ---
  async upsert(collection, id, data) {
    throw new Error("not implemented");
  }

  async find(collection, id) {
    throw new Error("not implemented");
  }

  async findAll(collection) {
    throw new Error("not implemented");
  }

  async findBy(collection, field, value) {
    throw new Error("not implemented");
  }

  async destroy(collection, id) {
    throw new Error("not implemented");
  }

  // --- Atomic token rotation (critical for providers with rotating refresh tokens) ---
  async rotateRefreshToken(accountId, oldToken, newToken, accessToken, expiresAt) {
    throw new Error("not implemented");
  }

  async updateAccessToken(accountId, accessToken, expiresAt) {
    throw new Error("not implemented");
  }
}
