import { createClient } from 'redis';

class RedisRegistrationStore {
  constructor({
    url,
    ttlSeconds = 300,
    mirrorTtlSeconds = null,
    openJoinPoolTtlSeconds = null,
    relayTtlSeconds = null,
    aliasTtlSeconds = null,
    tokenTtlSeconds = null,
    prefix = 'gateway:registrations:',
    logger
  } = {}) {
    if (!url) throw new Error('Redis URL is required for RedisRegistrationStore');
    this.url = url;
    this.ttlSeconds = ttlSeconds;
    this.mirrorTtlSeconds = Number.isFinite(mirrorTtlSeconds) ? mirrorTtlSeconds : null;
    this.openJoinPoolTtlSeconds = Number.isFinite(openJoinPoolTtlSeconds) ? openJoinPoolTtlSeconds : null;
    this.relayTtlSeconds = Number.isFinite(relayTtlSeconds) ? relayTtlSeconds : null;
    this.aliasTtlSeconds = Number.isFinite(aliasTtlSeconds) ? aliasTtlSeconds : null;
    this.tokenTtlSeconds = Number.isFinite(tokenTtlSeconds) ? tokenTtlSeconds : null;
    this.prefix = prefix.endsWith(':') ? prefix : `${prefix}:`;
    this.tokenPrefix = `${this.prefix}tokens:`;
    this.openJoinPrefix = `${this.prefix}open-join:`;
    this.openJoinAliasPrefix = `${this.prefix}open-join-aliases:`;
    this.mirrorPrefix = `${this.prefix}mirrors:`;
    this.aliasPrefix = `${this.prefix}aliases:`;
    this.hostApprovalPrefix = `${this.prefix}host-approvals:`;
    this.relaySponsorshipPrefix = `${this.prefix}sponsorships:`;
    this.relayMemberAclPrefix = `${this.prefix}member-acl:`;
    this.relayMemberGrantPrefix = `${this.prefix}member-grants:`;
    this.relayMemberTokenPrefix = `${this.prefix}member-tokens:`;
    this.logger = logger || console;
    this.client = createClient({ url: this.url });
    this.readyPromise = null;
    this.client.on('error', (err) => {
      this.logger?.error?.('Redis registration store error', { error: err?.message || err });
    });
  }

  async #ensureConnected() {
    if (this.client.isReady) return;
    if (!this.readyPromise) {
      this.readyPromise = this.client.connect().catch((error) => {
        this.readyPromise = null;
        throw error;
      });
    }
    await this.readyPromise;
  }

  async connect() {
    await this.#ensureConnected();
  }

  #key(relayKey) {
    return `${this.prefix}${relayKey}`;
  }

  #tokenKey(relayKey) {
    return `${this.tokenPrefix}${relayKey}`;
  }

  #openJoinKey(relayKey) {
    return `${this.openJoinPrefix}${relayKey}`;
  }

  #openJoinAliasKey(identifier) {
    return `${this.openJoinAliasPrefix}${identifier}`;
  }

  #mirrorKey(relayKey) {
    return `${this.mirrorPrefix}${relayKey}`;
  }

  #aliasKey(identifier) {
    return `${this.aliasPrefix}${identifier}`;
  }

  #hostApprovalKey(gatewayId, subjectPubkey) {
    return `${this.hostApprovalPrefix}${String(gatewayId || '').trim().toLowerCase()}:${String(subjectPubkey || '').trim().toLowerCase()}`;
  }

  #relaySponsorshipKey(relayKey) {
    return `${this.relaySponsorshipPrefix}${relayKey}`;
  }

  #relayMemberAclKey(relayKey, subjectPubkey) {
    return `${this.relayMemberAclPrefix}${String(relayKey || '').trim()}:${String(subjectPubkey || '').trim().toLowerCase()}`;
  }

  #relayMemberGrantKey(grantId) {
    return `${this.relayMemberGrantPrefix}${String(grantId || '').trim()}`;
  }

  #relayMemberTokenKey(relayKey, subjectPubkey) {
    return `${this.relayMemberTokenPrefix}${String(relayKey || '').trim()}:${String(subjectPubkey || '').trim().toLowerCase()}`;
  }

  async upsertRelay(relayKey, payload) {
    await this.#ensureConnected();
    const data = JSON.stringify({ ...payload, relayKey, updatedAt: Date.now() });
    const key = this.#key(relayKey);
    const ttlSeconds = Number.isFinite(this.relayTtlSeconds)
      ? this.relayTtlSeconds
      : this.ttlSeconds;
    if (Number.isFinite(ttlSeconds) && ttlSeconds > 0) {
      await this.client.set(key, data, { EX: ttlSeconds });
    } else {
      await this.client.set(key, data);
    }
  }

  async getRelay(relayKey) {
    await this.#ensureConnected();
    const value = await this.client.get(this.#key(relayKey));
    if (!value) return null;
    try {
      return JSON.parse(value);
    } catch (error) {
      this.logger?.warn?.('Failed to parse redis registration payload', { relayKey, error: error.message });
      return null;
    }
  }

  async removeRelay(relayKey) {
    await this.#ensureConnected();
    await this.client.del(this.#key(relayKey));
    await this.client.del(this.#tokenKey(relayKey));
    await this.clearOpenJoinPool(relayKey);
    await this.removeRelaySponsorship(relayKey);
    await this.clearRelayMemberAcls(relayKey);
  }

  pruneExpired() {
    // Redis handles TTL expiry automatically.
    return undefined;
  }

  async disconnect() {
    if (!this.client.isOpen) return;
    await this.client.disconnect();
  }

  async storeTokenMetadata(relayKey, metadata = {}) {
    await this.#ensureConnected();
    const payload = JSON.stringify({
      ...metadata,
      relayKey,
      recordedAt: Date.now()
    });
    const ttlSeconds = Number.isFinite(this.tokenTtlSeconds)
      ? this.tokenTtlSeconds
      : this.ttlSeconds;
    if (Number.isFinite(ttlSeconds) && ttlSeconds > 0) {
      await this.client.set(this.#tokenKey(relayKey), payload, { EX: ttlSeconds });
    } else {
      await this.client.set(this.#tokenKey(relayKey), payload);
    }
  }

  async getTokenMetadata(relayKey) {
    await this.#ensureConnected();
    const value = await this.client.get(this.#tokenKey(relayKey));
    if (!value) return null;
    try {
      return JSON.parse(value);
    } catch (error) {
      this.logger?.warn?.('Failed to parse redis token metadata', { relayKey, error: error.message });
      return null;
    }
  }

  async clearTokenMetadata(relayKey) {
    await this.#ensureConnected();
    await this.client.del(this.#tokenKey(relayKey));
  }

  async storeOpenJoinPool(relayKey, pool = {}) {
    if (!relayKey) return;
    await this.#ensureConnected();
    const payload = JSON.stringify({
      entries: Array.isArray(pool.entries) ? pool.entries : [],
      updatedAt: pool.updatedAt || Date.now(),
      publicIdentifier: typeof pool.publicIdentifier === 'string' ? pool.publicIdentifier : null,
      relayUrl: typeof pool.relayUrl === 'string' ? pool.relayUrl : null,
      relayCores: Array.isArray(pool.relayCores) ? pool.relayCores : [],
      metadata: pool.metadata && typeof pool.metadata === 'object' ? pool.metadata : null,
      aliases: Array.isArray(pool.aliases) ? pool.aliases : []
    });
    const ttlSeconds = Number.isFinite(this.openJoinPoolTtlSeconds)
      ? this.openJoinPoolTtlSeconds
      : this.ttlSeconds;
    if (Number.isFinite(ttlSeconds) && ttlSeconds > 0) {
      await this.client.set(this.#openJoinKey(relayKey), payload, { EX: ttlSeconds });
    } else {
      await this.client.set(this.#openJoinKey(relayKey), payload);
    }
  }

  async getOpenJoinPool(relayKey) {
    await this.#ensureConnected();
    const value = await this.client.get(this.#openJoinKey(relayKey));
    if (!value) return null;
    try {
      return JSON.parse(value);
    } catch (error) {
      this.logger?.warn?.('Failed to parse redis open-join pool payload', { relayKey, error: error.message });
      return null;
    }
  }

  async takeOpenJoinLease(relayKey) {
    await this.#ensureConnected();
    const pool = await this.getOpenJoinPool(relayKey);
    if (!pool) return null;
    const now = Date.now();
    const entries = Array.isArray(pool.entries) ? pool.entries : [];
    const nextEntries = entries.filter((entry) => !entry?.expiresAt || entry.expiresAt > now);
    const lease = nextEntries.shift() || null;
    if (nextEntries.length) {
      await this.storeOpenJoinPool(relayKey, {
        ...pool,
        entries: nextEntries,
        updatedAt: pool.updatedAt || now
      });
    } else {
      await this.clearOpenJoinPool(relayKey);
    }
    return lease;
  }

  async clearOpenJoinPool(relayKey) {
    await this.#ensureConnected();
    const pool = await this.getOpenJoinPool(relayKey);
    await this.client.del(this.#openJoinKey(relayKey));
    const aliases = Array.isArray(pool?.aliases) ? pool.aliases : [];
    if (aliases.length) {
      await this.clearOpenJoinAliases(relayKey, aliases);
    }
  }

  async storeOpenJoinAliases(relayKey, aliases = []) {
    if (!relayKey) return;
    await this.#ensureConnected();
    const ttlSeconds = Number.isFinite(this.openJoinPoolTtlSeconds)
      ? this.openJoinPoolTtlSeconds
      : this.ttlSeconds;
    const aliasList = Array.isArray(aliases) ? aliases : [];
    const unique = new Set();
    const multi = this.client.multi();
    for (const rawAlias of aliasList) {
      const alias = typeof rawAlias === 'string' ? rawAlias.trim() : null;
      if (!alias || unique.has(alias)) continue;
      unique.add(alias);
      if (Number.isFinite(ttlSeconds) && ttlSeconds > 0) {
        multi.set(this.#openJoinAliasKey(alias), relayKey, { EX: ttlSeconds });
      } else {
        multi.set(this.#openJoinAliasKey(alias), relayKey);
      }
    }
    if (unique.size === 0) return;
    await multi.exec();
  }

  async resolveOpenJoinAlias(identifier) {
    if (!identifier) return null;
    await this.#ensureConnected();
    const alias = typeof identifier === 'string' ? identifier.trim() : null;
    if (!alias) return null;
    const value = await this.client.get(this.#openJoinAliasKey(alias));
    return value || null;
  }

  async clearOpenJoinAliases(relayKey, aliases = null) {
    await this.#ensureConnected();
    let aliasList = Array.isArray(aliases) ? aliases : null;
    if (!aliasList && relayKey) {
      const pool = await this.getOpenJoinPool(relayKey);
      aliasList = Array.isArray(pool?.aliases) ? pool.aliases : [];
    }
    if (!Array.isArray(aliasList) || aliasList.length === 0) return;
    const keys = [];
    const seen = new Set();
    for (const rawAlias of aliasList) {
      const alias = typeof rawAlias === 'string' ? rawAlias.trim() : null;
      if (!alias || seen.has(alias)) continue;
      seen.add(alias);
      keys.push(this.#openJoinAliasKey(alias));
    }
    if (!keys.length) return;
    await this.client.del(...keys);
  }

  async storeMirrorMetadata(relayKey, payload = {}) {
    if (!relayKey) return;
    await this.#ensureConnected();
    const record = JSON.stringify({
      payload,
      storedAt: Date.now()
    });
    const ttlSeconds = Number.isFinite(this.mirrorTtlSeconds)
      ? this.mirrorTtlSeconds
      : this.ttlSeconds;
    if (Number.isFinite(ttlSeconds) && ttlSeconds > 0) {
      await this.client.set(this.#mirrorKey(relayKey), record, { EX: ttlSeconds });
    } else {
      await this.client.set(this.#mirrorKey(relayKey), record);
    }
  }

  async getMirrorMetadata(relayKey) {
    await this.#ensureConnected();
    const value = await this.client.get(this.#mirrorKey(relayKey));
    if (!value) return null;
    try {
      const parsed = JSON.parse(value);
      return parsed?.payload || null;
    } catch (error) {
      this.logger?.warn?.('Failed to parse redis mirror metadata payload', { relayKey, error: error.message });
      return null;
    }
  }

  async clearMirrorMetadata(relayKey) {
    await this.#ensureConnected();
    await this.client.del(this.#mirrorKey(relayKey));
  }

  async upsertHostApproval(gatewayId, subjectPubkey, approval = {}) {
    await this.#ensureConnected();
    const payload = JSON.stringify({
      ...approval,
      gatewayId: String(gatewayId || '').trim().toLowerCase(),
      subjectPubkey: String(subjectPubkey || '').trim().toLowerCase(),
      updatedAt: Date.now()
    });
    await this.client.set(this.#hostApprovalKey(gatewayId, subjectPubkey), payload);
    return JSON.parse(payload);
  }

  async getHostApproval(gatewayId, subjectPubkey) {
    await this.#ensureConnected();
    const value = await this.client.get(this.#hostApprovalKey(gatewayId, subjectPubkey));
    if (!value) return null;
    try {
      return JSON.parse(value);
    } catch (error) {
      this.logger?.warn?.('Failed to parse redis host approval payload', { gatewayId, subjectPubkey, error: error.message });
      return null;
    }
  }

  async listHostApprovals(gatewayId = null) {
    await this.#ensureConnected();
    const normalizedGatewayId = gatewayId ? String(gatewayId).trim().toLowerCase() : null;
    let cursor = '0';
    const out = [];
    const match = normalizedGatewayId
      ? `${this.hostApprovalPrefix}${normalizedGatewayId}:*`
      : `${this.hostApprovalPrefix}*`;
    do {
      const result = await this.client.scan(cursor, { MATCH: match, COUNT: 100 });
      cursor = result.cursor;
      const keys = result.keys || [];
      if (!keys.length) continue;
      const values = await this.client.mGet(keys);
      for (const value of values) {
        if (!value) continue;
        try {
          out.push(JSON.parse(value));
        } catch (error) {
          this.logger?.warn?.('Failed to parse redis host approval during list', { error: error.message });
        }
      }
    } while (cursor !== '0');
    return out;
  }

  async upsertRelaySponsorship(relayKey, sponsorship = {}) {
    await this.#ensureConnected();
    const payload = JSON.stringify({
      ...sponsorship,
      relayKey: String(relayKey || '').trim(),
      updatedAt: Date.now()
    });
    await this.client.set(this.#relaySponsorshipKey(relayKey), payload);
    return JSON.parse(payload);
  }

  async getRelaySponsorship(relayKey) {
    await this.#ensureConnected();
    const value = await this.client.get(this.#relaySponsorshipKey(relayKey));
    if (!value) return null;
    try {
      return JSON.parse(value);
    } catch (error) {
      this.logger?.warn?.('Failed to parse redis relay sponsorship payload', { relayKey, error: error.message });
      return null;
    }
  }

  async removeRelaySponsorship(relayKey) {
    await this.#ensureConnected();
    await this.client.del(this.#relaySponsorshipKey(relayKey));
  }

  async storeRelayMemberAcl(relayKey, subjectPubkey, acl = {}) {
    await this.#ensureConnected();
    const payload = {
      ...acl,
      relayKey: String(relayKey || '').trim(),
      subjectPubkey: String(subjectPubkey || '').trim().toLowerCase(),
      updatedAt: Date.now()
    };
    await this.client.set(this.#relayMemberAclKey(relayKey, subjectPubkey), JSON.stringify(payload));
    if (payload.grantId) {
      await this.client.set(this.#relayMemberGrantKey(payload.grantId), this.#relayMemberAclKey(relayKey, subjectPubkey));
    }
    return payload;
  }

  async getRelayMemberAcl(relayKey, subjectPubkey) {
    await this.#ensureConnected();
    const value = await this.client.get(this.#relayMemberAclKey(relayKey, subjectPubkey));
    if (!value) return null;
    try {
      return JSON.parse(value);
    } catch (error) {
      this.logger?.warn?.('Failed to parse redis relay member ACL payload', { relayKey, subjectPubkey, error: error.message });
      return null;
    }
  }

  async getRelayMemberAclByGrantId(grantId) {
    await this.#ensureConnected();
    const aclKey = await this.client.get(this.#relayMemberGrantKey(grantId));
    if (!aclKey) return null;
    const value = await this.client.get(aclKey);
    if (!value) return null;
    try {
      return JSON.parse(value);
    } catch (error) {
      this.logger?.warn?.('Failed to parse redis relay member ACL by grantId', { grantId, error: error.message });
      return null;
    }
  }

  async listRelayMemberAcls(relayKey) {
    await this.#ensureConnected();
    const normalizedRelayKey = String(relayKey || '').trim();
    if (!normalizedRelayKey) return [];
    let cursor = '0';
    const out = [];
    do {
      const result = await this.client.scan(cursor, {
        MATCH: `${this.relayMemberAclPrefix}${normalizedRelayKey}:*`,
        COUNT: 100
      });
      cursor = result.cursor;
      const keys = result.keys || [];
      if (!keys.length) continue;
      const values = await this.client.mGet(keys);
      for (const value of values) {
        if (!value) continue;
        try {
          out.push(JSON.parse(value));
        } catch (error) {
          this.logger?.warn?.('Failed to parse redis relay member ACL during list', { relayKey, error: error.message });
        }
      }
    } while (cursor !== '0');
    return out;
  }

  async clearRelayMemberAcls(relayKey) {
    await this.#ensureConnected();
    const records = await this.listRelayMemberAcls(relayKey);
    const keys = records.map((record) => this.#relayMemberAclKey(relayKey, record.subjectPubkey));
    const grantKeys = records
      .map((record) => record?.grantId ? this.#relayMemberGrantKey(record.grantId) : null)
      .filter(Boolean);
    const tokenKeys = records.map((record) => this.#relayMemberTokenKey(relayKey, record.subjectPubkey));
    const allKeys = [...keys, ...grantKeys, ...tokenKeys];
    if (allKeys.length) {
      await this.client.del(...allKeys);
    }
  }

  async storeRelayMemberTokenState(relayKey, subjectPubkey, state = {}) {
    await this.#ensureConnected();
    const payload = {
      ...state,
      relayKey: String(relayKey || '').trim(),
      subjectPubkey: String(subjectPubkey || '').trim().toLowerCase(),
      updatedAt: Date.now()
    };
    await this.client.set(this.#relayMemberTokenKey(relayKey, subjectPubkey), JSON.stringify(payload));
    return payload;
  }

  async getRelayMemberTokenState(relayKey, subjectPubkey) {
    await this.#ensureConnected();
    const value = await this.client.get(this.#relayMemberTokenKey(relayKey, subjectPubkey));
    if (!value) return null;
    try {
      return JSON.parse(value);
    } catch (error) {
      this.logger?.warn?.('Failed to parse redis relay member token state', { relayKey, subjectPubkey, error: error.message });
      return null;
    }
  }

  async clearRelayMemberTokenState(relayKey, subjectPubkey) {
    await this.#ensureConnected();
    await this.client.del(this.#relayMemberTokenKey(relayKey, subjectPubkey));
  }

  async storeRelayAlias(identifier, relayKey) {
    if (!identifier || !relayKey) return;
    await this.#ensureConnected();
    const alias = typeof identifier === 'string' ? identifier.trim() : null;
    if (!alias) return;
    const ttlSeconds = Number.isFinite(this.aliasTtlSeconds)
      ? this.aliasTtlSeconds
      : this.ttlSeconds;
    if (Number.isFinite(ttlSeconds) && ttlSeconds > 0) {
      await this.client.set(this.#aliasKey(alias), relayKey, { EX: ttlSeconds });
    } else {
      await this.client.set(this.#aliasKey(alias), relayKey);
    }
  }

  async resolveRelayAlias(identifier) {
    if (!identifier) return null;
    await this.#ensureConnected();
    const alias = typeof identifier === 'string' ? identifier.trim() : null;
    if (!alias) return null;
    const value = await this.client.get(this.#aliasKey(alias));
    return value || null;
  }

  async removeRelayAlias(identifier) {
    if (!identifier) return;
    await this.#ensureConnected();
    const alias = typeof identifier === 'string' ? identifier.trim() : null;
    if (!alias) return;
    await this.client.del(this.#aliasKey(alias));
  }

  async listRelays() {
    await this.#ensureConnected();
    const relays = [];
    const excludePrefixes = [
      this.tokenPrefix,
      this.openJoinPrefix,
      this.openJoinAliasPrefix,
      this.mirrorPrefix,
      this.aliasPrefix,
      this.hostApprovalPrefix,
      this.relaySponsorshipPrefix,
      this.relayMemberAclPrefix,
      this.relayMemberGrantPrefix,
      this.relayMemberTokenPrefix
    ];
    let cursor = '0';
    do {
      const result = await this.client.scan(cursor, { MATCH: `${this.prefix}*`, COUNT: 100 });
      cursor = result.cursor;
      const keys = result.keys || [];
      const relayKeys = keys.filter((key) => !excludePrefixes.some((prefix) => key.startsWith(prefix)));
      if (relayKeys.length === 0) continue;
      const values = await this.client.mGet(relayKeys);
      for (let i = 0; i < relayKeys.length; i += 1) {
        const value = values[i];
        if (!value) continue;
        try {
          const record = JSON.parse(value);
          const relayKey = relayKeys[i].slice(this.prefix.length);
          relays.push({ relayKey, record });
        } catch (error) {
          this.logger?.warn?.('Failed to parse redis relay record during listRelays', {
            relayKey: relayKeys[i],
            error: error?.message || error
          });
        }
      }
    } while (cursor !== '0');
    return relays;
  }
}

export default RedisRegistrationStore;
