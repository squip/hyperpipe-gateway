function compositeKey(...parts) {
  return parts.map((value) => String(value || '').trim().toLowerCase()).join('::');
}

function isExpiredRecord(record, now = Date.now()) {
  return Boolean(record?.expiresAt && record.expiresAt <= now);
}

class MemoryRegistrationStore {
  constructor(options = 300) {
    const resolved = typeof options === 'object' && options !== null
      ? options
      : { ttlSeconds: options };
    this.ttlSeconds = Number.isFinite(resolved.ttlSeconds) ? resolved.ttlSeconds : 300;
    this.relayTtlSeconds = Number.isFinite(resolved.relayTtlSeconds) ? resolved.relayTtlSeconds : null;
    this.aliasTtlSeconds = Number.isFinite(resolved.aliasTtlSeconds) ? resolved.aliasTtlSeconds : null;
    this.tokenTtlSeconds = Number.isFinite(resolved.tokenTtlSeconds) ? resolved.tokenTtlSeconds : null;
    this.mirrorTtlSeconds = Number.isFinite(resolved.mirrorTtlSeconds) ? resolved.mirrorTtlSeconds : null;
    this.openJoinPoolTtlSeconds = Number.isFinite(resolved.openJoinPoolTtlSeconds)
      ? resolved.openJoinPoolTtlSeconds
      : null;
    this.items = new Map();
    this.tokenMetadata = new Map();
    this.openJoinPools = new Map();
    this.mirrorMetadata = new Map();
    this.relayAliases = new Map();
    this.relayAliasIndex = new Map();
    this.openJoinAliases = new Map();
    this.openJoinAliasIndex = new Map();
    this.hostApprovals = new Map();
    this.relaySponsorships = new Map();
    this.relayMemberAcls = new Map();
    this.relayMemberGrantIndex = new Map();
    this.relayMemberTokenState = new Map();
  }

  async upsertRelay(relayKey, payload) {
    const ttlSeconds = Number.isFinite(this.relayTtlSeconds)
      ? this.relayTtlSeconds
      : this.ttlSeconds;
    const record = {
      payload,
      expiresAt: Number.isFinite(ttlSeconds) && ttlSeconds > 0
        ? Date.now() + ttlSeconds * 1000
        : null
    };
    this.items.set(relayKey, record);
  }

  async getRelay(relayKey) {
    const record = this.items.get(relayKey);
    if (!record) return null;
    if (record.expiresAt && record.expiresAt < Date.now()) {
      this.items.delete(relayKey);
      return null;
    }
    return record.payload;
  }

  async removeRelay(relayKey) {
    this.items.delete(relayKey);
    this.tokenMetadata.delete(relayKey);
    this.openJoinPools.delete(relayKey);
    this.removeRelayAliases(relayKey);
    this.clearOpenJoinAliases(relayKey);
    this.relaySponsorships.delete(relayKey);
    for (const [key, record] of this.relayMemberAcls.entries()) {
      if (record?.relayKey === relayKey) {
        this.relayMemberAcls.delete(key);
        if (record?.grantId) this.relayMemberGrantIndex.delete(record.grantId);
      }
    }
    for (const [key, record] of this.relayMemberTokenState.entries()) {
      if (record?.relayKey === relayKey) {
        this.relayMemberTokenState.delete(key);
      }
    }
  }

  pruneExpired() {
    const now = Date.now();
    for (const [key, record] of this.items.entries()) {
      if (record.expiresAt && record.expiresAt < now) {
        this.items.delete(key);
      }
    }

    for (const [key, metadata] of this.tokenMetadata.entries()) {
      if (metadata?.expiresAt && metadata.expiresAt < now) {
        this.tokenMetadata.delete(key);
      }
    }

    for (const [key, pool] of this.openJoinPools.entries()) {
      if (pool?.expiresAt && pool.expiresAt <= now) {
        this.openJoinPools.delete(key);
        this.clearOpenJoinAliases(key);
        continue;
      }
      const entries = Array.isArray(pool?.entries) ? pool.entries : [];
      const nextEntries = entries.filter((entry) => !entry?.expiresAt || entry.expiresAt > now);
      if (nextEntries.length) {
        this.openJoinPools.set(key, { ...pool, entries: nextEntries });
      } else {
        this.openJoinPools.delete(key);
        this.clearOpenJoinAliases(key);
      }
    }

    for (const [key, record] of this.mirrorMetadata.entries()) {
      if (record?.expiresAt && record.expiresAt <= now) {
        this.mirrorMetadata.delete(key);
      }
    }

    for (const [key, record] of this.hostApprovals.entries()) {
      if (isExpiredRecord(record, now)) {
        this.hostApprovals.delete(key);
      }
    }

    for (const [key, record] of this.relaySponsorships.entries()) {
      if (isExpiredRecord(record, now)) {
        this.relaySponsorships.delete(key);
      }
    }

    for (const [key, record] of this.relayMemberAcls.entries()) {
      if (isExpiredRecord(record, now)) {
        this.relayMemberAcls.delete(key);
        if (record?.grantId) this.relayMemberGrantIndex.delete(record.grantId);
      }
    }

    for (const [key, record] of this.relayMemberTokenState.entries()) {
      if (isExpiredRecord(record, now)) {
        this.relayMemberTokenState.delete(key);
      }
    }

    for (const [alias, record] of this.relayAliases.entries()) {
      if (!record?.expiresAt || record.expiresAt > now) continue;
      this.relayAliases.delete(alias);
      const relayKey = record?.relayKey;
      if (!relayKey) continue;
      const aliasSet = this.relayAliasIndex.get(relayKey);
      if (aliasSet) {
        aliasSet.delete(alias);
        if (aliasSet.size === 0) {
          this.relayAliasIndex.delete(relayKey);
        }
      }
    }

    for (const [alias, record] of this.openJoinAliases.entries()) {
      if (!record?.expiresAt || record.expiresAt > now) continue;
      this.openJoinAliases.delete(alias);
      const relayKey = record?.relayKey;
      if (!relayKey) continue;
      const aliasSet = this.openJoinAliasIndex.get(relayKey);
      if (aliasSet) {
        aliasSet.delete(alias);
        if (aliasSet.size === 0) {
          this.openJoinAliasIndex.delete(relayKey);
        }
      }
    }
  }

  async storeTokenMetadata(relayKey, metadata = {}) {
    const ttlSeconds = Number.isFinite(this.tokenTtlSeconds)
      ? this.tokenTtlSeconds
      : this.ttlSeconds;
    const explicitExpiresAt = Number.isFinite(metadata?.expiresAt) ? Number(metadata.expiresAt) : null;
    const record = {
      ...metadata,
      recordedAt: Date.now(),
      expiresAt: explicitExpiresAt ?? (
        Number.isFinite(ttlSeconds) && ttlSeconds > 0
          ? Date.now() + ttlSeconds * 1000
          : null
      )
    };
    this.tokenMetadata.set(relayKey, record);
  }

  async getTokenMetadata(relayKey) {
    const record = this.tokenMetadata.get(relayKey);
    if (!record) return null;
    if (record.expiresAt && record.expiresAt < Date.now()) {
      this.tokenMetadata.delete(relayKey);
      return null;
    }
    return record;
  }

  async clearTokenMetadata(relayKey) {
    this.tokenMetadata.delete(relayKey);
  }

  async storeOpenJoinPool(relayKey, pool = {}) {
    if (!relayKey) return;
    const now = Date.now();
    const poolTtlSeconds = Number.isFinite(this.openJoinPoolTtlSeconds)
      ? this.openJoinPoolTtlSeconds
      : this.ttlSeconds;
    const record = {
      entries: Array.isArray(pool.entries) ? pool.entries : [],
      updatedAt: pool.updatedAt || now,
      publicIdentifier: typeof pool.publicIdentifier === 'string' ? pool.publicIdentifier : null,
      relayUrl: typeof pool.relayUrl === 'string' ? pool.relayUrl : null,
      relayCores: Array.isArray(pool.relayCores) ? pool.relayCores : [],
      metadata: pool.metadata && typeof pool.metadata === 'object' ? pool.metadata : null,
      aliases: Array.isArray(pool.aliases) ? pool.aliases : [],
      expiresAt: Number.isFinite(poolTtlSeconds) && poolTtlSeconds > 0
        ? now + poolTtlSeconds * 1000
        : null
    };
    this.openJoinPools.set(relayKey, record);
  }

  async getOpenJoinPool(relayKey) {
    const record = this.openJoinPools.get(relayKey);
    if (!record) return null;
    if (record.expiresAt && record.expiresAt <= Date.now()) {
      this.openJoinPools.delete(relayKey);
      this.clearOpenJoinAliases(relayKey);
      return null;
    }
    return record;
  }

  async takeOpenJoinLease(relayKey) {
    const record = await this.getOpenJoinPool(relayKey);
    if (!record) return null;
    const now = Date.now();
    const entries = Array.isArray(record.entries) ? record.entries : [];
    const nextEntries = entries.filter((entry) => !entry?.expiresAt || entry.expiresAt > now);
    const lease = nextEntries.shift() || null;
    if (nextEntries.length) {
      this.openJoinPools.set(relayKey, { ...record, entries: nextEntries, updatedAt: record.updatedAt || now });
    } else {
      this.openJoinPools.delete(relayKey);
      this.clearOpenJoinAliases(relayKey);
    }
    return lease;
  }

  async clearOpenJoinPool(relayKey) {
    this.openJoinPools.delete(relayKey);
    this.clearOpenJoinAliases(relayKey);
  }

  async storeOpenJoinAliases(relayKey, aliases = []) {
    if (!relayKey) return;
    const ttlSeconds = Number.isFinite(this.openJoinPoolTtlSeconds)
      ? this.openJoinPoolTtlSeconds
      : this.ttlSeconds;
    const expiresAt = Number.isFinite(ttlSeconds) && ttlSeconds > 0
      ? Date.now() + ttlSeconds * 1000
      : null;
    const aliasList = Array.isArray(aliases) ? aliases : [];
    const unique = new Set();
    for (const rawAlias of aliasList) {
      const alias = typeof rawAlias === 'string' ? rawAlias.trim() : null;
      if (!alias || unique.has(alias)) continue;
      unique.add(alias);
      this.openJoinAliases.set(alias, { relayKey, expiresAt });
      const aliasSet = this.openJoinAliasIndex.get(relayKey) || new Set();
      aliasSet.add(alias);
      this.openJoinAliasIndex.set(relayKey, aliasSet);
    }
  }

  async resolveOpenJoinAlias(identifier) {
    if (!identifier) return null;
    const alias = typeof identifier === 'string' ? identifier.trim() : null;
    if (!alias) return null;
    const record = this.openJoinAliases.get(alias);
    if (!record) return null;
    if (record.expiresAt && record.expiresAt <= Date.now()) {
      this.openJoinAliases.delete(alias);
      const aliasSet = this.openJoinAliasIndex.get(record.relayKey);
      if (aliasSet) {
        aliasSet.delete(alias);
        if (aliasSet.size === 0) {
          this.openJoinAliasIndex.delete(record.relayKey);
        }
      }
      return null;
    }
    return record.relayKey || null;
  }

  clearOpenJoinAliases(relayKey) {
    const aliasSet = this.openJoinAliasIndex.get(relayKey);
    if (!aliasSet) return;
    for (const alias of aliasSet) {
      this.openJoinAliases.delete(alias);
    }
    this.openJoinAliasIndex.delete(relayKey);
  }

  async storeMirrorMetadata(relayKey, payload = {}) {
    if (!relayKey) return;
    const ttlSeconds = Number.isFinite(this.mirrorTtlSeconds) ? this.mirrorTtlSeconds : this.ttlSeconds;
    const record = {
      payload,
      storedAt: Date.now(),
      expiresAt: Number.isFinite(ttlSeconds) && ttlSeconds > 0
        ? Date.now() + ttlSeconds * 1000
        : null
    };
    this.mirrorMetadata.set(relayKey, record);
  }

  async getMirrorMetadata(relayKey) {
    const record = this.mirrorMetadata.get(relayKey);
    if (!record) return null;
    if (record.expiresAt && record.expiresAt <= Date.now()) {
      this.mirrorMetadata.delete(relayKey);
      return null;
    }
    return record.payload || null;
  }

  async clearMirrorMetadata(relayKey) {
    this.mirrorMetadata.delete(relayKey);
  }

  async upsertHostApproval(gatewayId, subjectPubkey, approval = {}) {
    if (!gatewayId || !subjectPubkey) return null;
    const record = {
      ...approval,
      gatewayId: String(gatewayId).trim().toLowerCase(),
      subjectPubkey: String(subjectPubkey).trim().toLowerCase(),
      updatedAt: Date.now()
    };
    this.hostApprovals.set(compositeKey(gatewayId, subjectPubkey), record);
    return record;
  }

  async getHostApproval(gatewayId, subjectPubkey) {
    const record = this.hostApprovals.get(compositeKey(gatewayId, subjectPubkey)) || null;
    if (isExpiredRecord(record)) {
      this.hostApprovals.delete(compositeKey(gatewayId, subjectPubkey));
      return null;
    }
    return record;
  }

  async listHostApprovals(gatewayId = null) {
    const normalizedGatewayId = gatewayId ? String(gatewayId).trim().toLowerCase() : null;
    const out = [];
    for (const record of this.hostApprovals.values()) {
      if (!record) continue;
      if (normalizedGatewayId && record.gatewayId !== normalizedGatewayId) continue;
      if (isExpiredRecord(record)) continue;
      out.push(record);
    }
    return out;
  }

  async upsertRelaySponsorship(relayKey, sponsorship = {}) {
    if (!relayKey) return null;
    const record = {
      ...sponsorship,
      relayKey: String(relayKey).trim(),
      updatedAt: Date.now()
    };
    this.relaySponsorships.set(String(relayKey).trim(), record);
    return record;
  }

  async getRelaySponsorship(relayKey) {
    const key = String(relayKey || '').trim();
    if (!key) return null;
    const record = this.relaySponsorships.get(key) || null;
    if (isExpiredRecord(record)) {
      this.relaySponsorships.delete(key);
      return null;
    }
    return record;
  }

  async removeRelaySponsorship(relayKey) {
    const key = String(relayKey || '').trim();
    if (!key) return;
    this.relaySponsorships.delete(key);
  }

  async storeRelayMemberAcl(relayKey, subjectPubkey, acl = {}) {
    if (!relayKey || !subjectPubkey) return null;
    const normalizedRelayKey = String(relayKey).trim();
    const normalizedSubjectPubkey = String(subjectPubkey).trim().toLowerCase();
    const key = compositeKey(normalizedRelayKey, normalizedSubjectPubkey);
    const previous = this.relayMemberAcls.get(key) || null;
    if (previous?.grantId && previous.grantId !== acl?.grantId) {
      this.relayMemberGrantIndex.delete(previous.grantId);
    }
    const record = {
      ...(previous || {}),
      ...acl,
      relayKey: normalizedRelayKey,
      subjectPubkey: normalizedSubjectPubkey,
      updatedAt: Date.now()
    };
    this.relayMemberAcls.set(key, record);
    if (record.grantId) {
      this.relayMemberGrantIndex.set(record.grantId, key);
    }
    return record;
  }

  async getRelayMemberAcl(relayKey, subjectPubkey) {
    const key = compositeKey(relayKey, subjectPubkey);
    const record = this.relayMemberAcls.get(key) || null;
    if (isExpiredRecord(record)) {
      this.relayMemberAcls.delete(key);
      if (record?.grantId) this.relayMemberGrantIndex.delete(record.grantId);
      return null;
    }
    return record;
  }

  async getRelayMemberAclByGrantId(grantId) {
    const key = this.relayMemberGrantIndex.get(String(grantId || '').trim()) || null;
    if (!key) return null;
    const record = this.relayMemberAcls.get(key) || null;
    if (isExpiredRecord(record)) {
      this.relayMemberAcls.delete(key);
      if (record?.grantId) this.relayMemberGrantIndex.delete(record.grantId);
      return null;
    }
    return record;
  }

  async listRelayMemberAcls(relayKey) {
    const normalizedRelayKey = String(relayKey || '').trim();
    if (!normalizedRelayKey) return [];
    const out = [];
    for (const record of this.relayMemberAcls.values()) {
      if (!record || record.relayKey !== normalizedRelayKey) continue;
      if (isExpiredRecord(record)) continue;
      out.push(record);
    }
    return out;
  }

  async clearRelayMemberAcls(relayKey) {
    const normalizedRelayKey = String(relayKey || '').trim();
    if (!normalizedRelayKey) return;
    for (const [key, record] of this.relayMemberAcls.entries()) {
      if (record?.relayKey !== normalizedRelayKey) continue;
      this.relayMemberAcls.delete(key);
      if (record?.grantId) this.relayMemberGrantIndex.delete(record.grantId);
    }
  }

  async storeRelayMemberTokenState(relayKey, subjectPubkey, state = {}) {
    if (!relayKey || !subjectPubkey) return null;
    const record = {
      ...state,
      relayKey: String(relayKey).trim(),
      subjectPubkey: String(subjectPubkey).trim().toLowerCase(),
      updatedAt: Date.now()
    };
    this.relayMemberTokenState.set(compositeKey(relayKey, subjectPubkey), record);
    return record;
  }

  async getRelayMemberTokenState(relayKey, subjectPubkey) {
    const key = compositeKey(relayKey, subjectPubkey);
    const record = this.relayMemberTokenState.get(key) || null;
    if (isExpiredRecord(record)) {
      this.relayMemberTokenState.delete(key);
      return null;
    }
    return record;
  }

  async clearRelayMemberTokenState(relayKey, subjectPubkey) {
    this.relayMemberTokenState.delete(compositeKey(relayKey, subjectPubkey));
  }

  async storeRelayAlias(identifier, relayKey) {
    if (!identifier || !relayKey) return;
    const alias = typeof identifier === 'string' ? identifier.trim() : null;
    if (!alias) return;
    const ttlSeconds = Number.isFinite(this.aliasTtlSeconds)
      ? this.aliasTtlSeconds
      : this.ttlSeconds;
    const record = {
      relayKey,
      expiresAt: Number.isFinite(ttlSeconds) && ttlSeconds > 0
        ? Date.now() + ttlSeconds * 1000
        : null
    };
    this.relayAliases.set(alias, record);
    const existing = this.relayAliasIndex.get(relayKey) || new Set();
    existing.add(alias);
    this.relayAliasIndex.set(relayKey, existing);
  }

  async resolveRelayAlias(identifier) {
    if (!identifier) return null;
    const alias = typeof identifier === 'string' ? identifier.trim() : null;
    if (!alias) return null;
    const record = this.relayAliases.get(alias);
    if (!record) return null;
    if (record.expiresAt && record.expiresAt < Date.now()) {
      this.relayAliases.delete(alias);
      const aliasSet = this.relayAliasIndex.get(record.relayKey);
      if (aliasSet) {
        aliasSet.delete(alias);
        if (aliasSet.size === 0) {
          this.relayAliasIndex.delete(record.relayKey);
        }
      }
      return null;
    }
    return record.relayKey || null;
  }

  removeRelayAliases(relayKey) {
    const aliasSet = this.relayAliasIndex.get(relayKey);
    if (!aliasSet) return;
    for (const alias of aliasSet) {
      this.relayAliases.delete(alias);
    }
    this.relayAliasIndex.delete(relayKey);
  }

  async listRelays() {
    const relays = [];
    const now = Date.now();
    for (const [relayKey, record] of this.items.entries()) {
      if (record?.expiresAt && record.expiresAt < now) continue;
      relays.push({ relayKey, record: record?.payload || null });
    }
    return relays;
  }
}

export default MemoryRegistrationStore;
