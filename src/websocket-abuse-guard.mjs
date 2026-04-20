const DEFAULT_OPTIONS = Object.freeze({
  invalidWindowMs: 30_000,
  invalidThreshold: 20,
  blockDurationMs: 2 * 60_000,
  missingRelayTtlMs: 30_000,
  rejectionLogWindowMs: 30_000,
  maxClientEntries: 2048,
  maxMissingRelayEntries: 4096,
  maxLogEntries: 2048
});

function normalizeString(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : null;
}

export function resolveClientAddress(req) {
  const cloudflare = normalizeString(req?.headers?.['cf-connecting-ip']);
  if (cloudflare) return cloudflare;

  const realIp = normalizeString(req?.headers?.['x-real-ip']);
  if (realIp) return realIp;

  const forwarded = normalizeString(req?.headers?.['x-forwarded-for']);
  if (forwarded) {
    const [first] = forwarded.split(',');
    const candidate = normalizeString(first);
    if (candidate) return candidate;
  }

  return normalizeString(req?.socket?.remoteAddress)
    || normalizeString(req?.connection?.remoteAddress)
    || 'unknown';
}

export class WebSocketAbuseGuard {
  constructor(options = {}) {
    this.options = {
      ...DEFAULT_OPTIONS,
      ...options
    };
    this.invalidClients = new Map();
    this.missingRelays = new Map();
    this.rejectionLogs = new Map();
  }

  isClientBlocked(address, now = Date.now()) {
    this.#prune(now);
    const key = normalizeString(address) || 'unknown';
    const state = this.invalidClients.get(key);
    if (!state) return false;
    return Number.isFinite(state.blockedUntil) && state.blockedUntil > now;
  }

  noteSuccess(address) {
    const key = normalizeString(address);
    if (!key) return;
    this.invalidClients.delete(key);
  }

  shouldSkipMissingRelayLookup(relayKey, now = Date.now()) {
    this.#prune(now);
    const key = normalizeString(relayKey);
    if (!key) return false;
    const expiresAt = this.missingRelays.get(key);
    return Number.isFinite(expiresAt) && expiresAt > now;
  }

  rememberMissingRelay(relayKey, now = Date.now()) {
    const key = normalizeString(relayKey);
    if (!key) return;
    this.#prune(now);
    this.missingRelays.delete(key);
    this.missingRelays.set(key, now + this.options.missingRelayTtlMs);
    this.#trimMap(this.missingRelays, this.options.maxMissingRelayEntries);
  }

  logRejectedAttempt({
    logger,
    reason,
    context = {},
    clientAddress = null,
    relayKey = null,
    now = Date.now()
  }) {
    this.#prune(now, { includeRejectionLogs: false });
    const key = this.#buildLogKey({
      reason,
      clientAddress,
      relayKey,
      url: context?.url || null
    });
    const state = this.rejectionLogs.get(key);
    if (!state || state.expiresAt <= now) {
      const suppressedCount = state?.suppressedCount || 0;
      const payload = {
        ...context,
        clientAddress: normalizeString(clientAddress) || context?.clientAddress || null,
        relayKey: normalizeString(relayKey) || context?.relayKey || null
      };
      if (suppressedCount > 0) {
        payload.suppressedCount = suppressedCount;
      }
      logger?.warn?.(payload, this.#formatReason(reason));
      this.rejectionLogs.delete(key);
      this.rejectionLogs.set(key, {
        expiresAt: now + this.options.rejectionLogWindowMs,
        suppressedCount: 0
      });
      this.#trimMap(this.rejectionLogs, this.options.maxLogEntries);
      return;
    }

    state.suppressedCount += 1;
    this.rejectionLogs.delete(key);
    this.rejectionLogs.set(key, state);
  }

  recordInvalidAttempt({
    logger,
    reason,
    context = {},
    clientAddress = null,
    relayKey = null,
    now = Date.now()
  }) {
    this.#prune(now);

    const address = normalizeString(clientAddress) || 'unknown';
    let state = this.invalidClients.get(address);
    if (!state || state.windowEndsAt <= now) {
      state = {
        count: 0,
        windowEndsAt: now + this.options.invalidWindowMs,
        blockedUntil: 0
      };
    }

    state.count += 1;
    let blockedNow = false;
    if (state.count >= this.options.invalidThreshold && state.blockedUntil <= now) {
      state.blockedUntil = now + this.options.blockDurationMs;
      blockedNow = true;
    }

    this.invalidClients.delete(address);
    this.invalidClients.set(address, state);
    this.#trimMap(this.invalidClients, this.options.maxClientEntries);

    this.logRejectedAttempt({
      logger,
      reason,
      clientAddress: address,
      relayKey,
      context: {
        ...context,
        blockedUntil: state.blockedUntil > now ? state.blockedUntil : null,
        invalidAttemptsInWindow: state.count,
        invalidWindowMs: this.options.invalidWindowMs
      },
      now
    });

    return {
      blocked: state.blockedUntil > now,
      blockedNow,
      retryAfterMs: state.blockedUntil > now ? Math.max(0, state.blockedUntil - now) : 0
    };
  }

  #formatReason(reason) {
    switch (reason) {
      case 'invalid-relay-key':
        return 'WebSocket rejected: invalid relay key';
      case 'relay-not-registered':
        return 'WebSocket rejected: relay not registered';
      case 'token-missing':
        return 'WebSocket rejected: token missing';
      case 'token-validation-failed':
        return 'WebSocket rejected: token validation failed';
      case 'client-rate-limited':
        return 'WebSocket rejected: client rate limited';
      default:
        return `WebSocket rejected: ${reason || 'unknown'}`;
    }
  }

  #buildLogKey({ reason, clientAddress, relayKey, url }) {
    return [
      normalizeString(reason) || 'unknown',
      normalizeString(clientAddress) || normalizeString(relayKey) || normalizeString(url) || 'unknown'
    ].join('|');
  }

  #prune(now, { includeRejectionLogs = true } = {}) {
    for (const [key, state] of this.invalidClients) {
      if ((state.blockedUntil || 0) <= now && (state.windowEndsAt || 0) <= now) {
        this.invalidClients.delete(key);
      }
    }

    for (const [key, expiresAt] of this.missingRelays) {
      if (!Number.isFinite(expiresAt) || expiresAt <= now) {
        this.missingRelays.delete(key);
      }
    }

    if (includeRejectionLogs) {
      for (const [key, state] of this.rejectionLogs) {
        if (!state || state.expiresAt <= now) {
          this.rejectionLogs.delete(key);
        }
      }
    }
  }

  #trimMap(map, limit) {
    while (map.size > limit) {
      const oldestKey = map.keys().next().value;
      if (oldestKey === undefined) break;
      map.delete(oldestKey);
    }
  }
}
