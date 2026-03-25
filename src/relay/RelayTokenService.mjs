import {
  issueClientToken,
  verifyClientToken
} from '../../../shared/auth/PublicGatewayTokens.mjs';

const DEFAULT_TTL_SECONDS = 3600;
const DEFAULT_REFRESH_WINDOW_SECONDS = 300;

function toNumber(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

export default class RelayTokenService {
  constructor({
    registrationStore,
    sharedSecret,
    logger = console,
    defaultTtlSeconds = DEFAULT_TTL_SECONDS,
    refreshWindowSeconds = DEFAULT_REFRESH_WINDOW_SECONDS
  } = {}) {
    if (!registrationStore) throw new Error('RelayTokenService requires a registrationStore');
    if (!sharedSecret) throw new Error('RelayTokenService requires shared secret');
    this.registrationStore = registrationStore;
    this.sharedSecret = sharedSecret;
    this.logger = logger;
    this.defaultTtlSeconds = toNumber(defaultTtlSeconds, DEFAULT_TTL_SECONDS);
    this.refreshWindowMs = toNumber(refreshWindowSeconds, DEFAULT_REFRESH_WINDOW_SECONDS) * 1000;
  }

  async issueToken(relayKey, options = {}) {
    if (!relayKey) throw new Error('relayKey required');
    if (!options.relayAuthToken) throw new Error('relayAuthToken required');

    const registration = await this.registrationStore.getRelay?.(relayKey);
    if (!registration) {
      throw new Error('relay-not-registered');
    }

    const existingMetadata = await this.registrationStore.getTokenMetadata?.(relayKey) || null;
    const sequence = (existingMetadata?.sequence || 0) + 1;
    const issuedAt = Date.now();
    const ttlSeconds = toNumber(options.ttlSeconds, this.defaultTtlSeconds);
    const expiresAt = issuedAt + ttlSeconds * 1000;
    const refreshAfter = Math.max(issuedAt, expiresAt - this.refreshWindowMs);

    const payload = {
      relayKey,
      relayAuthToken: options.relayAuthToken,
      pubkey: options.pubkey || null,
      scope: options.scope || 'relay-access',
      expiresAt,
      sequence
    };

    const token = issueClientToken(payload, this.sharedSecret);
    await this.registrationStore.storeTokenMetadata?.(relayKey, {
      token,
      relayAuthToken: options.relayAuthToken,
      pubkey: payload.pubkey,
      scope: payload.scope,
      sequence,
      issuedAt,
      expiresAt,
      refreshAfter,
      lastValidatedAt: issuedAt
    });

    this.logger?.info?.('[RelayTokenService] Token issued', {
      relayKey,
      expiresAt,
      sequence
    });

    return {
      token,
      expiresAt,
      refreshAfter,
      sequence
    };
  }

  async refreshToken(relayKey, options = {}) {
    if (!relayKey) throw new Error('relayKey required');
    if (!options.token) throw new Error('token required');

    const currentState = await this.registrationStore.getTokenMetadata?.(relayKey);
    if (!currentState || !currentState.token) {
      throw new Error('no-active-token');
    }
    if (currentState.token !== options.token) {
      throw new Error('token-mismatch');
    }

    // Verify existing token before issuing new one
    await this.verifyToken(options.token, relayKey);

    return this.issueToken(relayKey, {
      relayAuthToken: currentState.relayAuthToken,
      pubkey: currentState.pubkey,
      scope: currentState.scope,
      ttlSeconds: options.ttlSeconds
    });
  }

  async revokeToken(relayKey, { reason } = {}) {
    if (!relayKey) throw new Error('relayKey required');
    const metadata = await this.registrationStore.getTokenMetadata?.(relayKey);
    const nextSequence = (metadata?.sequence || 0) + 1;

    await this.registrationStore.storeTokenMetadata?.(relayKey, {
      token: null,
      relayAuthToken: metadata?.relayAuthToken || null,
      pubkey: metadata?.pubkey || null,
      scope: metadata?.scope || null,
      sequence: nextSequence,
      revokedAt: Date.now(),
      revocationReason: reason || null
    });

    this.logger?.warn?.('[RelayTokenService] Token revoked', {
      relayKey,
      reason: reason || 'unspecified'
    });

    return { sequence: nextSequence };
  }

  async verifyToken(token, relayKey) {
    if (!token || typeof token !== 'string') {
      throw new Error('token-required');
    }
    if (!relayKey) throw new Error('relayKey required');

    const payload = verifyClientToken(token, this.sharedSecret);
    if (!payload) {
      throw new Error('token-invalid');
    }

    if (payload.relayKey && payload.relayKey !== relayKey) {
      throw new Error('relay-mismatch');
    }

    if (payload.expiresAt && payload.expiresAt < Date.now()) {
      throw new Error('token-expired');
    }

    const metadata = await this.registrationStore.getTokenMetadata?.(relayKey);
    if (metadata?.revokedAt) {
      throw new Error('token-revoked');
    }

    if (metadata?.token && metadata.token !== token) {
      throw new Error('token-mismatch');
    }

    if (metadata?.sequence && payload.sequence && payload.sequence < metadata.sequence) {
      throw new Error('token-stale');
    }

    await this.registrationStore.storeTokenMetadata?.(relayKey, {
      token,
      relayAuthToken: payload.relayAuthToken || metadata?.relayAuthToken || null,
      pubkey: payload.pubkey || metadata?.pubkey || null,
      scope: payload.scope || metadata?.scope || null,
      sequence: payload.sequence || metadata?.sequence || 0,
      issuedAt: metadata?.issuedAt || payload.issuedAt || Date.now(),
      expiresAt: payload.expiresAt || metadata?.expiresAt || Date.now(),
      refreshAfter: metadata?.refreshAfter || (payload.expiresAt ? Math.max(Date.now(), payload.expiresAt - this.refreshWindowMs) : null),
      lastValidatedAt: Date.now()
    });

    return {
      payload,
      relayAuthToken: payload.relayAuthToken,
      pubkey: payload.pubkey || null,
      scope: payload.scope || null
    };
  }

  async getTokenState(relayKey) {
    return this.registrationStore.getTokenMetadata?.(relayKey) || null;
  }
}
