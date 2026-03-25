import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const LEGACY_PUBLIC_GATEWAY_PATH = 'public-gateway/hyperbee';
const DEFAULT_NOSTR_DISCOVERY_RELAYS = [
  'wss://relay.damus.io/',
  'wss://relay.primal.net/',
  'wss://nos.lol/',
  'wss://hypertuna.com/relay'
];

const DEFAULT_BLIND_PEER_MAX_BYTES = 25 * 1024 ** 3;
const DEFAULT_OPEN_JOIN_POOL_ENTRY_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function parseEnvNumber(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === null || raw === '') return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseCsvList(input, fallback = []) {
  if (typeof input !== 'string' || !input.trim()) {
    return Array.isArray(fallback) ? [...fallback] : [];
  }
  return input
    .split(',')
    .map((value) => String(value || '').trim())
    .filter(Boolean);
}

const DEFAULT_CONFIG = {
  host: '0.0.0.0',
  port: Number(process.env.PORT) || 4430,
  tls: {
    enabled: process.env.GATEWAY_TLS_ENABLED === 'true',
    keyPath: process.env.GATEWAY_TLS_KEY || null,
    certPath: process.env.GATEWAY_TLS_CERT || null
  },
  publicBaseUrl: process.env.GATEWAY_PUBLIC_URL || 'https://hypertuna.com',
  metrics: {
    enabled: process.env.GATEWAY_METRICS_ENABLED !== 'false',
    path: process.env.GATEWAY_METRICS_PATH || '/metrics'
  },
  registration: {
    sharedSecret: process.env.GATEWAY_REGISTRATION_SECRET || null,
    redisUrl: process.env.GATEWAY_REGISTRATION_REDIS || null,
    redisPrefix: process.env.GATEWAY_REGISTRATION_REDIS_PREFIX || 'gateway:registrations:',
    cacheTtlSeconds: Number(process.env.GATEWAY_REGISTRATION_TTL || 1800),
    mirrorTtlSeconds: Number(process.env.GATEWAY_MIRROR_METADATA_TTL || 86400),
    openJoinPoolTtlSeconds: parseEnvNumber('GATEWAY_OPEN_JOIN_POOL_TTL', 21600),
    relayGcAfterMs: Number(process.env.GATEWAY_RELAY_GC_AFTER_MS || (90 * 24 * 60 * 60 * 1000)),
    defaultTokenTtl: Number(process.env.GATEWAY_DEFAULT_TOKEN_TTL || 3600),
    tokenRefreshWindowSeconds: Number(process.env.GATEWAY_TOKEN_REFRESH_WINDOW || 300)
  },
  rateLimit: {
    enabled: process.env.GATEWAY_RATELIMIT_ENABLED === 'true',
    windowSeconds: Number(process.env.GATEWAY_RATELIMIT_WINDOW || 60),
    maxRequests: Number(process.env.GATEWAY_RATELIMIT_MAX || 120)
  },
  discovery: {
    enabled: process.env.GATEWAY_DISCOVERY_ENABLED === 'true',
    openAccess: process.env.GATEWAY_DISCOVERY_OPEN_ACCESS !== 'false',
    displayName: process.env.GATEWAY_DISCOVERY_DISPLAY_NAME || '',
    region: process.env.GATEWAY_DISCOVERY_REGION || '',
    keySeed: process.env.GATEWAY_DISCOVERY_KEY_SEED || null,
    ttlSeconds: Number(process.env.GATEWAY_DISCOVERY_TTL || 60),
    refreshIntervalMs: Number(process.env.GATEWAY_DISCOVERY_REFRESH_MS || 30000),
    secretPath: process.env.GATEWAY_DISCOVERY_SECRET_PATH || '/.well-known/hyperpipe-gateway-secret',
    sharedSecretVersion: process.env.GATEWAY_DISCOVERY_SECRET_VERSION || '',
    protocolVersion: Number(process.env.GATEWAY_DISCOVERY_PROTOCOL_VERSION || 1),
    nostrEnabled: process.env.GATEWAY_NOSTR_DISCOVERY_ENABLED !== 'false',
    nostrRelayUrls: parseCsvList(
      process.env.GATEWAY_NOSTR_DISCOVERY_RELAYS,
      DEFAULT_NOSTR_DISCOVERY_RELAYS
    ),
    nostrPublishIntervalMs: Number(process.env.GATEWAY_NOSTR_DISCOVERY_REFRESH_MS || process.env.GATEWAY_DISCOVERY_REFRESH_MS || 30000),
    nostrKeySeed: process.env.GATEWAY_NOSTR_DISCOVERY_KEY_SEED || null
  },
  auth: {
    hostPolicy: (process.env.GATEWAY_AUTH_HOST_POLICY || 'open').trim().toLowerCase(),
    memberDelegationMode: (process.env.GATEWAY_AUTH_MEMBER_DELEGATION || 'all-members').trim().toLowerCase(),
    operatorPubkey: process.env.GATEWAY_AUTH_OPERATOR_PUBKEY || null,
    operatorAttestationFile: process.env.GATEWAY_AUTH_OPERATOR_ATTESTATION_FILE || null,
    allowlistPubkeys: parseCsvList(process.env.GATEWAY_AUTH_ALLOWLIST_PUBKEYS),
    allowlistFile: process.env.GATEWAY_AUTH_ALLOWLIST_FILE || null,
    allowlistRefreshMs: parseEnvNumber('GATEWAY_AUTH_ALLOWLIST_REFRESH_MS', 5000),
    blocklistPubkeys: parseCsvList(process.env.GATEWAY_AUTH_BLOCKLIST_PUBKEYS),
    blocklistFile: process.env.GATEWAY_AUTH_BLOCKLIST_FILE || null,
    blocklistRefreshMs: parseEnvNumber('GATEWAY_AUTH_BLOCKLIST_REFRESH_MS', 5000),
    wotRootPubkey: process.env.GATEWAY_AUTH_WOT_ROOT_PUBKEY || null,
    wotRelayUrls: parseCsvList(process.env.GATEWAY_AUTH_WOT_RELAYS),
    wotMaxDepth: parseEnvNumber('GATEWAY_AUTH_WOT_MAX_DEPTH', 1),
    wotMinFollowersDepth2: parseEnvNumber('GATEWAY_AUTH_WOT_MIN_FOLLOWERS_DEPTH2', 0),
    wotRefreshIntervalMs: parseEnvNumber('GATEWAY_AUTH_WOT_REFRESH_MS', 10 * 60 * 1000),
    wotLoadTimeoutMs: parseEnvNumber('GATEWAY_AUTH_WOT_LOAD_TIMEOUT_MS', 30_000),
    quotas: {
      maxRelaysPerSponsor: parseEnvNumber('GATEWAY_AUTH_MAX_RELAYS_PER_SPONSOR', 100),
      maxMembersPerRelay: parseEnvNumber('GATEWAY_AUTH_MAX_MEMBERS_PER_RELAY', 500),
      maxOpenJoinPool: parseEnvNumber('GATEWAY_AUTH_MAX_OPEN_JOIN_POOL', 100),
      maxMirroredBytesPerRelay: parseEnvNumber('GATEWAY_AUTH_MAX_MIRRORED_BYTES_PER_RELAY', 0)
    }
  },
  relay: {
    storageDir: process.env.GATEWAY_RELAY_STORAGE || null,
    datasetNamespace: process.env.GATEWAY_RELAY_NAMESPACE || 'public-gateway-relay',
    adminPublicKey: process.env.GATEWAY_RELAY_ADMIN_PUBLIC_KEY || null,
    adminSecretKey: process.env.GATEWAY_RELAY_ADMIN_SECRET_KEY || null,
    statsIntervalMs: Number(process.env.GATEWAY_RELAY_STATS_INTERVAL_MS || 15000),
    replicationTopic: process.env.GATEWAY_RELAY_REPLICATION_TOPIC || null,
    canonicalPath: process.env.GATEWAY_RELAY_CANONICAL_PATH || 'relay',
    aliasPaths: parseRelayAliasPaths(process.env.GATEWAY_RELAY_ALIAS_PATHS)
  },
  features: {
    hyperbeeRelayEnabled: process.env.GATEWAY_FEATURE_HYPERBEE_RELAY === 'true',
    dispatcherEnabled: process.env.GATEWAY_FEATURE_RELAY_DISPATCHER === 'true',
    tokenEnforcementEnabled: process.env.GATEWAY_FEATURE_RELAY_TOKEN_ENFORCEMENT === 'true'
  },
  dispatcher: {
    maxConcurrentJobsPerPeer: Number(process.env.GATEWAY_DISPATCHER_MAX_CONCURRENT || 3),
    inFlightWeight: Number(process.env.GATEWAY_DISPATCHER_INFLIGHT_WEIGHT || 25),
    latencyWeight: Number(process.env.GATEWAY_DISPATCHER_LATENCY_WEIGHT || 1),
    failureWeight: Number(process.env.GATEWAY_DISPATCHER_FAILURE_WEIGHT || 500),
    reassignOnLagBlocks: Number(process.env.GATEWAY_DISPATCHER_REASSIGN_LAG || 500),
    circuitBreakerThreshold: Number(process.env.GATEWAY_DISPATCHER_CB_THRESHOLD || 5),
    circuitBreakerDurationMs: Number(process.env.GATEWAY_DISPATCHER_CB_TIMEOUT_MS || 60000)
  },
  blindPeer: {
    enabled: process.env.GATEWAY_BLINDPEER_ENABLED === 'true',
    storageDir: process.env.GATEWAY_BLINDPEER_STORAGE || null,
    port: parseEnvNumber('GATEWAY_BLINDPEER_PORT', 0),
    maxBytes: Number(process.env.GATEWAY_BLINDPEER_MAX_BYTES) || DEFAULT_BLIND_PEER_MAX_BYTES,
    gcIntervalMs: Number(process.env.GATEWAY_BLINDPEER_GC_INTERVAL_MS) || 300000,
    dedupeBatchSize: Number(process.env.GATEWAY_BLINDPEER_DEDUPE_BATCH) || 100,
    staleCoreTtlMs: Number(process.env.GATEWAY_BLINDPEER_STALE_TTL_MS) || (7 * 24 * 60 * 60 * 1000),
    trustedPeersPersistPath: process.env.GATEWAY_BLINDPEER_TRUSTED_PATH || null
  },
  openJoin: {
    enabled: process.env.GATEWAY_OPEN_JOIN_ENABLED !== 'false',
    // 0 means non-expiring pool entries unless a lease carries explicit expiresAt.
    poolEntryTtlMs: Math.max(0, Math.trunc(parseEnvNumber('GATEWAY_OPEN_JOIN_POOL_TTL_MS', DEFAULT_OPEN_JOIN_POOL_ENTRY_TTL_MS))),
    challengeTtlMs: Number(process.env.GATEWAY_OPEN_JOIN_CHALLENGE_TTL_MS) || (2 * 60 * 1000),
    authWindowSeconds: Number(process.env.GATEWAY_OPEN_JOIN_AUTH_WINDOW || 300),
    maxPoolSize: Number(process.env.GATEWAY_OPEN_JOIN_MAX_POOL || 100)
  }
};

async function loadTlsOptions(tlsConfig) {
  if (!tlsConfig.enabled) return null;
  if (!tlsConfig.keyPath || !tlsConfig.certPath) {
    throw new Error('TLS enabled but key/cert paths not provided');
  }

  const [key, cert] = await Promise.all([
    readFile(resolve(tlsConfig.keyPath)),
    readFile(resolve(tlsConfig.certPath))
  ]);

  return { key, cert };
}

function loadConfig(overrides = {}) {
  const merged = {
    ...DEFAULT_CONFIG,
    ...overrides,
    tls: {
      ...DEFAULT_CONFIG.tls,
      ...(overrides.tls || {})
    },
    metrics: {
      ...DEFAULT_CONFIG.metrics,
      ...(overrides.metrics || {})
    },
    registration: {
      ...DEFAULT_CONFIG.registration,
      ...(overrides.registration || {})
    },
    rateLimit: {
      ...DEFAULT_CONFIG.rateLimit,
      ...(overrides.rateLimit || {})
    },
    discovery: {
      ...DEFAULT_CONFIG.discovery,
      ...(overrides.discovery || {})
    },
    auth: {
      ...DEFAULT_CONFIG.auth,
      ...(overrides.auth || {}),
      quotas: {
        ...DEFAULT_CONFIG.auth.quotas,
        ...(overrides.auth?.quotas || {})
      }
    },
    relay: {
      ...DEFAULT_CONFIG.relay,
      ...(overrides.relay || {})
    },
    features: {
      ...DEFAULT_CONFIG.features,
      ...(overrides.features || {})
    },
    dispatcher: {
      ...DEFAULT_CONFIG.dispatcher,
      ...(overrides.dispatcher || {})
    },
    blindPeer: {
      ...DEFAULT_CONFIG.blindPeer,
      ...(overrides.blindPeer || {})
    },
    openJoin: {
      ...DEFAULT_CONFIG.openJoin,
      ...(overrides.openJoin || {})
    }
  };

  if (!merged.publicBaseUrl) {
    throw new Error('Gateway requires a publicBaseUrl configuration value');
  }

  if (!merged.registration?.sharedSecret) {
    merged.discovery.openAccess = false;
  }

  merged.relay = normalizeRelaySettings(merged.relay);
  merged.blindPeer = normalizeBlindPeerSettings(merged.blindPeer);
  merged.auth = normalizeAuthSettings(merged.auth);

  if (!Number.isFinite(merged.registration.tokenTtlSeconds)) {
    merged.registration.tokenTtlSeconds = merged.registration.defaultTokenTtl;
  }

  if (Number.isFinite(merged.openJoin?.poolEntryTtlMs)) {
    const derivedPoolTtlSeconds = Math.ceil(merged.openJoin.poolEntryTtlMs / 1000);
    merged.registration.openJoinPoolTtlSeconds = derivedPoolTtlSeconds;
  }

  if (Number.isFinite(merged.registration?.relayGcAfterMs) && merged.registration.relayGcAfterMs > 0) {
    merged.registration.cacheTtlSeconds = 0;
    merged.registration.mirrorTtlSeconds = 0;
    merged.registration.openJoinPoolTtlSeconds = 0;
    merged.registration.relayTtlSeconds = 0;
    merged.registration.aliasTtlSeconds = 0;
  }

  if (Number.isFinite(merged.registration?.relayGcAfterMs)
    && merged.registration.relayGcAfterMs > 0
    && Number.isFinite(merged.blindPeer?.staleCoreTtlMs)
    && merged.blindPeer.staleCoreTtlMs < merged.registration.relayGcAfterMs) {
    merged.blindPeer.staleCoreTtlMs = merged.registration.relayGcAfterMs;
  }

  return merged;
}

function parseRelayAliasPaths(input) {
  if (!input) return null;
  if (Array.isArray(input)) return input.map((value) => (typeof value === 'string' ? value.trim() : value)).filter((value) => typeof value === 'string' && value.length);
  return String(input)
    .split(',')
    .map((value) => value.trim())
    .filter((value) => value.length);
}

function normalizeGatewayPathValue(value) {
  if (!value || typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return trimmed.replace(/^\/+/, '').replace(/\/+$/, '');
}

function normalizeRelaySettings(relayConfig = {}) {
  const result = { ...relayConfig };
  const canonicalPath = normalizeGatewayPathValue(result.canonicalPath) || 'relay';
  const aliasInput = Array.isArray(result.aliasPaths) ? result.aliasPaths : parseRelayAliasPaths(result.aliasPaths);
  const aliasSet = new Set();
  const addAlias = (value) => {
    const normalized = normalizeGatewayPathValue(value);
    if (normalized) {
      aliasSet.add(normalized);
    }
  };

  addAlias(canonicalPath);
  (aliasInput || []).forEach(addAlias);
  addAlias(LEGACY_PUBLIC_GATEWAY_PATH);
  addAlias('relay');

  result.canonicalPath = canonicalPath;
  result.aliasPaths = Array.from(aliasSet);
  return result;
}

function normalizeBlindPeerSettings(settings = {}) {
  const sanitizePath = (value) => {
    if (!value || typeof value !== 'string') return null;
    const trimmed = value.trim();
    return trimmed.length ? trimmed : null;
  };

  const toPositiveInt = (value, fallback) => {
    const num = Number(value);
    return Number.isFinite(num) && num > 0 ? Math.trunc(num) : fallback;
  };

  const toOptionalPort = (value) => {
    const num = Number(value);
    return Number.isFinite(num) && num > 0 ? Math.trunc(num) : 0;
  };

  return {
    enabled: !!settings.enabled,
    storageDir: sanitizePath(settings.storageDir),
    port: toOptionalPort(settings.port),
    maxBytes: toPositiveInt(settings.maxBytes, DEFAULT_BLIND_PEER_MAX_BYTES),
    gcIntervalMs: toPositiveInt(settings.gcIntervalMs, 300000),
    dedupeBatchSize: toPositiveInt(settings.dedupeBatchSize, 100),
    staleCoreTtlMs: toPositiveInt(settings.staleCoreTtlMs, 7 * 24 * 60 * 60 * 1000),
    trustedPeersPersistPath: sanitizePath(settings.trustedPeersPersistPath)
  };
}

function normalizeHexPubkey(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim().toLowerCase();
  return /^[0-9a-f]{64}$/.test(trimmed) ? trimmed : null;
}

function normalizeAuthSettings(settings = {}) {
  const result = {
    ...settings,
    quotas: {
      ...(settings?.quotas || {})
    }
  };

  const hostPolicy = typeof result.hostPolicy === 'string'
    ? result.hostPolicy.trim().toLowerCase()
    : 'open';
  result.hostPolicy = ['open', 'allowlist', 'wot', 'allowlist+wot'].includes(hostPolicy)
    ? hostPolicy
    : 'open';

  const memberDelegationMode = typeof result.memberDelegationMode === 'string'
    ? result.memberDelegationMode.trim().toLowerCase()
    : 'all-members';
  result.memberDelegationMode = ['none', 'closed-members', 'all-members'].includes(memberDelegationMode)
    ? memberDelegationMode
    : 'all-members';

  result.operatorPubkey = normalizeHexPubkey(result.operatorPubkey);
  result.operatorAttestationFile = typeof result.operatorAttestationFile === 'string' && result.operatorAttestationFile.trim().length
    ? result.operatorAttestationFile.trim()
    : null;
  result.allowlistPubkeys = Array.from(new Set(
    (Array.isArray(result.allowlistPubkeys) ? result.allowlistPubkeys : [])
      .map((value) => normalizeHexPubkey(value))
      .filter(Boolean)
  ));
  result.allowlistFile = typeof result.allowlistFile === 'string' && result.allowlistFile.trim().length
    ? result.allowlistFile.trim()
    : null;
  result.allowlistRefreshMs = Number.isFinite(Number(result.allowlistRefreshMs))
    ? Math.max(0, Math.trunc(Number(result.allowlistRefreshMs)))
    : 5000;
  result.blocklistPubkeys = Array.from(new Set(
    (Array.isArray(result.blocklistPubkeys) ? result.blocklistPubkeys : [])
      .map((value) => normalizeHexPubkey(value))
      .filter(Boolean)
  ));
  result.blocklistFile = typeof result.blocklistFile === 'string' && result.blocklistFile.trim().length
    ? result.blocklistFile.trim()
    : null;
  result.blocklistRefreshMs = Number.isFinite(Number(result.blocklistRefreshMs))
    ? Math.max(0, Math.trunc(Number(result.blocklistRefreshMs)))
    : 5000;
  result.wotRootPubkey = normalizeHexPubkey(result.wotRootPubkey);
  result.wotRelayUrls = Array.from(new Set(
    (Array.isArray(result.wotRelayUrls) ? result.wotRelayUrls : [])
      .map((value) => (typeof value === 'string' ? value.trim() : ''))
      .filter(Boolean)
  ));
  result.wotMaxDepth = Number.isFinite(Number(result.wotMaxDepth))
    ? Math.max(1, Math.trunc(Number(result.wotMaxDepth)))
    : 1;
  result.wotMinFollowersDepth2 = Number.isFinite(Number(result.wotMinFollowersDepth2))
    ? Math.max(0, Math.trunc(Number(result.wotMinFollowersDepth2)))
    : 0;
  result.wotRefreshIntervalMs = Number.isFinite(Number(result.wotRefreshIntervalMs))
    ? Math.max(60_000, Math.trunc(Number(result.wotRefreshIntervalMs)))
    : (10 * 60 * 1000);
  result.wotLoadTimeoutMs = Number.isFinite(Number(result.wotLoadTimeoutMs))
    ? Math.max(1_000, Math.trunc(Number(result.wotLoadTimeoutMs)))
    : 30_000;
  result.quotas = {
    maxRelaysPerSponsor: Number.isFinite(Number(result.quotas?.maxRelaysPerSponsor))
      ? Math.max(0, Math.trunc(Number(result.quotas.maxRelaysPerSponsor)))
      : 100,
    maxMembersPerRelay: Number.isFinite(Number(result.quotas?.maxMembersPerRelay))
      ? Math.max(0, Math.trunc(Number(result.quotas.maxMembersPerRelay)))
      : 500,
    maxOpenJoinPool: Number.isFinite(Number(result.quotas?.maxOpenJoinPool))
      ? Math.max(0, Math.trunc(Number(result.quotas.maxOpenJoinPool)))
      : 100,
    maxMirroredBytesPerRelay: Number.isFinite(Number(result.quotas?.maxMirroredBytesPerRelay))
      ? Math.max(0, Math.trunc(Number(result.quotas.maxMirroredBytesPerRelay)))
      : 0
  };

  return result;
}

export {
  loadConfig,
  loadTlsOptions
};
