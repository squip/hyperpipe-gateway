import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { schnorr } from '@noble/curves/secp256k1';

import PublicGatewayService from '../src/PublicGatewayService.mjs';
import MemoryRegistrationStore from '../src/stores/MemoryRegistrationStore.mjs';

const ADMIN_SCOPE = 'gateway:allowlist-admin';
const ACCOUNTS = {
  operator: {
    role: 'operator',
    pubkeyHex: '75a3b6ac739a1c8e60edd5bbaa4b9486b1436b9cd23e5b739e22d0b0958724f8',
    secretHex: 'c5c0dee846de0bf4d8a9633b5d6ecab1efbcc138c713d4f8f2c9b70be455e8c9'
  },
  allowlistOnly: {
    role: 'allowlist_only',
    pubkeyHex: '5930023f28ea6f14e48812fe18eedaa8bac608068eb781617abfbd2a7e7aab1f',
    secretHex: '25682cebac193c4e4f1063beb9afca08b7390010b1cba240db0250f3a97c77ae'
  },
  wotDepth1: {
    role: 'wot_depth1',
    pubkeyHex: 'f667ecd68133d75cbb0bf66a52b843a96ca0dba239c839da18e64ee8639af0fa',
    secretHex: 'd6f638421edf37426c2250d96da577463ec37b93febe3122b32e074c47d0b6be'
  },
  outsider: {
    role: 'outsider',
    pubkeyHex: '0d1850aae25bdc9eb93cd2d8774db3d27506f4e7ff79e0df0cb4e0db9f759e8b',
    secretHex: '4d4d33fdf55d5c9ac3e9443d59960719adb5842db0825cb93bab24ad87a15eae'
  }
};

function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || /[^0-9a-f]/i.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function createLogger(warnings) {
  const noop = () => {};
  const logger = {
    info: noop,
    error: noop,
    debug: noop,
    warn(...args) {
      warnings.push(args);
    },
    child() {
      return logger;
    }
  };
  return logger;
}

function createConfig({
  port,
  hostPolicy = 'allowlist',
  allowlistPubkeys = [],
  allowlistFile = null,
  allowlistRefreshMs = 50,
  blocklistPubkeys = [],
  blocklistFile = null,
  blocklistRefreshMs = 50,
  wotMaxDepth = 2,
  wotMinFollowersDepth2 = 2
} = {}) {
  return {
    host: '127.0.0.1',
    port,
    publicBaseUrl: `http://127.0.0.1:${port}`,
    metrics: { enabled: false, path: '/metrics' },
    registration: {
      sharedSecret: 'test-shared-secret',
      cacheTtlSeconds: 60,
      defaultTokenTtl: 3600,
      tokenRefreshWindowSeconds: 300
    },
    discovery: { enabled: false, openAccess: false, nostrRelayUrls: [] },
    auth: {
      hostPolicy,
      authMethod: 'relay-scoped-bearer-v1',
      operatorPubkey: ACCOUNTS.operator.pubkeyHex,
      allowlistPubkeys,
      allowlistFile,
      allowlistRefreshMs,
      blocklistPubkeys,
      blocklistFile,
      blocklistRefreshMs,
      memberDelegationMode: 'all-members',
      wotRootPubkey: ACCOUNTS.operator.pubkeyHex,
      wotMaxDepth,
      wotMinFollowersDepth2
    },
    relay: {},
    features: {
      hyperbeeRelayEnabled: false,
      dispatcherEnabled: false,
      tokenEnforcementEnabled: false
    },
    dispatcher: {},
    blindPeer: { enabled: false }
  };
}

async function createService(options = {}) {
  const warnings = [];
  const logger = createLogger(warnings);
  const registrationStore = new MemoryRegistrationStore(60);
  const service = new PublicGatewayService({
    config: createConfig(options),
    logger,
    registrationStore
  });
  await service.init();
  await service.start();
  const address = service.server.address();
  const port = typeof address === 'object' && address ? address.port : options.port;
  return {
    service,
    warnings,
    baseUrl: `http://127.0.0.1:${port}`
  };
}

function installFakeWotGraph(service, {
  distances = {},
  followerCounts = {}
} = {}) {
  const nodes = new Map([
    [ACCOUNTS.operator.pubkeyHex, {
      pubkey: ACCOUNTS.operator.pubkeyHex,
      depth: 0,
      followedBy: new Set()
    }]
  ]);
  for (const [pubkey, depth] of Object.entries(distances)) {
    nodes.set(pubkey, {
      pubkey,
      depth,
      followedBy: new Set(
        Array.from({ length: Math.max(0, Number(followerCounts[pubkey]) || 0) }, (_, index) => `${pubkey}:${index}`)
      )
    });
  }
  service.wotState = {
    wot: {
      nodes,
      getDistance(pubkey) {
        return Object.prototype.hasOwnProperty.call(distances, pubkey)
          ? distances[pubkey]
          : null;
      },
      getNode(pubkey) {
        if (!Object.prototype.hasOwnProperty.call(followerCounts, pubkey)) return null;
        const count = Math.max(0, Number(followerCounts[pubkey]) || 0);
        return {
          followedBy: new Set(Array.from({ length: count }, (_, index) => `${pubkey}:${index}`))
        };
      }
    },
    rootPubkey: ACCOUNTS.operator.pubkeyHex,
    relayUrls: [],
    loadedAt: Date.now(),
    expiresAt: Date.now() + 60_000,
    loadingPromise: null,
    lastError: null
  };
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let payload = {};
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    payload = { raw: text };
  }
  return { response, payload, text };
}

async function probeGatewayAuth(baseUrl, account, {
  scope = 'gateway:relay-register',
  relayKey = null
} = {}) {
  const challengeResponse = await fetchJson(`${baseUrl}/api/auth/challenge`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      pubkey: account.pubkeyHex,
      scope,
      relayKey
    })
  });
  assert.equal(challengeResponse.response.status, 200, `challenge failed for ${account.role}`);
  const signatureBytes = await schnorr.sign(
    new TextEncoder().encode(challengeResponse.payload.nonce),
    hexToBytes(account.secretHex)
  );
  const signature = Buffer.from(signatureBytes).toString('hex');
  return fetchJson(`${baseUrl}/api/auth/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      challengeId: challengeResponse.payload.challengeId,
      pubkey: account.pubkeyHex,
      signature,
      scope,
      relayKey
    })
  });
}

async function signAdminEvent(account, { challenge, relay, purpose = ADMIN_SCOPE }) {
  const event = {
    pubkey: account.pubkeyHex,
    created_at: Math.floor(Date.now() / 1000),
    kind: 22242,
    tags: [
      ['challenge', challenge],
      ['relay', relay],
      ['purpose', purpose]
    ],
    content: ''
  };
  const serialized = JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content
  ]);
  event.id = createHash('sha256').update(serialized).digest('hex');
  const sigBytes = await schnorr.sign(hexToBytes(event.id), hexToBytes(account.secretHex));
  return {
    ...event,
    sig: Buffer.from(sigBytes).toString('hex')
  };
}

async function authenticateAdmin(baseUrl, account = ACCOUNTS.operator) {
  const challenge = await fetchJson(`${baseUrl}/api/admin/auth/challenge`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ pubkey: account.pubkeyHex })
  });
  assert.equal(challenge.response.status, 200);
  const authEvent = await signAdminEvent(account, {
    challenge: challenge.payload.challenge,
    relay: challenge.payload.relay,
    purpose: challenge.payload.purpose
  });
  const verification = await fetchJson(`${baseUrl}/api/admin/auth/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ authEvent })
  });
  assert.equal(verification.response.status, 200);
  return verification.payload.token;
}

async function getAdminAllowlist(baseUrl, token) {
  return fetchJson(`${baseUrl}/api/admin/allowlist`, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${token}`
    }
  });
}

async function putAdminAllowlist(baseUrl, token, pubkeys) {
  return fetchJson(`${baseUrl}/api/admin/allowlist`, {
    method: 'PUT',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json'
    },
    body: JSON.stringify({ pubkeys })
  });
}

async function getAdminBlocklist(baseUrl, token) {
  return fetchJson(`${baseUrl}/api/admin/blocklist`, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${token}`
    }
  });
}

async function putAdminBlocklist(baseUrl, token, pubkeys) {
  return fetchJson(`${baseUrl}/api/admin/blocklist`, {
    method: 'PUT',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json'
    },
    body: JSON.stringify({ pubkeys })
  });
}

async function getAdminWot(baseUrl, token) {
  return fetchJson(`${baseUrl}/api/admin/wot`, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${token}`
    }
  });
}

test('file-backed access manager bootstraps the allowlist and serves the admin page assets', async () => {
  const tempDir = await mkdtemp(join(tmpdir(), 'pg-allowlist-'));
  const allowlistFile = join(tempDir, 'allowlist.json');
  const blocklistFile = join(tempDir, 'blocklist.json');
  const { service, baseUrl } = await createService({
    port: 0,
    hostPolicy: 'allowlist',
    allowlistFile,
    blocklistFile,
    allowlistPubkeys: [
      ACCOUNTS.allowlistOnly.pubkeyHex.toUpperCase(),
      ACCOUNTS.allowlistOnly.pubkeyHex
    ]
  });

  try {
    const stored = JSON.parse(await readFile(allowlistFile, 'utf8'));
    assert.deepEqual(stored.pubkeys, [ACCOUNTS.allowlistOnly.pubkeyHex]);

    const html = await fetchJson(`${baseUrl}/admin/allowlist`);
    assert.equal(html.response.status, 200);
    assert.match(html.text, /Access Manager/);
    assert.match(html.text, /Loading the access manager/);

    const hashesUtils = await fetchJson(`${baseUrl}/admin/allowlist/vendor/@noble/hashes/utils`);
    assert.equal(hashesUtils.response.status, 200);
    assert.match(hashesUtils.text, /randomBytes|createView/);

    const hashesCrypto = await fetchJson(`${baseUrl}/admin/allowlist/vendor/@noble/hashes/crypto`);
    assert.equal(hashesCrypto.response.status, 200);
    assert.match(hashesCrypto.text, /export.*crypto|const crypto/);

    const token = await authenticateAdmin(baseUrl);
    const list = await getAdminAllowlist(baseUrl, token);
    assert.equal(list.response.status, 200);
    assert.equal(list.payload.source, 'env-bootstrap');
    assert.equal(list.payload.count, 1);
    assert.deepEqual(list.payload.pubkeys, [ACCOUNTS.allowlistOnly.pubkeyHex]);

    const blocklist = await getAdminBlocklist(baseUrl, token);
    assert.equal(blocklist.response.status, 200);
    assert.equal(blocklist.payload.count, 0);
  } finally {
    await service.stop();
    await rm(tempDir, { recursive: true, force: true });
  }
});

test('allowlist policy updates live without a container restart', async () => {
  const tempDir = await mkdtemp(join(tmpdir(), 'pg-allowlist-'));
  const allowlistFile = join(tempDir, 'allowlist.json');
  const { service, baseUrl } = await createService({
    port: 0,
    hostPolicy: 'allowlist',
    allowlistFile,
    allowlistPubkeys: []
  });

  try {
    let auth = await probeGatewayAuth(baseUrl, ACCOUNTS.allowlistOnly);
    assert.equal(auth.response.status, 403);

    const token = await authenticateAdmin(baseUrl);
    const update = await putAdminAllowlist(baseUrl, token, [
      ACCOUNTS.allowlistOnly.pubkeyHex.toUpperCase(),
      ACCOUNTS.allowlistOnly.pubkeyHex
    ]);
    assert.equal(update.response.status, 200);
    assert.deepEqual(update.payload.pubkeys, [ACCOUNTS.allowlistOnly.pubkeyHex]);
    assert.equal(update.payload.updatedBy, ACCOUNTS.operator.pubkeyHex);

    auth = await probeGatewayAuth(baseUrl, ACCOUNTS.allowlistOnly);
    assert.equal(auth.response.status, 200);

    const cleared = await putAdminAllowlist(baseUrl, token, []);
    assert.equal(cleared.response.status, 200);
    auth = await probeGatewayAuth(baseUrl, ACCOUNTS.allowlistOnly);
    assert.equal(auth.response.status, 403);
  } finally {
    await service.stop();
    await rm(tempDir, { recursive: true, force: true });
  }
});

test('allowlist+wot keeps live allowlist updates and WoT approvals active together', async () => {
  const tempDir = await mkdtemp(join(tmpdir(), 'pg-allowlist-'));
  const allowlistFile = join(tempDir, 'allowlist.json');
  const blocklistFile = join(tempDir, 'blocklist.json');
  const { service, baseUrl } = await createService({
    port: 0,
    hostPolicy: 'allowlist+wot',
    allowlistFile,
    blocklistFile,
    allowlistPubkeys: []
  });

  try {
    installFakeWotGraph(service, {
      distances: {
        [ACCOUNTS.wotDepth1.pubkeyHex]: 1
      }
    });

    let allowlistOnly = await probeGatewayAuth(baseUrl, ACCOUNTS.allowlistOnly);
    let wotApproved = await probeGatewayAuth(baseUrl, ACCOUNTS.wotDepth1);
    assert.equal(allowlistOnly.response.status, 403);
    assert.equal(wotApproved.response.status, 200);

    const token = await authenticateAdmin(baseUrl);
    const wotSnapshot = await getAdminWot(baseUrl, token);
    assert.equal(wotSnapshot.response.status, 200);
    assert.ok(Array.isArray(wotSnapshot.payload.pubkeys));
    assert.equal(wotSnapshot.payload.pubkeys[0].pubkey, ACCOUNTS.operator.pubkeyHex);
    assert.equal(wotSnapshot.payload.pubkeys[1].pubkey, ACCOUNTS.wotDepth1.pubkeyHex);
    assert.equal(wotSnapshot.payload.pubkeys[1].depth, 1);
    assert.equal(wotSnapshot.payload.pubkeys[1].approved, true);

    const update = await putAdminAllowlist(baseUrl, token, [ACCOUNTS.allowlistOnly.pubkeyHex]);
    assert.equal(update.response.status, 200);

    allowlistOnly = await probeGatewayAuth(baseUrl, ACCOUNTS.allowlistOnly);
    wotApproved = await probeGatewayAuth(baseUrl, ACCOUNTS.wotDepth1);
    assert.equal(allowlistOnly.response.status, 200);
    assert.equal(wotApproved.response.status, 200);
  } finally {
    await service.stop();
    await rm(tempDir, { recursive: true, force: true });
  }
});

test('wot-only policy exposes the access manager and blocklist overrides WoT approval', async () => {
  const tempDir = await mkdtemp(join(tmpdir(), 'pg-allowlist-'));
  const blocklistFile = join(tempDir, 'blocklist.json');
  const { service, baseUrl } = await createService({
    port: 0,
    hostPolicy: 'wot',
    blocklistFile,
    blocklistPubkeys: [ACCOUNTS.wotDepth1.pubkeyHex]
  });

  try {
    installFakeWotGraph(service, {
      distances: {
        [ACCOUNTS.wotDepth1.pubkeyHex]: 1
      }
    });

    const page = await fetchJson(`${baseUrl}/admin/allowlist`);
    assert.equal(page.response.status, 200);

    const outsider = await probeGatewayAuth(baseUrl, ACCOUNTS.outsider);
    const wotApproved = await probeGatewayAuth(baseUrl, ACCOUNTS.wotDepth1);
    assert.equal(outsider.response.status, 403);
    assert.equal(wotApproved.response.status, 403);

    const token = await authenticateAdmin(baseUrl);
    const blocklist = await getAdminBlocklist(baseUrl, token);
    assert.equal(blocklist.response.status, 200);
    assert.deepEqual(blocklist.payload.pubkeys, [ACCOUNTS.wotDepth1.pubkeyHex]);

    const cleared = await putAdminBlocklist(baseUrl, token, []);
    assert.equal(cleared.response.status, 200);

    const wotApprovedAfterClear = await probeGatewayAuth(baseUrl, ACCOUNTS.wotDepth1);
    assert.equal(wotApprovedAfterClear.response.status, 200);
  } finally {
    await service.stop();
    await rm(tempDir, { recursive: true, force: true });
  }
});

test('blocklist overrides open and allowlist approvals', async () => {
  const tempDir = await mkdtemp(join(tmpdir(), 'pg-blocklist-'));
  const blocklistFile = join(tempDir, 'blocklist.json');
  const allowlistFile = join(tempDir, 'allowlist.json');

  const openService = await createService({
    port: 0,
    hostPolicy: 'open',
    blocklistFile,
    blocklistPubkeys: [ACCOUNTS.outsider.pubkeyHex]
  });

  const allowlistService = await createService({
    port: 0,
    hostPolicy: 'allowlist',
    allowlistFile,
    allowlistPubkeys: [ACCOUNTS.allowlistOnly.pubkeyHex],
    blocklistFile: join(tempDir, 'allowlist-blocklist.json'),
    blocklistPubkeys: [ACCOUNTS.allowlistOnly.pubkeyHex]
  });

  try {
    const openOutsider = await probeGatewayAuth(openService.baseUrl, ACCOUNTS.outsider);
    const allowlisted = await probeGatewayAuth(allowlistService.baseUrl, ACCOUNTS.allowlistOnly);
    assert.equal(openOutsider.response.status, 403);
    assert.equal(allowlisted.response.status, 403);
  } finally {
    await openService.service.stop();
    await allowlistService.service.stop();
    await rm(tempDir, { recursive: true, force: true });
  }
});

test('operator admin auth still works when the operator is blocklisted for host access', async () => {
  const tempDir = await mkdtemp(join(tmpdir(), 'pg-blocklist-'));
  const blocklistFile = join(tempDir, 'blocklist.json');
  const { service, baseUrl } = await createService({
    port: 0,
    hostPolicy: 'wot',
    blocklistFile,
    blocklistPubkeys: [ACCOUNTS.operator.pubkeyHex]
  });

  try {
    installFakeWotGraph(service, {
      distances: {
        [ACCOUNTS.wotDepth1.pubkeyHex]: 1
      }
    });

    const token = await authenticateAdmin(baseUrl);
    assert.ok(token);

    const operatorHostAccess = await probeGatewayAuth(baseUrl, ACCOUNTS.operator);
    assert.equal(operatorHostAccess.response.status, 403);

    const blocklist = await getAdminBlocklist(baseUrl, token);
    assert.equal(blocklist.response.status, 200);
    assert.deepEqual(blocklist.payload.pubkeys, [ACCOUNTS.operator.pubkeyHex]);
  } finally {
    await service.stop();
    await rm(tempDir, { recursive: true, force: true });
  }
});

test('admin auth rejects non-operator identities, wrong-purpose events, and non-admin bearer scopes', async () => {
  const tempDir = await mkdtemp(join(tmpdir(), 'pg-allowlist-'));
  const allowlistFile = join(tempDir, 'allowlist.json');
  const { service, baseUrl } = await createService({
    port: 0,
    hostPolicy: 'allowlist',
    allowlistFile,
    allowlistPubkeys: [ACCOUNTS.allowlistOnly.pubkeyHex]
  });

  try {
    const outsiderChallenge = await fetchJson(`${baseUrl}/api/admin/auth/challenge`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ pubkey: ACCOUNTS.outsider.pubkeyHex })
    });
    assert.equal(outsiderChallenge.response.status, 403);

    const challenge = await fetchJson(`${baseUrl}/api/admin/auth/challenge`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ pubkey: ACCOUNTS.operator.pubkeyHex })
    });
    assert.equal(challenge.response.status, 200);
    const wrongPurposeEvent = await signAdminEvent(ACCOUNTS.operator, {
      challenge: challenge.payload.challenge,
      relay: challenge.payload.relay,
      purpose: 'wrong-purpose'
    });
    const wrongPurpose = await fetchJson(`${baseUrl}/api/admin/auth/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ authEvent: wrongPurposeEvent })
    });
    assert.equal(wrongPurpose.response.status, 401);

    const rawScope = await probeGatewayAuth(baseUrl, ACCOUNTS.allowlistOnly);
    assert.equal(rawScope.response.status, 200);
    const listWithWrongScope = await fetchJson(`${baseUrl}/api/admin/allowlist`, {
      method: 'GET',
      headers: {
        authorization: `Bearer ${rawScope.payload.token}`
      }
    });
    assert.equal(listWithWrongScope.response.status, 401);
  } finally {
    await service.stop();
    await rm(tempDir, { recursive: true, force: true });
  }
});

test('allowlist store reloads external file edits and keeps the last good state on malformed updates', async () => {
  const tempDir = await mkdtemp(join(tmpdir(), 'pg-allowlist-'));
  const allowlistFile = join(tempDir, 'allowlist.json');
  const { service, baseUrl } = await createService({
    port: 0,
    hostPolicy: 'allowlist',
    allowlistFile,
    allowlistPubkeys: [],
    allowlistRefreshMs: 40
  });

  try {
    let auth = await probeGatewayAuth(baseUrl, ACCOUNTS.allowlistOnly);
    assert.equal(auth.response.status, 403);

    await writeFile(allowlistFile, JSON.stringify({
      version: 1,
      updatedAt: Date.now(),
      updatedBy: ACCOUNTS.operator.pubkeyHex,
      pubkeys: [ACCOUNTS.allowlistOnly.pubkeyHex]
    }, null, 2));
    await new Promise((resolve) => setTimeout(resolve, 80));

    auth = await probeGatewayAuth(baseUrl, ACCOUNTS.allowlistOnly);
    assert.equal(auth.response.status, 200);

    await writeFile(allowlistFile, '{"version":1,"pubkeys":["not-a-pubkey"]}\n');
    await new Promise((resolve) => setTimeout(resolve, 80));

    auth = await probeGatewayAuth(baseUrl, ACCOUNTS.allowlistOnly);
    assert.equal(auth.response.status, 200);

    const token = await authenticateAdmin(baseUrl);
    const list = await getAdminAllowlist(baseUrl, token);
    assert.equal(list.response.status, 200);
    assert.match(list.payload.lastError || '', /invalid-allowlist-pubkey/);
  } finally {
    await service.stop();
    await rm(tempDir, { recursive: true, force: true });
  }
});

test('allowlist PUT validates input and preserves state when persistence fails', async () => {
  const tempDir = await mkdtemp(join(tmpdir(), 'pg-allowlist-'));
  const allowlistFile = join(tempDir, 'allowlist.json');
  const { service, baseUrl } = await createService({
    port: 0,
    hostPolicy: 'allowlist',
    allowlistFile,
    allowlistPubkeys: [ACCOUNTS.allowlistOnly.pubkeyHex]
  });

  try {
    const token = await authenticateAdmin(baseUrl);

    const invalid = await putAdminAllowlist(baseUrl, token, ['not-a-pubkey']);
    assert.equal(invalid.response.status, 400);

    service.allowlistStore.filePath = tempDir;
    const failed = await putAdminAllowlist(baseUrl, token, []);
    assert.equal(failed.response.status, 500);

    const list = await getAdminAllowlist(baseUrl, token);
    assert.equal(list.response.status, 200);
    assert.deepEqual(list.payload.pubkeys, [ACCOUNTS.allowlistOnly.pubkeyHex]);

    const auth = await probeGatewayAuth(baseUrl, ACCOUNTS.allowlistOnly);
    assert.equal(auth.response.status, 200);
  } finally {
    await service.stop();
    await rm(tempDir, { recursive: true, force: true });
  }
});
