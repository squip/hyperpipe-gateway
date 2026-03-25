import test from 'node:test';
import assert from 'node:assert/strict';
import { schnorr } from '@noble/curves/secp256k1';

import PublicGatewayService from '../src/PublicGatewayService.mjs';
import MemoryRegistrationStore from '../src/stores/MemoryRegistrationStore.mjs';

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
  wotDepth2Pass: {
    role: 'wot_depth2_pass',
    pubkeyHex: '51020b69ff4c2941a25612cfe6056014980e0348c0c98386ba967cc5e13723e2',
    secretHex: '833df9b70cdb66e4e06211b186ca4cf58920906bfaee64372e8b88752da1d9ea'
  },
  wotDepth2Fail: {
    role: 'wot_depth2_fail',
    pubkeyHex: 'ca312f5a04700b4ab6eb47587b3714b0cbe7b3550e4cd5909ab43223094c93b4',
    secretHex: '4d7759cf139cec748cfd4ca1d3ce19076efd5a1f6fc57ac5e42e46f52f99f8da'
  },
  wotDepth3: {
    role: 'wot_depth3',
    pubkeyHex: '6106ee36530fb546d9edcdab39caa5c14fa159a0a85044799095ba9ca37e908b',
    secretHex: '3da7a07c653b5368ca80156afc06f352aedc0d981861d4fdadb2b310838fdef3'
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
  hostPolicy = 'wot',
  allowlistPubkeys = [],
  wotRootPubkey = ACCOUNTS.operator.pubkeyHex,
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
      memberDelegationMode: 'all-members',
      wotRootPubkey,
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
    logger,
    warnings,
    baseUrl: `http://127.0.0.1:${port}`
  };
}

function installFakeWotGraph(service, {
  distances = {},
  followerCounts = {}
} = {}) {
  const defaultNode = {
    followedBy: new Set()
  };
  service.wotState = {
    ndk: null,
    wot: {
      getDistance(pubkey) {
        return Object.prototype.hasOwnProperty.call(distances, pubkey)
          ? distances[pubkey]
          : null;
      },
      getNode(pubkey) {
        if (!Object.prototype.hasOwnProperty.call(followerCounts, pubkey)) return null;
        const count = Math.max(0, Number(followerCounts[pubkey]) || 0);
        return {
          ...defaultNode,
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

async function probeGatewayAuth(baseUrl, account, {
  scope = 'gateway:relay-register',
  relayKey = null
} = {}) {
  const challengeResponse = await fetch(`${baseUrl}/api/auth/challenge`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      pubkey: account.pubkeyHex,
      scope,
      relayKey
    })
  });
  const challengePayload = await challengeResponse.json();
  assert.equal(challengeResponse.status, 200, `challenge failed for ${account.role}`);
  const signatureBytes = await schnorr.sign(
    new TextEncoder().encode(challengePayload.nonce),
    hexToBytes(account.secretHex)
  );
  const signature = Buffer.from(signatureBytes).toString('hex');
  const verifyResponse = await fetch(`${baseUrl}/api/auth/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      challengeId: challengePayload.challengeId,
      pubkey: account.pubkeyHex,
      signature,
      scope,
      relayKey
    })
  });
  const text = await verifyResponse.text();
  let payload = {};
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    payload = { raw: text };
  }
  return {
    status: verifyResponse.status,
    payload
  };
}

test('PublicGatewayService enforces deterministic WoT policy decisions', async () => {
  const { service, baseUrl } = await createService({
    port: 0,
    hostPolicy: 'wot',
    wotMaxDepth: 2,
    wotMinFollowersDepth2: 2
  });

  try {
    installFakeWotGraph(service, {
      distances: {
        [ACCOUNTS.wotDepth1.pubkeyHex]: 1,
        [ACCOUNTS.wotDepth2Pass.pubkeyHex]: 2,
        [ACCOUNTS.wotDepth2Fail.pubkeyHex]: 2,
        [ACCOUNTS.wotDepth3.pubkeyHex]: 3
      },
      followerCounts: {
        [ACCOUNTS.wotDepth2Pass.pubkeyHex]: 2,
        [ACCOUNTS.wotDepth2Fail.pubkeyHex]: 1
      }
    });

    const depth1 = await probeGatewayAuth(baseUrl, ACCOUNTS.wotDepth1);
    const depth2Pass = await probeGatewayAuth(baseUrl, ACCOUNTS.wotDepth2Pass);
    const depth2Fail = await probeGatewayAuth(baseUrl, ACCOUNTS.wotDepth2Fail);
    const depth3 = await probeGatewayAuth(baseUrl, ACCOUNTS.wotDepth3);
    const outsider = await probeGatewayAuth(baseUrl, ACCOUNTS.outsider);

    assert.equal(depth1.status, 200);
    assert.ok(typeof depth1.payload.token === 'string');
    assert.equal(depth2Pass.status, 200);
    assert.ok(typeof depth2Pass.payload.token === 'string');
    assert.equal(depth2Fail.status, 403);
    assert.equal(depth2Fail.payload.error, 'gateway-host-unauthorized');
    assert.equal(depth3.status, 403);
    assert.equal(depth3.payload.error, 'gateway-host-unauthorized');
    assert.equal(outsider.status, 403);
    assert.equal(outsider.payload.error, 'gateway-host-unauthorized');
  } finally {
    await service.stop();
  }
});

test('PublicGatewayService allowlist+wot combines both approval branches', async () => {
  const { service, baseUrl } = await createService({
    port: 0,
    hostPolicy: 'allowlist+wot',
    allowlistPubkeys: [ACCOUNTS.allowlistOnly.pubkeyHex],
    wotMaxDepth: 2,
    wotMinFollowersDepth2: 2
  });

  try {
    installFakeWotGraph(service, {
      distances: {
        [ACCOUNTS.wotDepth1.pubkeyHex]: 1
      }
    });

    const allowlisted = await probeGatewayAuth(baseUrl, ACCOUNTS.allowlistOnly);
    const wotApproved = await probeGatewayAuth(baseUrl, ACCOUNTS.wotDepth1);
    const outsider = await probeGatewayAuth(baseUrl, ACCOUNTS.outsider);

    assert.equal(allowlisted.status, 200);
    assert.equal(wotApproved.status, 200);
    assert.equal(outsider.status, 403);
    assert.equal(outsider.payload.error, 'gateway-host-unauthorized');
  } finally {
    await service.stop();
  }
});

test('PublicGatewayService surfaces WoT timeout failures as denied host auth', async () => {
  const { service, baseUrl, warnings } = await createService({
    port: 0,
    hostPolicy: 'wot',
    wotMaxDepth: 2,
    wotMinFollowersDepth2: 2
  });

  try {
    const timeoutError = new Error('Timeout fetching contact lists for 1 authors');
    const loadingPromise = Promise.reject(timeoutError);
    loadingPromise.catch(() => {});
    service.wotState = {
      ndk: null,
      wot: null,
      rootPubkey: ACCOUNTS.operator.pubkeyHex,
      relayUrls: [],
      loadedAt: 0,
      expiresAt: 0,
      loadingPromise,
      lastError: null
    };

    const response = await probeGatewayAuth(baseUrl, ACCOUNTS.wotDepth1);
    assert.equal(response.status, 403);
    assert.equal(response.payload.error, 'gateway-host-unauthorized');
    assert.ok(
      warnings.some((entry) => entry.some((value) => (
        typeof value === 'string' && value.includes('WoT evaluation failed')
      )) || entry.some((value) => (
        value && typeof value === 'object' && value.error === 'Timeout fetching contact lists for 1 authors'
      ))),
      'expected WoT timeout warning to be logged'
    );
  } finally {
    await service.stop();
  }
});
