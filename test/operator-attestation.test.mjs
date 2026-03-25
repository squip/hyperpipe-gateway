import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { schnorr } from '@noble/curves/secp256k1';

import PublicGatewayService from '../src/PublicGatewayService.mjs';
import MemoryRegistrationStore from '../src/stores/MemoryRegistrationStore.mjs';
import { deriveKeyPair } from '../../shared/public-gateway/GatewayDiscovery.mjs';
import {
  createOperatorAttestationRequest,
  signOperatorAttestationRequest
} from '../../shared/public-gateway/OperatorAttestation.mjs';

const ACCOUNTS = {
  operator: {
    pubkeyHex: '75a3b6ac739a1c8e60edd5bbaa4b9486b1436b9cd23e5b739e22d0b0958724f8',
    secretHex: 'c5c0dee846de0bf4d8a9633b5d6ecab1efbcc138c713d4f8f2c9b70be455e8c9'
  },
  approved: {
    pubkeyHex: '5930023f28ea6f14e48812fe18eedaa8bac608068eb781617abfbd2a7e7aab1f',
    secretHex: '25682cebac193c4e4f1063beb9afca08b7390010b1cba240db0250f3a97c77ae'
  },
  denied: {
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

function createLogger() {
  const noop = () => {};
  const logger = {
    info: noop,
    error: noop,
    debug: noop,
    warn: noop,
    child() {
      return logger;
    }
  };
  return logger;
}

function gatewayIdFromSeed(seed) {
  return Buffer.from(deriveKeyPair(seed).publicKey).toString('hex');
}

function createConfig({ port, allowlistFile, discoveryKeySeed, operatorAttestationFile } = {}) {
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
    discovery: {
      enabled: false,
      openAccess: false,
      nostrRelayUrls: [],
      keySeed: discoveryKeySeed
    },
    auth: {
      hostPolicy: 'allowlist',
      authMethod: 'relay-scoped-bearer-v1',
      operatorPubkey: ACCOUNTS.operator.pubkeyHex,
      operatorAttestationFile,
      allowlistPubkeys: [ACCOUNTS.approved.pubkeyHex],
      allowlistFile,
      allowlistRefreshMs: 50,
      memberDelegationMode: 'all-members'
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
  const registrationStore = new MemoryRegistrationStore(60);
  const service = new PublicGatewayService({
    config: createConfig(options),
    logger: createLogger(),
    registrationStore
  });
  await service.init();
  await service.start();
  const address = service.server.address();
  const port = typeof address === 'object' && address ? address.port : options.port;
  return {
    service,
    baseUrl: `http://127.0.0.1:${port}`
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
  return { response, payload };
}

async function probeGatewayAuth(baseUrl, account, {
  scope = 'gateway:relay-register',
  relayKey = null
} = {}) {
  const challenge = await fetchJson(`${baseUrl}/api/auth/challenge`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      pubkey: account.pubkeyHex,
      scope,
      relayKey
    })
  });
  assert.equal(challenge.response.status, 200);
  const signatureBytes = await schnorr.sign(
    new TextEncoder().encode(challenge.payload.nonce),
    hexToBytes(account.secretHex)
  );
  return fetchJson(`${baseUrl}/api/auth/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      challengeId: challenge.payload.challengeId,
      pubkey: account.pubkeyHex,
      signature: Buffer.from(signatureBytes).toString('hex'),
      scope,
      relayKey
    })
  });
}

async function createTempFixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'gateway-attestation-'));
  t.after(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  return dir;
}

async function writeAttestationFile(filePath, {
  operatorPubkey = ACCOUNTS.operator.pubkeyHex,
  publicUrl,
  gatewayId,
  secretInput = ACCOUNTS.operator.secretHex,
  expiresAt = Date.now() + (365 * 24 * 60 * 60 * 1000)
} = {}) {
  const request = createOperatorAttestationRequest({
    operatorPubkey,
    gatewayId,
    publicUrl
  });
  const attestation = signOperatorAttestationRequest(request, {
    secretInput,
    issuedAt: Date.now(),
    expiresAt,
    schnorrImpl: schnorr
  });
  await writeFile(filePath, `${JSON.stringify(attestation, null, 2)}\n`, 'utf8');
  return attestation;
}

test('approved auth responses include verified operator identity when attestation is valid', async (t) => {
  const dir = await createTempFixture(t);
  const allowlistFile = join(dir, 'allowlist.json');
  const operatorAttestationFile = join(dir, 'operator-attestation.json');
  const discoveryKeySeed = 'operator-attestation-seed';
  const port = 45101;
  const gatewayId = gatewayIdFromSeed(discoveryKeySeed);
  const publicUrl = `http://127.0.0.1:${port}`;
  await writeFile(allowlistFile, JSON.stringify({
    version: 1,
    updatedAt: Date.now(),
    updatedBy: ACCOUNTS.operator.pubkeyHex,
    pubkeys: [ACCOUNTS.approved.pubkeyHex]
  }), 'utf8');
  await writeAttestationFile(operatorAttestationFile, {
    publicUrl,
    gatewayId
  });

  const { service, baseUrl } = await createService({
    port,
    allowlistFile,
    discoveryKeySeed,
    operatorAttestationFile
  });
  try {
    const auth = await probeGatewayAuth(baseUrl, ACCOUNTS.approved);
    assert.equal(auth.response.status, 200);
    assert.equal(auth.payload.operatorIdentity?.pubkey, ACCOUNTS.operator.pubkeyHex);
    assert.equal(auth.payload.operatorIdentity?.attestation?.payload?.gatewayId, gatewayId);
    assert.equal(auth.payload.operatorIdentity?.attestation?.payload?.publicUrl, publicUrl);
  } finally {
    await service.stop();
  }
});

test('denied auth responses never include operator identity', async (t) => {
  const dir = await createTempFixture(t);
  const allowlistFile = join(dir, 'allowlist.json');
  const operatorAttestationFile = join(dir, 'operator-attestation.json');
  const discoveryKeySeed = 'operator-attestation-seed-denied';
  const port = 45102;
  await writeFile(allowlistFile, JSON.stringify({
    version: 1,
    updatedAt: Date.now(),
    updatedBy: ACCOUNTS.operator.pubkeyHex,
    pubkeys: [ACCOUNTS.approved.pubkeyHex]
  }), 'utf8');
  await writeAttestationFile(operatorAttestationFile, {
    publicUrl: `http://127.0.0.1:${port}`,
    gatewayId: gatewayIdFromSeed(discoveryKeySeed)
  });

  const { service, baseUrl } = await createService({
    port,
    allowlistFile,
    discoveryKeySeed,
    operatorAttestationFile
  });
  try {
    const auth = await probeGatewayAuth(baseUrl, ACCOUNTS.denied);
    assert.equal(auth.response.status, 403);
    assert.equal('operatorIdentity' in auth.payload, false);
  } finally {
    await service.stop();
  }
});

test('invalid operator attestation is ignored while auth success remains intact', async (t) => {
  const dir = await createTempFixture(t);
  const allowlistFile = join(dir, 'allowlist.json');
  const operatorAttestationFile = join(dir, 'operator-attestation.json');
  const discoveryKeySeed = 'operator-attestation-seed-invalid';
  const port = 45103;
  await writeFile(allowlistFile, JSON.stringify({
    version: 1,
    updatedAt: Date.now(),
    updatedBy: ACCOUNTS.operator.pubkeyHex,
    pubkeys: [ACCOUNTS.approved.pubkeyHex]
  }), 'utf8');
  const attestation = await writeAttestationFile(operatorAttestationFile, {
    publicUrl: `http://127.0.0.1:${port}`,
    gatewayId: gatewayIdFromSeed(discoveryKeySeed)
  });
  attestation.signature = `${attestation.signature.slice(0, -2)}00`;
  await writeFile(operatorAttestationFile, `${JSON.stringify(attestation, null, 2)}\n`, 'utf8');

  const { service, baseUrl } = await createService({
    port,
    allowlistFile,
    discoveryKeySeed,
    operatorAttestationFile
  });
  try {
    const auth = await probeGatewayAuth(baseUrl, ACCOUNTS.approved);
    assert.equal(auth.response.status, 200);
    assert.equal(auth.payload.operatorIdentity || null, null);
  } finally {
    await service.stop();
  }
});
