import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import HypercoreId from 'hypercore-id-encoding';

import BlindPeerService, { deriveMirrorIdentifier } from '../src/blind-peer/BlindPeerService.mjs';
import PublicGatewayService from '../src/PublicGatewayService.mjs';

test('BlindPeerService canonicalizes trusted peer keys from buffers', () => {
  const service = new BlindPeerService({ config: { enabled: true } });
  const rawKey = randomBytes(32);

  const added = service.addTrustedPeer(rawKey);
  assert.equal(added, true);

  const canonical = HypercoreId.encode(rawKey);
  assert.equal(service.getTrustedPeers().length, 1);
  assert.equal(service.getTrustedPeers()[0].key, canonical);
  assert.equal(service.isTrustedPeer(rawKey), true);
  assert.equal(service.isTrustedPeer(canonical), true);
});

test('deriveMirrorIdentifier only treats the wakeup root as the primary identifier', () => {
  const wakeupKey = randomBytes(32);
  const systemKey = randomBytes(32);

  const wakeupId = HypercoreId.encode(wakeupKey);
  const systemId = HypercoreId.encode(systemKey);

  assert.equal(
    deriveMirrorIdentifier({ key: wakeupKey, referrer: wakeupKey }),
    wakeupId
  );
  assert.equal(
    deriveMirrorIdentifier({ key: systemKey, referrer: wakeupKey }),
    null
  );
  assert.equal(
    deriveMirrorIdentifier({ key: systemId, referrer: wakeupId }),
    null
  );
});

test('PublicGatewayService forwards raw peer keys to blind peer service', async () => {
  const rawPeerKey = randomBytes(32);
  const peerHex = rawPeerKey.toString('hex');

  const registrationStore = {
    getRelay: async () => null,
    upsertRelay: async () => {},
    items: new Map()
  };

  const noop = () => {};
  const logger = {
    info: noop,
    warn: noop,
    error: noop,
    debug: noop,
    child: () => logger
  };

  const service = new PublicGatewayService({
    config: {
      host: '127.0.0.1',
      port: 0,
      publicBaseUrl: 'https://example.com',
      metrics: { enabled: false, path: '/metrics' },
      registration: { sharedSecret: null, cacheTtlSeconds: 60 },
      discovery: { enabled: false, openAccess: false },
      relay: {},
      features: {},
      dispatcher: {},
      blindPeer: { enabled: false }
    },
    logger,
    registrationStore
  });

  const blindPeerService = new BlindPeerService({ config: { enabled: true } });
  const addedPeers = [];
  const removedPeers = [];
  const originalAdd = blindPeerService.addTrustedPeer.bind(blindPeerService);
  const originalRemove = blindPeerService.removeTrustedPeer.bind(blindPeerService);

  blindPeerService.addTrustedPeer = (value) => {
    addedPeers.push(value);
    return originalAdd(value);
  };

  blindPeerService.removeTrustedPeer = (value) => {
    removedPeers.push(value);
    return originalRemove(value);
  };

  service.blindPeerService = blindPeerService;

  const onProtocol = service.connectionPool.options.onProtocol;
  let registrationHandler = null;
  const cleanupHandlers = [];
  const protocol = {
    handle: (path, handler) => {
      if (path === '/gateway/register') {
        registrationHandler = handler;
      }
    },
    once: (_event, handler) => {
      cleanupHandlers.push(handler);
    }
  };

  onProtocol({
    publicKey: peerHex,
    protocol,
    context: {
      peerInfo: { publicKey: rawPeerKey }
    }
  });

  assert.equal(typeof registrationHandler, 'function');

  const response = await registrationHandler({
    method: 'POST',
    body: Buffer.from(JSON.stringify({
      publicKey: peerHex,
      relays: []
    }))
  });

  assert.equal(response.statusCode, 200);
  assert.equal(addedPeers.length, 1);
  assert.equal(Buffer.isBuffer(addedPeers[0]), true);
  assert.equal(addedPeers[0].toString('hex'), rawPeerKey.toString('hex'));

  const status = blindPeerService.getStatus();
  assert.equal(status.trustedPeerCount, 1);

  for (const handler of cleanupHandlers) {
    handler?.();
  }

  assert.equal(removedPeers.length, 0);
  const postCleanupStatus = blindPeerService.getStatus();
  assert.equal(postCleanupStatus.trustedPeerCount, 1);
});

test('BlindPeerService waits for a lease-critical core proof after nudging hydration', async () => {
  const service = new BlindPeerService({ config: { enabled: true } });
  const coreKey = randomBytes(32);
  const discoveryKey = randomBytes(32);
  let currentLength = 0;
  let announceCalls = 0;

  const trackerRecord = {
    key: coreKey,
    length: currentLength,
    updated: Date.now(),
    active: Date.now(),
    blocksCleared: 0,
    referrer: coreKey
  };

  const tracker = {
    record: trackerRecord,
    refresh: async () => {},
    announceToReferrer: () => {
      announceCalls += 1;
      currentLength = 32;
      trackerRecord.length = currentLength;
      trackerRecord.updated = Date.now();
      trackerRecord.active = Date.now();
    }
  };

  const core = {
    discoveryKey,
    length: currentLength,
    contiguousLength: currentLength,
    byteLength: 0,
    ready: async () => {},
    download: () => {
      core.length = currentLength;
      core.contiguousLength = currentLength;
      core.byteLength = currentLength * 10;
    }
  };

  service.blindPeer = {
    db: {
      getCoreRecord: async () => ({
        key: coreKey,
        length: currentLength,
        updated: Date.now(),
        active: Date.now(),
        blocksCleared: 0,
        referrer: coreKey
      })
    },
    store: {
      get: () => core
    },
    activeReplication: new Map([
      [Buffer.from(discoveryKey).toString('hex'), tracker]
    ])
  };

  const proof = await service.waitForCoreFastForwardProof(coreKey, {
    minSignedLength: 16,
    timeoutMs: 250,
    pollIntervalMs: 10,
    nudgeIntervalMs: 0
  });

  assert.ok(announceCalls >= 1);
  assert.ok(proof);
  assert.equal(proof.proofAuthoritative, true);
  assert.equal(proof.signedLength, 32);
});
