import test from 'node:test';
import assert from 'node:assert/strict';

import PublicGatewayService from '../src/PublicGatewayService.mjs';
import MemoryRegistrationStore from '../src/stores/MemoryRegistrationStore.mjs';
import { createSignature } from '@squip/hyperpipe-bridge/auth/PublicGatewayTokens';

function createLogger() {
  const noop = () => {};
  const logger = {
    info: noop,
    warn: noop,
    error: noop,
    debug: noop,
    child() {
      return logger;
    }
  };
  return logger;
}

async function createService({
  peerFreshnessMs = 60_000
} = {}) {
  const registrationStore = new MemoryRegistrationStore({
    ttlSeconds: 60,
    relayTtlSeconds: 60,
    aliasTtlSeconds: 60
  });
  const service = new PublicGatewayService({
    config: {
      host: '127.0.0.1',
      port: 0,
      publicBaseUrl: 'http://127.0.0.1',
      metrics: { enabled: false, path: '/metrics' },
      registration: {
        sharedSecret: 'test-shared-secret',
        cacheTtlSeconds: 60
      },
      discovery: { enabled: false, openAccess: false, nostrRelayUrls: [] },
      relay: {},
      features: {
        hyperbeeRelayEnabled: false,
        dispatcherEnabled: false,
        tokenEnforcementEnabled: false
      },
      dispatcher: {},
      blindPeer: { enabled: false },
      presence: {
        peerFreshnessMs
      }
    },
    logger: createLogger(),
    registrationStore
  });
  await service.init();
  await service.start();
  const address = service.server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  return {
    service,
    registrationStore,
    baseUrl: `http://127.0.0.1:${port}`
  };
}

test('relay presence excludes stale registrations and counts only verified usable peers', async () => {
  const { service, registrationStore, baseUrl } = await createService({
    peerFreshnessMs: 5_000
  });

  try {
    const relayKey = 'a'.repeat(64);
    const publicIdentifier = 'npub1presence:test-group';
    const now = Date.now();
    await registrationStore.upsertRelay(relayKey, {
      relayKey,
      peers: ['peer-live', 'peer-stale', 'peer-unreachable'],
      metadata: {
        identifier: publicIdentifier,
        directJoinOnly: false
      }
    });
    await registrationStore.storeRelayAlias(publicIdentifier, relayKey);

    service.peerMetadata.set('peer-live', {
      relays: new Set([relayKey]),
      lastHealthyAt: now - 500,
      lastSeen: now - 500,
      lastRegistrationAt: now - 500,
      lastHandshakeAt: now - 500
    });
    service.peerMetadata.set('peer-stale', {
      relays: new Set(),
      lastHealthyAt: now - 20_000,
      lastSeen: now - 20_000,
      lastRegistrationAt: now - 20_000,
      lastHandshakeAt: now - 20_000
    });
    service.peerMetadata.set('peer-unreachable', {
      relays: new Set([relayKey]),
      lastHealthyAt: now - 500,
      lastSeen: now - 500,
      lastRegistrationAt: now - 500,
      lastHandshakeAt: now - 500,
      unreachableSince: now - 250
    });

    const response = await fetch(
      `${baseUrl}/api/relays/${encodeURIComponent(publicIdentifier)}/presence`
    );
    assert.equal(response.status, 200);
    const payload = await response.json();

    assert.equal(payload.relayKey, relayKey);
    assert.equal(payload.publicIdentifier, publicIdentifier);
    assert.equal(payload.usablePeerCount, 1);
    assert.equal(payload.aggregatePeerCount, 2);
    assert.equal(payload.gatewayIncluded, true);
    assert.equal(payload.gatewayHealthy, true);
    assert.equal(payload.registeredPeerCount, 3);
    assert.equal(payload.staleRegisteredPeerCount, 2);
    assert.equal(payload.source, 'gateway');
    assert.equal(typeof payload.verifiedAt, 'number');
  } finally {
    await service.stop();
  }
});

test('relay presence does not include the gateway for direct-join-only groups', async () => {
  const { service, registrationStore, baseUrl } = await createService({
    peerFreshnessMs: 5_000
  });

  try {
    const relayKey = 'b'.repeat(64);
    const now = Date.now();
    await registrationStore.upsertRelay(relayKey, {
      relayKey,
      peers: ['peer-direct'],
      metadata: {
        identifier: 'npub1presence:direct-only',
        directJoinOnly: true
      }
    });

    service.peerMetadata.set('peer-direct', {
      relays: new Set([relayKey]),
      lastHealthyAt: now - 250,
      lastSeen: now - 250
    });

    const response = await fetch(`${baseUrl}/api/relays/${relayKey}/presence`);
    assert.equal(response.status, 200);
    const payload = await response.json();

    assert.equal(payload.usablePeerCount, 1);
    assert.equal(payload.aggregatePeerCount, 1);
    assert.equal(payload.gatewayIncluded, false);
    assert.equal(payload.gatewayHealthy, false);
  } finally {
    await service.stop();
  }
});

test('relay registration refresh preserves existing relay peers for presence resolution', async () => {
  const { service, registrationStore, baseUrl } = await createService({
    peerFreshnessMs: 5_000
  });

  try {
    const relayKey = 'c'.repeat(64);
    const publicIdentifier = 'npub1presence:refresh-preserve';
    const now = Date.now();
    await registrationStore.upsertRelay(relayKey, {
      relayKey,
      peers: ['peer-refresh'],
      metadata: {
        identifier: publicIdentifier,
        directJoinOnly: false,
        peerStates: {
          'peer-refresh': {
            lastSeen: now - 250,
            lastHealthyAt: now - 250,
            unreachableSince: null
          }
        }
      },
      registeredAt: now - 1_000
    });

    service.peerMetadata.set('peer-refresh', {
      relays: new Set([relayKey]),
      lastHealthyAt: now - 250,
      lastSeen: now - 250,
      lastRegistrationAt: now - 250,
      lastHandshakeAt: now - 250
    });

    const registration = {
      relayKey,
      metadata: {
        identifier: publicIdentifier,
        directJoinOnly: false,
        name: 'Refresh Preserve'
      }
    };
    const signature = createSignature(registration, 'test-shared-secret');
    const registerResponse = await fetch(`${baseUrl}/api/relays`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        registration,
        signature
      })
    });
    assert.equal(registerResponse.status, 200);

    const stored = await registrationStore.getRelay(relayKey);
    assert.deepEqual(stored?.peers, ['peer-refresh']);
    assert.ok(stored?.metadata?.peerStates?.['peer-refresh']);

    const presenceResponse = await fetch(`${baseUrl}/api/relays/${relayKey}/presence`);
    assert.equal(presenceResponse.status, 200);
    const payload = await presenceResponse.json();

    assert.equal(payload.usablePeerCount, 1);
    assert.equal(payload.aggregatePeerCount, 2);
    assert.equal(payload.gatewayIncluded, true);
    assert.equal(payload.registeredPeerCount, 1);
  } finally {
    await service.stop();
  }
});
