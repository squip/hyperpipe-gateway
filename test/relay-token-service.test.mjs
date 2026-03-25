import test from 'node:test';
import assert from 'node:assert/strict';

import RelayTokenService from '../src/relay/RelayTokenService.mjs';
import MemoryRegistrationStore from '../src/stores/MemoryRegistrationStore.mjs';

const SHARED_SECRET = 'token-service-secret';

async function createService() {
  const store = new MemoryRegistrationStore(10);
  await store.upsertRelay('relay:test', { relayKey: 'relay:test' });
  const service = new RelayTokenService({
    registrationStore: store,
    sharedSecret: SHARED_SECRET,
    defaultTtlSeconds: 60,
    refreshWindowSeconds: 10,
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} }
  });
  return { service, store };
}

test('RelayTokenService issues and verifies token metadata', async () => {
  const { service, store } = await createService();
  const issued = await service.issueToken('relay:test', {
    relayAuthToken: 'auth-token-1',
    scope: 'relay-access',
    pubkey: 'peer-pubkey'
  });

  assert.ok(issued.token);
  assert.equal(typeof issued.expiresAt, 'number');
  assert.equal(issued.sequence, 1);

  const state = await store.getTokenMetadata('relay:test');
  assert.equal(state.sequence, 1);
  assert.equal(state.scope, 'relay-access');
  assert.equal(state.pubkey, 'peer-pubkey');

  const verification = await service.verifyToken(issued.token, 'relay:test');
  assert.equal(verification.payload.sequence, 1);
  assert.equal(verification.payload.scope, 'relay-access');
});

test('RelayTokenService refreshes and revokes tokens', async () => {
  const { service } = await createService();
  const first = await service.issueToken('relay:test', { relayAuthToken: 'auth-token', scope: 'relay-access' });
  const refreshed = await service.refreshToken('relay:test', { token: first.token });
  assert.equal(refreshed.sequence, 2);
  assert.notEqual(refreshed.token, first.token);

  await service.verifyToken(refreshed.token, 'relay:test');

  const revokeResult = await service.revokeToken('relay:test');
  assert.equal(typeof revokeResult.sequence, 'number');

  await assert.rejects(() => service.verifyToken(refreshed.token, 'relay:test'), /token-revoked|token-mismatch|token-stale/);
});
