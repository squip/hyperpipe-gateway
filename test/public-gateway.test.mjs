import test from 'node:test';
import assert from 'node:assert/strict';

import {
  issueClientToken,
  verifyClientToken,
  createSignature,
  verifySignature
} from '../../shared/auth/PublicGatewayTokens.mjs';
import MemoryRegistrationStore from '../src/stores/MemoryRegistrationStore.mjs';

const SECRET = 'test-secret-key';

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test('client token round trip', () => {
  const payload = {
    relayKey: 'relay:alpha',
    scope: 'test',
    relayAuthToken: 'auth-token-123'
  };
  const token = issueClientToken(payload, SECRET);
  assert.ok(typeof token === 'string' && token.includes('.'));
  const decoded = verifyClientToken(token, SECRET);
  assert.ok(decoded, 'token should validate');
  assert.equal(decoded.relayKey, payload.relayKey);
  assert.equal(decoded.scope, payload.scope);
  assert.equal(decoded.relayAuthToken, payload.relayAuthToken);
  assert.ok(decoded.issuedAt);
});

test('signature helpers are symmetric', () => {
  const payload = { relayKey: 'relay:beta', peers: ['peerA'] };
  const signature = createSignature(payload, SECRET);
  assert.ok(signature && signature.length > 0);
  assert.equal(verifySignature(payload, signature, SECRET), true);
  assert.equal(verifySignature(payload, signature.slice(2) + '00', SECRET), false);
});

test('memory registration store respects TTL', async () => {
  const store = new MemoryRegistrationStore(1);
  await store.upsertRelay('relay:test', { relayKey: 'relay:test' });
  const initial = await store.getRelay('relay:test');
  assert.ok(initial);
  await delay(1100);
  const expired = await store.getRelay('relay:test');
  assert.equal(expired, null);
});

test('memory registration store captures token metadata', async () => {
  const store = new MemoryRegistrationStore(5);
  const expiresAt = Date.now() + 5000;
  await store.storeTokenMetadata('relay:meta', {
    pubkey: 'pubkey123',
    scope: 'relay-access',
    expiresAt
  });
  const metadata = await store.getTokenMetadata('relay:meta');
  assert.ok(metadata);
  assert.equal(metadata.pubkey, 'pubkey123');
  assert.equal(metadata.scope, 'relay-access');
  assert.equal(metadata.expiresAt, expiresAt);
});
