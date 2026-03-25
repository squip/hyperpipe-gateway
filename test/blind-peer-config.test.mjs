import test from 'node:test';
import assert from 'node:assert/strict';

import { loadConfig } from '../src/config.mjs';

test('blind peer defaults disabled with sane limits', () => {
  const config = loadConfig();
  assert.equal(config.blindPeer.enabled, false);
  assert.equal(config.blindPeer.storageDir, null);
  assert.equal(config.blindPeer.maxBytes, 25 * 1024 ** 3);
  assert.equal(config.blindPeer.dedupeBatchSize, 100);
});

test('blind peer overrides are normalised', () => {
  const config = loadConfig({
    registration: {
      relayGcAfterMs: 0
    },
    blindPeer: {
      enabled: true,
      storageDir: '/tmp/blind-peer',
      maxBytes: 1024,
      gcIntervalMs: 10_000,
      dedupeBatchSize: 50,
      staleCoreTtlMs: 5_000,
      trustedPeersPersistPath: '/tmp/trusted.json'
    }
  });

  assert.equal(config.blindPeer.enabled, true);
  assert.equal(config.blindPeer.storageDir, '/tmp/blind-peer');
  assert.equal(config.blindPeer.maxBytes, 1024);
  assert.equal(config.blindPeer.gcIntervalMs, 10_000);
  assert.equal(config.blindPeer.dedupeBatchSize, 50);
  assert.equal(config.blindPeer.staleCoreTtlMs, 5_000);
  assert.equal(config.blindPeer.trustedPeersPersistPath, '/tmp/trusted.json');
});

test('blind peer negative values fall back to defaults', () => {
  const config = loadConfig({
    registration: {
      relayGcAfterMs: 0
    },
    blindPeer: {
      enabled: true,
      maxBytes: -5,
      gcIntervalMs: -1,
      dedupeBatchSize: -1,
      staleCoreTtlMs: -1
    }
  });

  assert.equal(config.blindPeer.enabled, true);
  assert.equal(config.blindPeer.maxBytes, 25 * 1024 ** 3);
  assert.equal(config.blindPeer.gcIntervalMs, 300000);
  assert.equal(config.blindPeer.dedupeBatchSize, 100);
  assert.equal(config.blindPeer.staleCoreTtlMs, 7 * 24 * 60 * 60 * 1000);
});
