import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import crypto from 'hypercore-crypto';

import HyperbeeRelayHost from '../src/relay/HyperbeeRelayHost.mjs';

const NOOP_LOGGER = {
  info: () => {},
  warn: () => {},
  error: () => {},
  debug: () => {}
};

function bufferToHex(buffer) {
  return Buffer.isBuffer(buffer) ? buffer.toString('hex') : buffer;
}

test('HyperbeeRelayHost lifecycle emits telemetry and persists events', async (t) => {
  const tmpDir = await mkdtemp(join(tmpdir(), 'hyperbee-relay-host-'));
  const keyPair = crypto.keyPair();
  const host = new HyperbeeRelayHost({ telemetryIntervalMs: 25, logger: NOOP_LOGGER });
  const telemetry = [];
  const unsubscribe = host.registerTelemetrySink((event) => telemetry.push(event));

  await host.initialize({
    storageDir: tmpDir,
    adminKeyPair: {
      publicKey: bufferToHex(keyPair.publicKey),
      secretKey: bufferToHex(keyPair.secretKey)
    },
    statsIntervalMs: 25
  });

  await host.start();

  const nostrEvent = {
    id: bufferToHex(crypto.randomBytes(32)),
    kind: 1,
    pubkey: bufferToHex(crypto.randomBytes(32)),
    created_at: Math.floor(Date.now() / 1000),
    tags: [],
    content: 'hello public gateway',
    sig: bufferToHex(crypto.randomBytes(64))
  };

  const result = await host.applyEvent(nostrEvent);
  assert.equal(result.status, 'accepted');
  assert.equal(result.id, nostrEvent.id);

  // wait for telemetry loop
  await new Promise((resolve) => setTimeout(resolve, 75));

  assert.ok(telemetry.some((event) => event.type === 'hyperbee-append'), 'append telemetry should be emitted');
  assert.ok(telemetry.some((event) => event.type === 'replication'), 'stats telemetry should be emitted');

  await host.stop();
  unsubscribe();
  await rm(tmpDir, { recursive: true, force: true });
});

test('HyperbeeRelayHost rejects events when not started', async () => {
  const tmpDir = await mkdtemp(join(tmpdir(), 'hyperbee-relay-host-'));
  const keyPair = crypto.keyPair();
  const host = new HyperbeeRelayHost({ telemetryIntervalMs: 25, logger: NOOP_LOGGER });

  await host.initialize({
    storageDir: tmpDir,
    adminKeyPair: {
      publicKey: bufferToHex(keyPair.publicKey),
      secretKey: bufferToHex(keyPair.secretKey)
    }
  });

  const nostrEvent = {
    id: bufferToHex(crypto.randomBytes(32)),
    kind: 1,
    pubkey: bufferToHex(crypto.randomBytes(32)),
    created_at: Math.floor(Date.now() / 1000),
    tags: [],
    content: 'not started',
    sig: bufferToHex(crypto.randomBytes(64))
  };

  const result = await host.applyEvent(nostrEvent);
  assert.equal(result.status, 'rejected');
  assert.equal(result.reason, 'host-not-writable');

  await host.stop();
  await rm(tmpDir, { recursive: true, force: true });
});
