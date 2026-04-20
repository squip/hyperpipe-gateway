import test from 'node:test';
import assert from 'node:assert/strict';

import { WebSocketAbuseGuard, resolveClientAddress } from '../src/websocket-abuse-guard.mjs';

function createLogger() {
  const warnings = [];
  return {
    warnings,
    warn(payload, message) {
      warnings.push({ payload, message });
    }
  };
}

test('resolveClientAddress prefers x-forwarded-for', () => {
  const address = resolveClientAddress({
    headers: {
      'x-forwarded-for': '198.51.100.10, 10.0.0.1'
    },
    socket: {
      remoteAddress: '10.0.0.2'
    }
  });
  assert.equal(address, '198.51.100.10');
});

test('resolveClientAddress prefers cloudflare and x-real-ip headers before forwarded-for', () => {
  const address = resolveClientAddress({
    headers: {
      'cf-connecting-ip': '203.0.113.12',
      'x-real-ip': '203.0.113.20',
      'x-forwarded-for': '198.51.100.10, 10.0.0.1'
    },
    socket: {
      remoteAddress: '10.0.0.2'
    }
  });
  assert.equal(address, '203.0.113.12');
});

test('WebSocketAbuseGuard caches missing relay lookups for a short ttl', () => {
  const guard = new WebSocketAbuseGuard({
    missingRelayTtlMs: 100
  });
  const now = 1_000;

  assert.equal(guard.shouldSkipMissingRelayLookup('relay:test', now), false);
  guard.rememberMissingRelay('relay:test', now);
  assert.equal(guard.shouldSkipMissingRelayLookup('relay:test', now + 50), true);
  assert.equal(guard.shouldSkipMissingRelayLookup('relay:test', now + 150), false);
});

test('WebSocketAbuseGuard blocks clients after repeated invalid attempts', () => {
  const guard = new WebSocketAbuseGuard({
    invalidThreshold: 3,
    invalidWindowMs: 1_000,
    blockDurationMs: 5_000
  });
  const logger = createLogger();
  const address = '203.0.113.9';

  guard.recordInvalidAttempt({
    logger,
    reason: 'relay-not-registered',
    clientAddress: address,
    relayKey: 'relay:a',
    now: 0
  });
  guard.recordInvalidAttempt({
    logger,
    reason: 'relay-not-registered',
    clientAddress: address,
    relayKey: 'relay:b',
    now: 100
  });
  const result = guard.recordInvalidAttempt({
    logger,
    reason: 'relay-not-registered',
    clientAddress: address,
    relayKey: 'relay:c',
    now: 200
  });

  assert.equal(result.blocked, true);
  assert.equal(result.blockedNow, true);
  assert.equal(guard.isClientBlocked(address, 300), true);
  assert.equal(guard.isClientBlocked(address, 5_500), false);
});

test('WebSocketAbuseGuard suppresses repetitive rejection logs within the sample window', () => {
  const guard = new WebSocketAbuseGuard({
    rejectionLogWindowMs: 100
  });
  const logger = createLogger();

  guard.logRejectedAttempt({
    logger,
    reason: 'relay-not-registered',
    clientAddress: '203.0.113.10',
    relayKey: 'relay:first',
    now: 0
  });
  guard.logRejectedAttempt({
    logger,
    reason: 'relay-not-registered',
    clientAddress: '203.0.113.10',
    relayKey: 'relay:second',
    now: 50
  });
  guard.logRejectedAttempt({
    logger,
    reason: 'relay-not-registered',
    clientAddress: '203.0.113.10',
    relayKey: 'relay:third',
    now: 125
  });

  assert.equal(logger.warnings.length, 2);
  assert.equal(logger.warnings[0].message, 'WebSocket rejected: relay not registered');
  assert.equal(logger.warnings[1].message, 'WebSocket rejected: relay not registered');
  assert.equal(logger.warnings[1].payload.suppressedCount, 1);
});
