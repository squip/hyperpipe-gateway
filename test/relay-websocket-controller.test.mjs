import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import WebSocket from 'ws';

import RelayWebsocketController from '../src/relay/RelayWebsocketController.mjs';

class MockRelayHost {
  constructor() {
    this.events = [];
  }

  async applyEvent(event) {
    this.events.push(event);
    return { id: event.id, status: 'accepted' };
  }
}

class MockWebSocket extends EventEmitter {
  constructor() {
    super();
    this.sent = [];
    this.readyState = WebSocket.OPEN;
  }

  send(message) {
    this.sent.push(message);
  }
}

test('RelayWebsocketController handles EVENT frames', async () => {
  const host = new MockRelayHost();
  const controller = new RelayWebsocketController({
    relayHost: host,
    logger: console,
    legacyForward: async () => {}
  });

  const ws = new MockWebSocket();
  const session = {
    ws,
    connectionKey: 'conn-1',
    relayKey: 'relay-1',
    peers: ['peer-a'],
    messageQueue: { enqueue: async (_payload, handler) => { await handler(_payload); } }
  };

  await controller.handleMessage(session, JSON.stringify(['EVENT', { id: 'abc', kind: 1 }]));

  assert.equal(host.events.length, 1);
  assert.equal(host.events[0].id, 'abc');
  assert.ok(ws.sent.some((msg) => msg.includes('"OK"')));
});

test('RelayWebsocketController falls back to legacy for unknown frames', async () => {
  const host = new MockRelayHost();
  let forwarded = false;
  const controller = new RelayWebsocketController({
    relayHost: host,
    logger: console,
    legacyForward: async () => { forwarded = true; }
  });

  const ws = new MockWebSocket();
  const session = {
    ws,
    connectionKey: 'conn-2',
    relayKey: 'relay-2',
    peers: ['peer-a'],
    messageQueue: { enqueue: async (_payload, handler) => { await handler(_payload); } }
  };

  const handled = await controller.handleMessage(session, JSON.stringify(['COMMAND', 'unknown']));
  assert.equal(handled, false);
  assert.equal(forwarded, false);
});

test('RelayWebsocketController forwards REQ when dispatcher disabled', async () => {
  const host = new MockRelayHost();
  let forwardCount = 0;
  const controller = new RelayWebsocketController({
    relayHost: host,
    logger: console,
    legacyForward: async () => { forwardCount += 1; }
  });

  const ws = new MockWebSocket();
  const session = {
    ws,
    connectionKey: 'conn-3',
    relayKey: 'relay-3',
    peers: ['peer-a'],
    messageQueue: { enqueue: async (_payload, handler) => { await handler(_payload); } }
  };

  await controller.handleMessage(session, JSON.stringify(['REQ', 'sub1', { kinds: [1] }]));
  assert.equal(forwardCount, 1);
});

test('RelayWebsocketController schedules REQ when dispatcher enabled', async () => {
  const host = new MockRelayHost();
  let scheduledJob = null;
  const dispatcher = {
    schedule: async (job) => {
      scheduledJob = job;
      return { status: 'assigned', assignedPeer: 'peer-a' };
    },
    acknowledge: () => {},
    fail: () => {}
  };

  const controller = new RelayWebsocketController({
    relayHost: host,
    dispatcher,
    featureFlags: { dispatcherEnabled: true },
    logger: console,
    legacyForward: async (_session, _msg, peer) => { if (peer) assignments.push(peer); }
  });

  const ws = new MockWebSocket();
  const assignments = [];
  const session = {
    ws,
    connectionKey: 'conn-4',
    relayKey: 'relay-4',
    clientPubkey: 'peer123',
    peers: ['peer-a', 'peer-b'],
    assignPeer: (peer) => assignments.push(`assign:${peer}`),
    messageQueue: { enqueue: async (_payload, handler) => { await handler(_payload); } }
  };

  await controller.handleMessage(session, JSON.stringify(['REQ', 'sub2', { kinds: [1] }]));
  assert.ok(scheduledJob);
  assert.equal(scheduledJob.id, 'sub2');
  assert.equal(scheduledJob.requester.peerId, 'peer123');
  assert.equal(assignments.length, 2);
  assert.ok(assignments.includes('assign:peer-a'));
  assert.ok(assignments.includes('peer-a'));
});
