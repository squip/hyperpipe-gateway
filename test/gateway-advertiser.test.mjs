import assert from 'node:assert/strict';
import test from 'node:test';

import { WebSocketServer } from 'ws';

import { publishNostrEventToRelay } from '../src/discovery/GatewayAdvertiser.mjs';

test('publishNostrEventToRelay returns false when relay closes without OK', async () => {
  const wss = new WebSocketServer({ port: 0 });
  const relayUrl = `ws://127.0.0.1:${wss.address().port}`;

  wss.on('connection', (socket) => {
    socket.once('message', () => {
      socket.close();
    });
  });

  try {
    const ok = await publishNostrEventToRelay(relayUrl, { id: 'event-without-ack' });
    assert.equal(ok, false);
  } finally {
    await new Promise((resolve, reject) => {
      wss.close((error) => {
        if (error) reject(error);
        else resolve();
      });
    });
  }
});

test('publishNostrEventToRelay returns true only after OK true', async () => {
  const wss = new WebSocketServer({ port: 0 });
  const relayUrl = `ws://127.0.0.1:${wss.address().port}`;

  wss.on('connection', (socket) => {
    socket.once('message', (raw) => {
      const message = JSON.parse(String(raw));
      socket.send(JSON.stringify(['OK', message[1].id, true, 'stored']));
      socket.close();
    });
  });

  try {
    const ok = await publishNostrEventToRelay(relayUrl, { id: 'event-with-ack' });
    assert.equal(ok, true);
  } finally {
    await new Promise((resolve, reject) => {
      wss.close((error) => {
        if (error) reject(error);
        else resolve();
      });
    });
  }
});
