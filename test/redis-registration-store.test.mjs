import test from 'node:test';
import assert from 'node:assert/strict';

import RedisRegistrationStore from '../src/stores/RedisRegistrationStore.mjs';

function createStoreWithClient(fakeClient) {
  const store = new RedisRegistrationStore({
    url: 'redis://127.0.0.1:6379'
  });
  store.client = fakeClient;
  return store;
}

test('redis registration store handles numeric scan cursors for relay member ACL listing', async () => {
  const scanCalls = [];
  const store = createStoreWithClient({
    isReady: true,
    scan: async (cursor, options) => {
      scanCalls.push({ cursor, options });
      if (scanCalls.length === 1) {
        return {
          cursor: 13,
          keys: []
        };
      }
      return {
        cursor: 0,
        keys: ['gateway:registrations:member-acl:relay-alpha:member-one']
      };
    },
    mGet: async (keys) => keys.map((key) => JSON.stringify({
      relayKey: 'relay-alpha',
      subjectPubkey: key.split(':').at(-1)
    })),
    on: () => {}
  });

  const rows = await store.listRelayMemberAcls('relay-alpha');
  assert.equal(scanCalls.length, 2);
  assert.deepEqual(scanCalls.map((call) => call.cursor), ['0', '13']);
  assert.deepEqual(rows, [{
    relayKey: 'relay-alpha',
    subjectPubkey: 'member-one'
  }]);
});

test('redis registration store handles numeric scan cursors for host approval listing and relay listing', async () => {
  let hostScanCalls = 0;
  const store = createStoreWithClient({
    isReady: true,
    scan: async (cursor, options) => {
      if (String(options?.MATCH || '').includes('host-approvals')) {
        hostScanCalls += 1;
        if (hostScanCalls === 1) {
          return {
            cursor: 9,
            keys: ['gateway:registrations:host-approvals:gateway-a:member-a']
          };
        }
        return {
          cursor: 0,
          keys: []
        };
      }
      return {
        cursor: 0,
        keys: ['gateway:registrations:relay-z']
      };
    },
    mGet: async (keys) => keys.map((key) => {
      if (key.includes('host-approvals')) {
        return JSON.stringify({
          gatewayId: 'gateway-a',
          subjectPubkey: 'member-a'
        });
      }
      return JSON.stringify({
        publicIdentifier: 'relay-z'
      });
    }),
    on: () => {}
  });

  const approvals = await store.listHostApprovals('gateway-a');
  assert.equal(hostScanCalls, 2);
  assert.deepEqual(approvals, [{
    gatewayId: 'gateway-a',
    subjectPubkey: 'member-a'
  }]);

  const relays = await store.listRelays();
  assert.deepEqual(relays, [{
    relayKey: 'relay-z',
    record: {
      publicIdentifier: 'relay-z'
    }
  }]);
});
