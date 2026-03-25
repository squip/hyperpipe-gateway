import test from 'node:test';
import assert from 'node:assert/strict';

import BlindPeerService from '../src/blind-peer/BlindPeerService.mjs';

test('BlindPeerService tracks dispatcher assignments', async () => {
  const service = new BlindPeerService({ config: { enabled: false } });

  const entry = service.recordDispatcherAssignment({
    jobId: 'sub-1',
    peerKey: 'peerA',
    relayKey: 'relay:alpha',
    filters: [{ kinds: [1] }],
    requester: { peerId: 'clientZ' }
  });

  assert.equal(entry.jobId, 'sub-1');
  assert.equal(entry.peerKey, 'peerA');
  assert.equal(entry.relayKey, 'relay:alpha');
  assert.equal(entry.status, 'assigned');

  const snapshot = service.getDispatcherAssignmentsSnapshot();
  assert.equal(snapshot.length, 1);
  assert.equal(snapshot[0].jobId, 'sub-1');

  service.clearDispatcherAssignment('sub-1', { status: 'acknowledged' });
  const updated = service.getDispatcherAssignmentsSnapshot()[0];
  assert.equal(updated.status, 'acknowledged');
  assert.ok(updated.completedAt);
});
