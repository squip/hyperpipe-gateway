import test from 'node:test';
import assert from 'node:assert/strict';

import RelayDispatcherService from '../src/relay/RelayDispatcherService.mjs';

test('RelayDispatcherService emits assignment and settlement events', async () => {
  const dispatcher = new RelayDispatcherService({ policy: { maxConcurrentJobsPerPeer: 1 } });
  const events = [];
  dispatcher.on('assignment', (evt) => events.push({ type: 'assignment', evt }));
  dispatcher.on('acknowledge', (evt) => events.push({ type: 'ack', evt }));
  dispatcher.on('failure', (evt) => events.push({ type: 'fail', evt }));

  const decision = dispatcher.schedule({
    id: 'job-1',
    peers: ['peerA'],
    relayKey: 'relay-abc',
    filters: [{ kinds: [1] }],
    requester: { relayKey: 'relay-abc', peerId: 'clientX' }
  });

  assert.equal(decision.status, 'assigned');
  assert.equal(events.length, 1);
  assert.equal(events[0].type, 'assignment');
  assert.equal(events[0].evt.jobId, 'job-1');
  assert.equal(events[0].evt.peerId, 'peerA');
  assert.equal(events[0].evt.job.relayKey, 'relay-abc');

  dispatcher.acknowledge('job-1', { deliveredCount: 3 });
  assert.equal(events.length, 2);
  assert.equal(events[1].type, 'ack');
  assert.equal(events[1].evt.jobId, 'job-1');
  assert.equal(events[1].evt.peerId, 'peerA');

  dispatcher.fail('unknown', { reason: 'noop' });
  assert.equal(events.length, 2, 'unexpected failure event for unknown job');
});
