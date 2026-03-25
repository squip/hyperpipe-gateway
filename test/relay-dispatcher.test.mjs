import test from 'node:test';
import assert from 'node:assert/strict';

import RelayDispatcherService from '../src/relay/RelayDispatcherService.mjs';

test('RelayDispatcherService assigns peers with available capacity', () => {
  const dispatcher = new RelayDispatcherService({ policy: { maxConcurrentJobsPerPeer: 2 } });
  dispatcher.reportPeerMetrics('peer-a', { peerId: 'peer-a', latencyMs: 10, inFlightJobs: 0, failureRate: 0, reportedAt: Date.now() });
  dispatcher.reportPeerMetrics('peer-b', { peerId: 'peer-b', latencyMs: 50, inFlightJobs: 0, failureRate: 0, reportedAt: Date.now() });

  const decision = dispatcher.schedule({ id: 'job-1', peers: ['peer-a', 'peer-b'] });
  assert.equal(decision.status, 'assigned');
  assert.equal(decision.assignedPeer, 'peer-a');
});

test('RelayDispatcherService triggers circuit breaker on repeated failures', () => {
  const dispatcher = new RelayDispatcherService({ policy: { maxConcurrentJobsPerPeer: 1, circuitBreakerThreshold: 2, circuitBreakerDurationMs: 1000 } });
  dispatcher.reportPeerMetrics('peer-a', { peerId: 'peer-a', latencyMs: 10, inFlightJobs: 0, failureRate: 0, reportedAt: Date.now() });
  dispatcher.reportPeerMetrics('peer-b', { peerId: 'peer-b', latencyMs: 20, inFlightJobs: 0, failureRate: 0, reportedAt: Date.now() });

  const first = dispatcher.schedule({ id: 'job-a', peers: ['peer-a', 'peer-b'] });
  dispatcher.fail('job-a', { error: 'timeout' });

  const second = dispatcher.schedule({ id: 'job-b', peers: ['peer-a', 'peer-b'] });
  dispatcher.fail('job-b', { error: 'timeout' });

  const third = dispatcher.schedule({ id: 'job-c', peers: ['peer-a', 'peer-b'] });
  assert.equal(third.assignedPeer, 'peer-b');
});
