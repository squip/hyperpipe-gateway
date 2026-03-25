import { EventEmitter } from 'node:events';

const DEFAULT_POLICY = {
  maxConcurrentJobsPerPeer: 3,
  maxFailureRate: 0.4,
  reassignOnLagBlocks: 500,
  circuitBreakerThreshold: 5,
  circuitBreakerDurationMs: 60_000,
  inFlightWeight: 25,
  latencyWeight: 1,
  failureWeight: 500
};

function now() {
  return Date.now();
}

export default class RelayDispatcherService {
  constructor({ logger = console, policy = {} } = {}) {
    this.logger = logger;
    this.policy = { ...DEFAULT_POLICY, ...policy };
    this.peerState = new Map();
    this.jobAssignments = new Map();
    this.events = new EventEmitter();
  }

  on(eventName, handler) {
    this.events.on(eventName, handler);
    return () => this.events.off(eventName, handler);
  }

  off(eventName, handler) {
    this.events.off(eventName, handler);
  }

  schedule(job = {}) {
    const { peers = [] } = job;
    if (!Array.isArray(peers) || peers.length === 0) {
      return { status: 'rejected', reason: 'no-peers' };
    }

    const candidates = [];
    const jobId = job.id || `job-${now()}`;
    for (const peerId of peers) {
      const state = this.#ensurePeerState(peerId);
      if (this.#isPeerCircuitBroken(state)) {
        continue;
      }
      if (state.inFlight >= this.policy.maxConcurrentJobsPerPeer) {
        continue;
      }
      candidates.push({ peerId, state });
    }

    if (!candidates.length) {
      return { status: 'rejected', reason: 'peers-saturated' };
    }

    const best = candidates.reduce((acc, candidate) => {
      const score = this.#scorePeer(candidate.state);
      if (!acc || score < acc.score) {
        return { peerId: candidate.peerId, score };
      }
      return acc;
    }, null);

    if (!best) {
      return { status: 'rejected', reason: 'no-candidate' };
    }

    const state = this.peerState.get(best.peerId);
    state.inFlight += 1;
    state.lastAssignedAt = now();
    this.jobAssignments.set(jobId, {
      peerId: best.peerId,
      assignedAt: state.lastAssignedAt,
      job
    });

    this.logger?.debug?.('[RelayDispatcher] Job scheduled', {
      jobId,
      peerId: best.peerId,
      score: best.score
    });

    this.events.emit('assignment', {
      jobId,
      peerId: best.peerId,
      assignedAt: state.lastAssignedAt,
      job
    });

    return {
      status: 'assigned',
      assignedPeer: best.peerId,
      jobId
    };
  }

  acknowledge(jobId, outcome = {}) {
    const assignment = this.jobAssignments.get(jobId);
    if (!assignment) return;

    const state = this.peerState.get(assignment.peerId);
    if (state) {
      state.inFlight = Math.max(0, state.inFlight - 1);
      state.lastSuccessAt = now();
      state.consecutiveFailures = 0;
      state.failureRate = this.#decayFailureRate(state.failureRate, false);
    }

    this.jobAssignments.delete(jobId);
    this.logger?.debug?.('[RelayDispatcher] Job acknowledged', {
      jobId,
      peerId: assignment.peerId,
      deliveredCount: outcome.deliveredCount || 0
    });

    this.events.emit('acknowledge', {
      jobId,
      peerId: assignment.peerId,
      outcome,
      job: assignment.job
    });
  }

  fail(jobId, reason = {}) {
    const assignment = this.jobAssignments.get(jobId);
    if (!assignment) return;
    const state = this.peerState.get(assignment.peerId);

    if (state) {
      state.inFlight = Math.max(0, state.inFlight - 1);
      state.consecutiveFailures += 1;
      state.failureRate = this.#decayFailureRate(state.failureRate, true);
      if (state.consecutiveFailures >= this.policy.circuitBreakerThreshold) {
        state.circuitBrokenUntil = now() + this.policy.circuitBreakerDurationMs;
        this.logger?.warn?.('[RelayDispatcher] Peer circuit broken', {
          peerId: assignment.peerId,
          reason: reason?.error || 'consecutive-failures'
        });
      }
    }

    this.jobAssignments.delete(jobId);
    this.events.emit('failure', {
      jobId,
      peerId: assignment?.peerId || null,
      reason,
      job: assignment?.job || null
    });
  }

  reportPeerMetrics(peerId, metrics = {}) {
    const state = this.#ensurePeerState(peerId);
    state.metrics = {
      latencyMs: metrics.latencyMs ?? state.metrics.latencyMs,
      inFlightJobs: metrics.inFlightJobs ?? state.metrics.inFlightJobs,
      failureRate: metrics.failureRate ?? state.metrics.failureRate,
      hyperbeeVersion: metrics.hyperbeeVersion ?? state.metrics.hyperbeeVersion,
      hyperbeeLag: metrics.hyperbeeLag ?? state.metrics.hyperbeeLag,
      queueDepth: metrics.queueDepth ?? state.metrics.queueDepth,
      reportedAt: metrics.reportedAt ?? now()
    };
    state.lastHeartbeatAt = state.metrics.reportedAt;

    if (state.circuitBrokenUntil && state.metrics.failureRate < this.policy.maxFailureRate) {
      state.circuitBrokenUntil = null;
      state.consecutiveFailures = 0;
      this.logger?.info?.('[RelayDispatcher] Peer circuit restored via heartbeat', { peerId });
    }
  }

  applyPolicyUpdate(policy = {}) {
    this.policy = { ...this.policy, ...policy };
  }

  shutdown() {
    this.peerState.clear();
    this.jobAssignments.clear();
    this.events.removeAllListeners();
  }

  #ensurePeerState(peerId) {
    if (!this.peerState.has(peerId)) {
      this.peerState.set(peerId, {
        inFlight: 0,
        consecutiveFailures: 0,
        failureRate: 0,
        metrics: {
          latencyMs: 0,
          inFlightJobs: 0,
          failureRate: 0,
          hyperbeeVersion: 0,
          hyperbeeLag: 0,
          queueDepth: 0,
          reportedAt: 0
        },
        lastHeartbeatAt: 0,
        lastAssignedAt: 0,
        lastSuccessAt: 0,
        circuitBrokenUntil: null
      });
    }
    return this.peerState.get(peerId);
  }

  #isPeerCircuitBroken(state) {
    if (!state.circuitBrokenUntil) return false;
    if (state.circuitBrokenUntil < now()) {
      state.circuitBrokenUntil = null;
      state.consecutiveFailures = 0;
      return false;
    }
    return true;
  }

  #scorePeer(state) {
    const latency = state.metrics.latencyMs || 0;
    const inFlight = state.inFlight;
    const failure = state.metrics.failureRate || 0;
    const lagPenalty = state.metrics.hyperbeeLag && this.policy.reassignOnLagBlocks && state.metrics.hyperbeeLag > this.policy.reassignOnLagBlocks
      ? state.metrics.hyperbeeLag
      : 0;

    return (
      latency * this.policy.latencyWeight
      + inFlight * this.policy.inFlightWeight
      + failure * this.policy.failureWeight
      + lagPenalty
    );
  }

  #decayFailureRate(current, failure) {
    const next = failure ? (current * 0.7) + 0.3 : current * 0.7;
    return Math.min(1, Math.max(0, next));
  }
}
