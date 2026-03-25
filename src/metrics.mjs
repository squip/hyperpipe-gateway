import client from 'prom-client';

const register = new client.Registry();
client.collectDefaultMetrics({ register });

const sessionGauge = new client.Gauge({
  name: 'gateway_active_sessions',
  help: 'Number of active websocket sessions'
});

const peerGauge = new client.Gauge({
  name: 'gateway_active_peers',
  help: 'Number of active hyperswarm peers'
});

const requestCounter = new client.Counter({
  name: 'gateway_forwarded_messages_total',
  help: 'Count of messages forwarded through the gateway',
  labelNames: ['relay']
});

const relayEventCounter = new client.Counter({
  name: 'gateway_relay_events_total',
  help: 'Count of EVENT frames processed by the gateway relay host',
  labelNames: ['result']
});

const relayReqCounter = new client.Counter({
  name: 'gateway_relay_requests_total',
  help: 'Count of REQ frames processed by the gateway relay pipeline',
  labelNames: ['path']
});

const relayErrorCounter = new client.Counter({
  name: 'gateway_relay_websocket_errors_total',
  help: 'Count of errors encountered while handling relay websocket messages',
  labelNames: ['stage']
});

const relayTokenIssueCounter = new client.Counter({
  name: 'gateway_relay_token_issues_total',
  help: 'Count of relay tokens issued by the gateway',
  labelNames: ['result']
});

const relayTokenRefreshCounter = new client.Counter({
  name: 'gateway_relay_token_refresh_total',
  help: 'Count of relay token refresh operations',
  labelNames: ['result']
});

const relayTokenRevocationCounter = new client.Counter({
  name: 'gateway_relay_token_revocations_total',
  help: 'Count of relay token revocations initiated by the gateway',
  labelNames: ['result']
});

const openJoinPoolDepletionCounter = new client.Counter({
  name: 'gateway_open_join_pool_depletion_total',
  help: 'Count of open-join lease pool depletion events',
  labelNames: ['stage']
});

const blindPeerActiveGauge = new client.Gauge({
  name: 'gateway_blind_peer_active',
  help: 'Indicates whether the blind-peer service is active (1) or disabled (0)'
});

const blindPeerTrustedPeersGauge = new client.Gauge({
  name: 'gateway_blind_peer_trusted_peers',
  help: 'Number of trusted peers registered with the blind-peer service'
});

const blindPeerBytesGauge = new client.Gauge({
  name: 'gateway_blind_peer_bytes_allocated',
  help: 'Bytes allocated by the blind-peer storage subsystem'
});

const blindPeerGcRunsCounter = new client.Counter({
  name: 'gateway_blind_peer_gc_runs_total',
  help: 'Count of hygiene/GC runs triggered for the blind-peer service'
});

const blindPeerEvictionsCounter = new client.Counter({
  name: 'gateway_blind_peer_evictions_total',
  help: 'Count of blind-peer core evictions performed by hygiene',
  labelNames: ['reason']
});

const blindPeerMirrorStateGauge = new client.Gauge({
  name: 'gateway_blind_peer_mirror_state',
  help: 'Mirror readiness state (1 = healthy, 0 = stale)',
  labelNames: ['identifier', 'owner', 'type']
});

const blindPeerMirrorLagGauge = new client.Gauge({
  name: 'gateway_blind_peer_mirror_lag_ms',
  help: 'Lag in milliseconds since the mirror last reported activity',
  labelNames: ['identifier', 'owner', 'type']
});

register.registerMetric(sessionGauge);
register.registerMetric(peerGauge);
register.registerMetric(requestCounter);
register.registerMetric(relayEventCounter);
register.registerMetric(relayReqCounter);
register.registerMetric(relayErrorCounter);
register.registerMetric(relayTokenIssueCounter);
register.registerMetric(relayTokenRefreshCounter);
register.registerMetric(relayTokenRevocationCounter);
register.registerMetric(openJoinPoolDepletionCounter);
register.registerMetric(blindPeerActiveGauge);
register.registerMetric(blindPeerTrustedPeersGauge);
register.registerMetric(blindPeerBytesGauge);
register.registerMetric(blindPeerGcRunsCounter);
register.registerMetric(blindPeerEvictionsCounter);
register.registerMetric(blindPeerMirrorStateGauge);
register.registerMetric(blindPeerMirrorLagGauge);

function metricsMiddleware(path = '/metrics') {
  return async (req, res, next) => {
    if (req.path !== path) return next();
    try {
      res.setHeader('Content-Type', register.contentType);
      res.end(await register.metrics());
    } catch (error) {
      next(error);
    }
  };
}

export {
  register,
  sessionGauge,
  peerGauge,
  requestCounter,
  relayEventCounter,
  relayReqCounter,
  relayErrorCounter,
  relayTokenIssueCounter,
  relayTokenRefreshCounter,
  relayTokenRevocationCounter,
  openJoinPoolDepletionCounter,
  blindPeerActiveGauge,
  blindPeerTrustedPeersGauge,
  blindPeerBytesGauge,
  blindPeerGcRunsCounter,
  blindPeerEvictionsCounter,
  blindPeerMirrorStateGauge,
  blindPeerMirrorLagGauge,
  metricsMiddleware
};
