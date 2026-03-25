import pino from 'pino';
import pinoHttp from 'pino-http';

function createLogger(options = {}) {
  // Default: suppress noisy instrumentation unless explicitly disabled.
  const noiseEnv = String(process.env.GATEWAY_SUPPRESS_NOISE || '').toLowerCase();
  const suppressNoise = noiseEnv === '' ? true : noiseEnv !== 'false' && noiseEnv !== '0';
  const extraTags = (process.env.GATEWAY_SUPPRESS_TAGS || '')
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean);
  const suppressedMarkers = new Set([
    'DelegationDebug',
    'PublicGatewayHyperbeeAdapter',
    'HyperbeeRelayHost',
    'Peer operation succeeded',
    ...extraTags
  ]);

  const shouldSuppress = (...args) => {
    if (!suppressNoise) return false;

    const stringValues = [];
    const objectValues = [];

    for (const arg of args) {
      if (typeof arg === 'string') {
        stringValues.push(arg);
      } else if (arg && typeof arg === 'object') {
        objectValues.push(arg);
        for (const value of Object.values(arg)) {
          if (typeof value === 'string') stringValues.push(value);
        }
      }
    }

    for (const marker of suppressedMarkers) {
      if (stringValues.some((val) => val.includes(marker))) return true;
    }

    const relayKey = objectValues.find((o) => typeof o.relayKey === 'string')?.relayKey;
    if (relayKey === 'public-gateway:hyperbee') return true;

    return false;
  };

  const normalizeArgs = (args) => {
    if (args.length >= 2 && typeof args[0] === 'string' && args[1] && typeof args[1] === 'object' && !Array.isArray(args[1])) {
      const [msg, obj, ...rest] = args;
      return [obj, msg, ...rest];
    }
    return args;
  };

  return pino({
    level: 'trace',
    transport: process.env.NODE_ENV === 'development'
      ? { target: 'pino-pretty', options: { colorize: true } }
      : undefined,
    hooks: {
      logMethod(args, method) {
        const normalized = normalizeArgs(args);
        if (shouldSuppress(...normalized)) return;
        return method.apply(this, normalized);
      }
    },
    ...options
  });
}

function createHttpLogger(logger) {
  return pinoHttp({
    logger,
    autoLogging: true,
    redact: ['req.headers.authorization', 'req.headers.cookie']
  });
}

export {
  createLogger,
  createHttpLogger
};
