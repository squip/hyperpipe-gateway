import { EventEmitter } from 'node:events';
import { mkdir } from 'node:fs/promises';
import Corestore from 'corestore';
import Hyperbee from 'hyperbee';
import b4a from 'b4a';

const DEFAULT_STATS_INTERVAL_MS = 15_000;
const DEFAULT_NAMESPACE = 'public-gateway-relay';

function hexToBuffer(hex) {
  if (!hex) return null;
  return Buffer.isBuffer(hex) ? hex : Buffer.from(hex, 'hex');
}

function safeStringify(payload) {
  try {
    return JSON.stringify(payload);
  } catch (error) {
    return JSON.stringify({ error: 'serialization-error', message: error?.message });
  }
}

function padNumber(num, length) {
  const value = Number.isFinite(num) ? num : 0;
  return String(Math.trunc(value)).padStart(length, '0');
}

function padTimestamp(timestamp) {
  const value = Number.isFinite(timestamp) ? timestamp : 0;
  return String(Math.trunc(value)).padStart(10, '0');
}

export class HyperbeeRelayHost extends EventEmitter {
  constructor({ logger = console, telemetryIntervalMs = DEFAULT_STATS_INTERVAL_MS } = {}) {
    super();
    this.logger = logger;
    this.telemetryIntervalMs = telemetryIntervalMs;
    this.store = null;
    this.namespace = DEFAULT_NAMESPACE;
    this.core = null;
    this.db = null;
    this.options = null;
    this.initialized = false;
    this.started = false;
    this.statsTimer = null;
    this.telemetrySinks = new Set();
  }

  async initialize(options) {
    if (this.initialized) return;
    if (!options?.storageDir) {
      throw new Error('HyperbeeRelayHost requires a storageDir');
    }
    if (!options?.adminKeyPair?.publicKey || !options?.adminKeyPair?.secretKey) {
      throw new Error('HyperbeeRelayHost requires admin key pair');
    }

    this.options = {
      statsIntervalMs: this.telemetryIntervalMs,
      ...options
    };

    await mkdir(options.storageDir, { recursive: true });

    const adminKeyPair = {
      publicKey: hexToBuffer(options.adminKeyPair.publicKey),
      secretKey: hexToBuffer(options.adminKeyPair.secretKey)
    };

    this.namespace = options.datasetNamespace || this.namespace;

    this.store = new Corestore(options.storageDir);
    await this.store.ready();

    const coreOptions = {
      cache: true
    };

    if (adminKeyPair.secretKey) {
      coreOptions.keyPair = adminKeyPair;
    } else {
      coreOptions.name = options.datasetNamespace || this.namespace;
    }

    this.core = this.store.get(coreOptions);

    this.db = new Hyperbee(this.core, {
      keyEncoding: 'binary',
      valueEncoding: 'utf-8'
    });

    await this.db.ready();
    this.initialized = true;

    this.logger.info?.({
      namespace: this.core.id,
      writable: this.db?.writable,
      key: this.getPublicKey()
    }, '[HyperbeeRelayHost] Initialized');
  }

  async start() {
    if (!this.initialized) {
      throw new Error('HyperbeeRelayHost not initialized');
    }
    if (this.started) return;
    this.started = true;
    this.#startStatsLoop();
    this.logger.info?.('[HyperbeeRelayHost] Started');
  }

  async stop() {
    if (!this.initialized) return;
    if (this.statsTimer) {
      clearInterval(this.statsTimer);
      this.statsTimer = null;
    }
    if (this.db) {
      await this.db.close();
      this.db = null;
    }
    if (this.core) {
      await this.core.close();
      this.core = null;
    }
    if (this.store) {
      await this.store.close();
      this.store = null;
    }
    this.started = false;
    this.initialized = false;
    this.logger.info?.('[HyperbeeRelayHost] Stopped');
  }

  async applyEvent(event) {
    if (!this.started || !this.db?.writable) {
      return { id: event?.id, status: 'rejected', reason: 'host-not-writable' };
    }
    if (!event?.id) {
      return { id: null, status: 'rejected', reason: 'invalid-event' };
    }

    const key = hexToBuffer(event.id);
    if (!key) {
      return { id: event.id, status: 'rejected', reason: 'invalid-event-id' };
    }

    const payload = safeStringify(event);

    try {
      const batch = this.db.batch();
      await batch.put(key, payload);

      for (const entry of this.#buildIndexEntries(event)) {
        await batch.put(entry.key, entry.value);
      }

      await batch.flush();
      this.logger?.info?.({
        id: event.id,
        kind: event.kind,
        created_at: event.created_at
      }, '[HyperbeeRelayHost] Event stored');
      this.#emitTelemetry('hyperbee-append', { id: event.id, kind: event.kind, created_at: event.created_at });
      return { id: event.id, status: 'accepted' };
    } catch (error) {
      this.logger.error?.({ error: error?.message }, '[HyperbeeRelayHost] Failed to append event');
      this.#emitTelemetry('hyperbee-error', { id: event.id, error: error?.message || error });
      return { id: event.id, status: 'rejected', reason: error?.message || 'append-failed' };
    }
  }

  async replicateWithPeer(peer) {
    if (!this.core) {
      throw new Error('HyperbeeRelayHost core not initialized');
    }
    this.logger.debug?.({ peer }, '[HyperbeeRelayHost] Replication requested');
    // Placeholder for replication stream wiring; to be implemented in dispatcher phase.
  }

  async getStats() {
    if (!this.core || !this.db) {
      return {
        version: 0,
        eventCount: 0,
        replicationPeers: []
      };
    }

    await this.core.ready();
    await this.db.ready();

    const eventCount = this.core.length;

    return {
      version: this.db.version,
      eventCount,
      lastAppendAt: this.core?.header?.timestamp || null,
      replicationPeers: []
    };
  }

  registerTelemetrySink(sink) {
    if (typeof sink !== 'function') return () => {};
    this.telemetrySinks.add(sink);
    return () => {
      this.telemetrySinks.delete(sink);
    };
  }

  #buildIndexEntries(event) {
    const entries = [];
    if (!event?.id) return entries;

    const eventIdValue = b4a.from(event.id, 'utf8');
    const createdAt = Number(event?.created_at) || 0;
    const paddedCreatedAt = padTimestamp(createdAt);

    const timeKey = b4a.from(`created_at:${paddedCreatedAt}:id:${event.id}`, 'utf8');
    entries.push({ key: timeKey, value: eventIdValue });

    if (Number.isInteger(event?.kind)) {
      const paddedKind = padNumber(event.kind, 5);
      const kindKey = b4a.from(`kind:${paddedKind}:created_at:${paddedCreatedAt}:id:${event.id}`, 'utf8');
      entries.push({ key: kindKey, value: eventIdValue });
    }

    if (typeof event?.pubkey === 'string' && event.pubkey.length) {
      const authorKey = b4a.from(`pubkey:${event.pubkey}:created_at:${paddedCreatedAt}:id:${event.id}`, 'utf8');
      entries.push({ key: authorKey, value: eventIdValue });
    }

    if (Array.isArray(event?.tags)) {
      for (const tag of event.tags) {
        if (!Array.isArray(tag) || tag.length < 2) continue;
        const [name, value] = tag;
        if (typeof name !== 'string' || typeof value !== 'string') continue;
        const tagKey = b4a.from(`tagKey:${name}:tagValue:${value}:created_at:${paddedCreatedAt}:id:${event.id}`, 'utf8');
        entries.push({ key: tagKey, value: eventIdValue });
      }
    }

    return entries;
  }

  getPublicKey() {
    if (!this.core?.key) return null;
    return b4a.toString(this.core.key, 'hex');
  }

  getDiscoveryKey() {
    if (!this.core?.discoveryKey) return null;
    return b4a.toString(this.core.discoveryKey, 'hex');
  }

  getHyperbee() {
    return this.db;
  }

  getCore() {
    return this.core;
  }

  #startStatsLoop() {
    if (this.statsTimer) return;
    const interval = this.options?.statsIntervalMs || DEFAULT_STATS_INTERVAL_MS;
    this.statsTimer = setInterval(async () => {
      try {
        const stats = await this.getStats();
        this.#emitTelemetry('replication', { stats });
      } catch (error) {
        this.logger.error?.({ error: error?.message }, '[HyperbeeRelayHost] Failed to collect stats');
        this.#emitTelemetry('hyperbee-error', { error: error?.message || error });
      }
    }, interval);
    this.statsTimer.unref?.();
  }

  #emitTelemetry(type, payload) {
    const event = {
      type,
      timestamp: Date.now(),
      payload
    };
    for (const sink of this.telemetrySinks) {
      try {
        sink(event);
      } catch (error) {
        this.logger.warn?.({ error: error?.message }, '[HyperbeeRelayHost] Telemetry sink failed');
      }
    }
    this.emit('telemetry', event);
  }
}

export default HyperbeeRelayHost;
