import { URL } from 'node:url';
import { createHash } from 'node:crypto';
import Hyperswarm from 'hyperswarm';
import WebSocket from 'ws';
import { schnorr } from '@noble/curves/secp256k1';

import {
  DISCOVERY_TOPIC,
  computeSecretHash,
  encodeAnnouncement,
  deriveKeyPair,
  signAnnouncement
} from '@hyperpipe/bridge/public-gateway/GatewayDiscovery';
import {
  buildGatewayAnnouncementEventTemplate,
  normalizeNostrRelayList
} from '@hyperpipe/bridge/public-gateway/GatewayDiscoveryNostr';

const DEFAULT_TTL_SECONDS = 60;
const DEFAULT_REFRESH_INTERVAL_MS = 30_000;

export async function publishNostrEventToRelay(relayUrl, event, { WebSocketImpl = WebSocket } = {}) {
  return await new Promise((resolve) => {
    let settled = false;
    let acknowledged = false;
    const timeout = setTimeout(() => {
      if (settled) return;
      settled = true;
      try {
        socket.terminate();
      } catch (_) {}
      resolve(false);
    }, 10_000);

    const finish = (ok) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve(ok);
    };

    const socket = new WebSocketImpl(relayUrl, {
      handshakeTimeout: 5_000
    });

    socket.once('open', () => {
      socket.send(JSON.stringify(['EVENT', event]));
      setTimeout(() => {
        if (!settled) {
          try {
            socket.close();
          } catch (_) {}
        }
      }, 1_000);
    });

    socket.on('message', (raw) => {
      let parsed;
      try {
        parsed = JSON.parse(String(raw));
      } catch (_) {
        return;
      }
      if (!Array.isArray(parsed)) return;
      if (parsed[0] !== 'OK') return;
      if (String(parsed[1] || '') !== event.id) return;
      acknowledged = true;
      finish(parsed[2] === true);
      try {
        socket.close();
      } catch (_) {}
    });

    socket.once('close', () => finish(acknowledged));
    socket.once('error', () => finish(false));
  });
}

class GatewayAdvertiser {
  constructor({
    logger,
    discoveryConfig,
    getSharedSecret,
    getSharedSecretVersion,
    getRelayInfo,
    publicUrl,
    wsUrl
  }) {
    this.logger = logger || console;
    this.config = discoveryConfig || {};
    this.getSharedSecret = typeof getSharedSecret === 'function' ? getSharedSecret : async () => null;
    this.getSharedSecretVersion = typeof getSharedSecretVersion === 'function'
      ? getSharedSecretVersion
      : async () => null;
    this.getRelayInfo = typeof getRelayInfo === 'function' ? getRelayInfo : async () => null;
    this.publicUrl = publicUrl || null;
    this.wsUrl = wsUrl || null;
    this.keyPair = null;
    this.gatewayId = null;
    this.swarm = null;
    this.discovery = null;
    this.running = false;
    this.secretUrl = this.#resolveSecretUrl(this.config.secretPath);
    this.ttl = Number.isFinite(this.config.ttlSeconds) && this.config.ttlSeconds > 0
      ? Math.round(this.config.ttlSeconds)
      : DEFAULT_TTL_SECONDS;
    this.refreshInterval = Number.isFinite(this.config.refreshIntervalMs) && this.config.refreshIntervalMs > 0
      ? this.config.refreshIntervalMs
      : DEFAULT_REFRESH_INTERVAL_MS;
    this.refreshTimer = null;
    this.cachedAnnouncement = null;
    this.cachedBuffer = null;
    this.cachedAt = 0;
    this.nostrEnabled = this.config.nostrEnabled !== false;
    this.nostrRelayUrls = normalizeNostrRelayList(this.config.nostrRelayUrls || []);
    this.nostrPublishInterval = Number.isFinite(this.config.nostrPublishIntervalMs) && this.config.nostrPublishIntervalMs > 0
      ? this.config.nostrPublishIntervalMs
      : this.refreshInterval;
    this.nostrPrivateKeyHex = null;
    this.nostrPublicKeyHex = null;
    this.lastNostrPublishedAt = 0;
    this.logger?.debug?.('[GatewayAdvertiser] Initialized discovery advertiser', {
      enabled: !!this.config.enabled,
      openAccess: !!this.config.openAccess,
      secretUrl: this.secretUrl,
      ttl: this.ttl,
      refreshInterval: this.refreshInterval,
      nostrEnabled: this.nostrEnabled,
      nostrRelayUrls: this.nostrRelayUrls
    });
  }

  isEnabled() {
    return !!this.config.enabled;
  }

  async start() {
    if (!this.isEnabled()) {
      this.logger?.info?.('[GatewayAdvertiser] Discovery disabled');
      return;
    }
    if (this.running) return;

    try {
      this.keyPair = deriveKeyPair(this.config.keySeed || null);
      this.gatewayId = Buffer.from(this.keyPair.publicKey).toString('hex');
      this.swarm = new Hyperswarm({ keyPair: this.keyPair });
      this.swarm.on('connection', (socket) => {
        this.#handleConnection(socket).catch((error) => {
          this.logger?.warn?.('[GatewayAdvertiser] Failed to handle discovery connection', {
            error: error?.message || error
          });
        });
      });
      this.swarm.on('error', (error) => {
        this.logger?.error?.('[GatewayAdvertiser] Hyperswarm error', {
          error: error?.message || error
        });
      });
      this.discovery = this.swarm.join(DISCOVERY_TOPIC, { server: true, client: false });
      await this.discovery.flushed();
      this.logger?.info?.('[GatewayAdvertiser] Discovery topic joined', {
        topic: Buffer.from(DISCOVERY_TOPIC).toString('hex')
      });
      this.running = true;
      await this.#refreshAnnouncement();
      this.refreshTimer = setInterval(() => {
        this.#refreshAnnouncement().catch((error) => {
          this.logger?.warn?.('[GatewayAdvertiser] Failed to refresh announcement', {
            error: error?.message || error
          });
        });
      }, this.refreshInterval).unref();
    } catch (error) {
      if (this.logger?.error) {
        this.logger.error({ err: error, stack: error?.stack }, '[GatewayAdvertiser] Failed to start discovery advertiser');
      }
      await this.stop();
      throw error;
    }
  }

  async stop() {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    if (this.discovery) {
      try {
        await this.discovery.destroy?.();
      } catch (error) {
        this.logger?.debug?.('[GatewayAdvertiser] Failed to destroy discovery handle', {
          error: error?.message || error
        });
      }
      this.discovery = null;
    }
    if (this.swarm) {
      try {
        await this.swarm.destroy();
      } catch (error) {
        this.logger?.debug?.('[GatewayAdvertiser] Failed to destroy hyperswarm', {
          error: error?.message || error
        });
      }
      this.swarm = null;
    }
    this.running = false;
    this.cachedAnnouncement = null;
    this.cachedBuffer = null;
    this.cachedAt = 0;
    this.lastNostrPublishedAt = 0;
  }

  async #handleConnection(socket) {
    socket.once('error', () => socket.destroy());
    try {
      const buffer = await this.#getAnnouncementBuffer();
      if (buffer) {
        socket.write(buffer);
      }
    } finally {
      socket.end();
    }
  }

  async #getAnnouncementBuffer() {
    const now = Date.now();
    if (!this.cachedBuffer || (now - this.cachedAt) > this.refreshInterval / 2) {
      await this.#refreshAnnouncement();
    }
    return this.cachedBuffer;
  }

  async #refreshAnnouncement() {
    const announcement = await this.#buildAnnouncement();
    this.cachedAnnouncement = announcement;
    this.cachedBuffer = encodeAnnouncement(announcement);
    this.cachedAt = Date.now();
    await this.#publishNostrAnnouncement(announcement).catch((error) => {
      this.logger?.warn?.('[GatewayAdvertiser] Failed to publish nostr announcement', {
        error: error?.message || error
      });
    });
  }

  async #buildAnnouncement() {
    const sharedSecret = await this.getSharedSecret();
    const sharedSecretVersion = await this.getSharedSecretVersion();
    const relayInfo = await this.getRelayInfo?.();
    const authConfig = this.config?.auth || {};
    const timestamp = Date.now();
    const displayName = this.config.displayName || null;
    const region = this.config.region || null;
    const protocolVersion = Number.isFinite(this.config.protocolVersion)
      ? Math.round(this.config.protocolVersion)
      : 1;

    const toPositiveInt = (value) => {
      const num = Number(value);
      if (!Number.isFinite(num) || num <= 0) return 0;
      return Math.round(num);
    };

    const relayTokenTtl = toPositiveInt(relayInfo?.defaultTokenTtl);
    const relayTokenRefreshWindow = toPositiveInt(relayInfo?.tokenRefreshWindowSeconds);
    const dispatcher = relayInfo?.dispatcher || {};
    const authMethod = typeof authConfig?.authMethod === 'string' && authConfig.authMethod.trim()
      ? authConfig.authMethod.trim()
      : 'relay-scoped-bearer-v1';
    const hostPolicy = typeof authConfig?.hostPolicy === 'string' ? authConfig.hostPolicy.trim().toLowerCase() : 'open';
    const memberDelegationMode = typeof authConfig?.memberDelegationMode === 'string'
      ? authConfig.memberDelegationMode.trim().toLowerCase()
      : 'all-members';
    const capabilities = Array.from(new Set([
      'relay-sponsor',
      memberDelegationMode !== 'none' ? 'relay-member-delegation' : null,
      memberDelegationMode === 'all-members' ? 'relay-open-join' : null,
      memberDelegationMode === 'closed-members' || memberDelegationMode === 'all-members'
        ? 'relay-closed-invite'
        : null
    ].filter(Boolean)));
    const openAccess = hostPolicy === 'open';

    const payload = {
      gatewayId: this.gatewayId,
      timestamp,
      ttl: this.ttl,
      publicUrl: this.publicUrl || '',
      wsUrl: this.wsUrl || '',
      secretUrl: openAccess && this.secretUrl ? this.secretUrl : '',
      secretHash: openAccess && sharedSecret ? computeSecretHash(sharedSecret || '') : '',
      openAccess,
      sharedSecretVersion: openAccess ? (sharedSecretVersion || '') : '',
      displayName: displayName || '',
      region: region || '',
      protocolVersion,
      signatureKey: Buffer.from(this.keyPair.publicKey).toString('hex'),
      relayKey: relayInfo?.hyperbeeKey || null,
      relayDiscoveryKey: relayInfo?.discoveryKey || null,
      relayReplicationTopic: relayInfo?.replicationTopic || null,
      relayTokenTtl,
      relayTokenRefreshWindow,
      dispatcherMaxConcurrent: toPositiveInt(dispatcher.maxConcurrentJobsPerPeer),
      dispatcherInFlightWeight: toPositiveInt(dispatcher.inFlightWeight),
      dispatcherLatencyWeight: toPositiveInt(dispatcher.latencyWeight),
      dispatcherFailureWeight: toPositiveInt(dispatcher.failureWeight),
      dispatcherReassignLagBlocks: toPositiveInt(dispatcher.reassignOnLagBlocks),
      dispatcherCircuitBreakerThreshold: toPositiveInt(dispatcher.circuitBreakerThreshold),
      dispatcherCircuitBreakerTimeoutMs: toPositiveInt(dispatcher.circuitBreakerDurationMs),
      authMethod,
      hostPolicy,
      memberDelegationMode,
      operatorPubkey: authConfig?.operatorAttestationFile
        ? null
        : (authConfig?.operatorPubkey || null),
      wotRootPubkey: authConfig?.wotRootPubkey || null,
      wotMaxDepth: toPositiveInt(authConfig?.wotMaxDepth),
      wotMinFollowersDepth2: Math.max(0, toPositiveInt(authConfig?.wotMinFollowersDepth2)),
      capabilities
    };

    payload.signature = signAnnouncement(payload, this.keyPair.secretKey);
    return payload;
  }

  async #publishNostrAnnouncement(announcement) {
    if (!this.nostrEnabled || !this.nostrRelayUrls.length) return;
    const now = Date.now();
    if (this.lastNostrPublishedAt && (now - this.lastNostrPublishedAt) < this.nostrPublishInterval) {
      return;
    }

    const event = this.#buildNostrAnnouncementEvent(announcement);
    if (!event) return;
    this.lastNostrPublishedAt = now;

    const outcomes = await Promise.allSettled(
      this.nostrRelayUrls.map((relayUrl) => this.#publishNostrEventToRelay(relayUrl, event))
    );
    const successes = outcomes.filter((result) => result.status === 'fulfilled' && result.value === true).length;
    const failures = outcomes.length - successes;

    if (successes > 0) {
      this.logger?.debug?.('[GatewayAdvertiser] Nostr discovery publish complete', {
        eventId: event.id,
        relays: this.nostrRelayUrls.length,
        successes,
        failures
      });
      return;
    }

    this.logger?.warn?.('[GatewayAdvertiser] Nostr discovery publish had no successful relays', {
      eventId: event.id,
      relays: this.nostrRelayUrls
    });
  }

  #buildNostrAnnouncementEvent(announcement) {
    const identity = this.#ensureNostrIdentity();
    if (!identity) return null;

    const eventTemplate = buildGatewayAnnouncementEventTemplate({
      gatewayId: announcement.gatewayId,
      httpOrigin: announcement.publicUrl,
      wsOrigin: announcement.wsUrl,
      displayName: announcement.displayName || null,
      region: announcement.region || null,
      secretUrl: announcement.secretUrl || null,
      secretHash: announcement.secretHash || null,
      sharedSecretVersion: announcement.sharedSecretVersion || null,
      relayKey: announcement.relayKey || null,
      relayDiscoveryKey: announcement.relayDiscoveryKey || null,
      relayReplicationTopic: announcement.relayReplicationTopic || null,
      defaultTokenTtl: announcement.relayTokenTtl || null,
      tokenRefreshWindowSeconds: announcement.relayTokenRefreshWindow || null,
      openAccess: announcement.openAccess === true,
      authMethod: announcement.authMethod || null,
      hostPolicy: announcement.hostPolicy || null,
      memberDelegationMode: announcement.memberDelegationMode || null,
      operatorPubkey: announcement.operatorPubkey || null,
      wotRootPubkey: announcement.wotRootPubkey || null,
      wotMaxDepth: announcement.wotMaxDepth || null,
      wotMinFollowersDepth2: announcement.wotMinFollowersDepth2 ?? null,
      capabilities: Array.isArray(announcement.capabilities) ? announcement.capabilities : [],
      ttlSeconds: announcement.ttl || this.ttl
    });

    const unsignedEvent = {
      pubkey: this.nostrPublicKeyHex,
      kind: eventTemplate.kind,
      created_at: eventTemplate.created_at,
      tags: eventTemplate.tags,
      content: eventTemplate.content || ''
    };
    const serialized = JSON.stringify([
      0,
      unsignedEvent.pubkey,
      unsignedEvent.created_at,
      unsignedEvent.kind,
      unsignedEvent.tags,
      unsignedEvent.content
    ]);
    const eventId = createHash('sha256').update(serialized).digest('hex');
    const signatureBytes = schnorr.sign(Buffer.from(eventId, 'hex'), Buffer.from(identity.privateKeyHex, 'hex'));
    const sig = Buffer.from(signatureBytes).toString('hex');

    return {
      ...unsignedEvent,
      id: eventId,
      sig
    };
  }

  #ensureNostrIdentity() {
    if (this.nostrPrivateKeyHex && this.nostrPublicKeyHex) {
      return {
        privateKeyHex: this.nostrPrivateKeyHex,
        publicKeyHex: this.nostrPublicKeyHex
      };
    }

    const seed = this.#resolveNostrSeedMaterial();
    if (!seed) return null;
    const privateKeyHex = createHash('sha256').update(seed).digest('hex');
    const publicKeyHex = Buffer.from(schnorr.getPublicKey(Buffer.from(privateKeyHex, 'hex'))).toString('hex');
    this.nostrPrivateKeyHex = privateKeyHex;
    this.nostrPublicKeyHex = publicKeyHex;
    return { privateKeyHex, publicKeyHex };
  }

  #resolveNostrSeedMaterial() {
    const explicitSeed =
      typeof this.config.nostrKeySeed === 'string' && this.config.nostrKeySeed.trim()
        ? this.config.nostrKeySeed.trim()
        : null;
    if (explicitSeed) return `hyperpipe-nostr:${explicitSeed}`;

    const legacySeed =
      typeof this.config.keySeed === 'string' && this.config.keySeed.trim()
        ? this.config.keySeed.trim()
        : null;
    if (legacySeed) return `hyperpipe-nostr:${legacySeed}`;

    if (this.keyPair?.secretKey) {
      return Buffer.from(this.keyPair.secretKey).toString('hex');
    }
    return this.gatewayId || null;
  }

  async #publishNostrEventToRelay(relayUrl, event) {
    return await publishNostrEventToRelay(relayUrl, event);
  }

  #resolveSecretUrl(secretPath) {
    if (!secretPath) {
      return this.publicUrl ? new URL('/.well-known/hyperpipe-gateway-secret', this.publicUrl).toString() : '';
    }
    if (!this.publicUrl) return secretPath;
    try {
      if (secretPath.startsWith('http://') || secretPath.startsWith('https://')) {
        return secretPath;
      }
      const normalizedPath = secretPath.startsWith('/') ? secretPath : `/${secretPath}`;
      return new URL(normalizedPath, this.publicUrl).toString();
    } catch (error) {
      this.logger?.warn?.('[GatewayAdvertiser] Failed to resolve secret URL', {
        secretPath,
        error: error?.message || error
      });
      return '';
    }
  }
}

export default GatewayAdvertiser;
