import WebSocket from 'ws';

export default class RelayWebsocketController {
  constructor({
    relayHost,
    hyperbeeAdapter = null,
    dispatcher = null,
    logger = console,
    featureFlags = {},
    metrics = {},
    legacyForward
  }) {
    if (!relayHost) throw new Error('RelayWebsocketController requires a relayHost');
    if (typeof legacyForward !== 'function') {
      throw new Error('RelayWebsocketController requires a legacyForward handler');
    }

    this.relayHost = relayHost;
    this.hyperbeeAdapter = hyperbeeAdapter;
    this.dispatcher = dispatcher;
    this.logger = logger;
    this.featureFlags = featureFlags;
    this.metrics = {
      eventCounter: metrics.eventCounter,
      reqCounter: metrics.reqCounter,
      errorCounter: metrics.errorCounter
    };
    this.legacyForward = legacyForward;
    this.subscriptions = new Map();
  }

  getSubscriptionSnapshot(sessionKey) {
    const subs = this.subscriptions.get(sessionKey);
    if (!subs) return [];
    return Array.from(subs.entries()).map(([subscriptionId, state]) => ({
      subscriptionId,
      filters: Array.isArray(state?.filters) ? state.filters : [],
      lastReturnedAt: Number.isFinite(state?.lastReturnedAt) ? state.lastReturnedAt : null
    }));
  }

  updateSubscriptionCursor(sessionKey, subscriptionId, timestamp) {
    this.#updateSubscriptionCursor(sessionKey, subscriptionId, timestamp);
  }

  async handleMessage(session, rawMessage) {
    let frame;
    try {
      frame = JSON.parse(typeof rawMessage === 'string' ? rawMessage : rawMessage.toString());
    } catch (error) {
      this.#incrementError('parse');
      this.#sendNotice(session, 'Invalid message payload');
      return true;
    }

    if (!Array.isArray(frame) || frame.length === 0) {
      this.#incrementError('format');
      this.#sendNotice(session, 'Malformed Nostr frame');
      return true;
    }

    const type = frame[0];
    switch (type) {
      case 'EVENT':
        await this.#handleEventFrame(session, frame);
        return true;
      case 'REQ':
        await this.#handleReqFrame(session, frame, rawMessage);
        return true;
      case 'CLOSE':
        this.#removeSubscription(session.connectionKey, frame[1]);
        await this.#forwardLegacy(session, rawMessage);
        return true;
      case 'PING':
      case 'PONG':
      case 'AUTH':
        // Pass through without modification for now
        await this.#forwardLegacy(session, rawMessage);
        return true;
      default:
        // Unknown frame types fall back to legacy handling
        return false;
    }
  }

  removeSession(sessionKey) {
    const subs = this.subscriptions.get(sessionKey);
    if (subs) {
      for (const subscriptionId of subs.keys()) {
        this.dispatcher?.acknowledge(subscriptionId, { peerId: null });
      }
    }
    this.subscriptions.delete(sessionKey);
  }

  async #handleEventFrame(session, frame) {
    if (frame.length < 2 || typeof frame[1] !== 'object' || frame[1] === null) {
      this.#incrementError('event-format');
      this.#sendNotice(session, 'Invalid EVENT payload');
      return;
    }

    const event = frame[1];
    try {
      const result = await this.relayHost.applyEvent(event);
      const success = result?.status === 'accepted';
      this.#incrementEvent(success ? 'accepted' : 'rejected');
      this.#sendOk(session, event.id || null, success, success ? 'stored' : result?.reason || 'rejected');
    } catch (error) {
      this.#incrementEvent('error');
      this.logger.error?.({
        error: error?.message || error,
        eventId: event?.id || null
      }, '[RelayWebsocketController] Failed to persist event');
      this.#sendOk(session, event?.id || null, false, error?.message || 'append-error');
    }
  }

  async #handleReqFrame(session, frame, rawMessage) {
    if (frame.length < 2) {
      this.#incrementError('req-format');
      this.#sendNotice(session, 'REQ frame missing subscription id');
      return;
    }

    const subscriptionId = frame[1];
    const filters = frame.slice(2);

    this.#recordSubscription(session.connectionKey, subscriptionId, filters);

    const subscriptionState = this.#getSubscriptionState(session.connectionKey, subscriptionId);
    const lastReturnedAt = subscriptionState?.lastReturnedAt ?? null;

    const pendingDelegatedMessages = Array.isArray(session.pendingDelegatedMessages)
      ? session.pendingDelegatedMessages.length
      : 0;
    this.logger.info?.({
      tag: 'DelegationDebug',
      stage: 'req-received',
      relayKey: session.relayKey,
      connectionKey: session.connectionKey,
      subscriptionId,
      delegateReqToPeers: session.delegateReqToPeers === true,
      delegationReady: session.delegationReady === true,
      localOnly: session.localOnly === true,
      peerKey: session.peerKey || null,
      peerCount: Array.isArray(session.peers) ? session.peers.length : 0,
      pendingDelegatedMessages,
      lastReturnedAt
    }, 'DelegationDebug: REQ received');

    const localResult = await this.#serveReqFromHyperbee(session, subscriptionId, filters, lastReturnedAt);
    if (localResult?.handled) {
      this.logger.info?.({
        tag: 'DelegationDebug',
        stage: 'req-served-local',
        relayKey: session.relayKey,
        connectionKey: session.connectionKey,
        subscriptionId,
        delivered: localResult.delivered || 0,
        latestTimestamp: localResult.latestTimestamp ?? null
      }, 'DelegationDebug: REQ served locally');
      if (Number.isFinite(localResult.latestTimestamp)) {
        this.#updateSubscriptionCursor(session.connectionKey, subscriptionId, localResult.latestTimestamp);
      }
      return;
    }

    this.logger.info?.({
      tag: 'DelegationDebug',
      stage: 'req-delegating',
      relayKey: session.relayKey,
      connectionKey: session.connectionKey,
      subscriptionId,
      dispatcherEnabled: this.featureFlags?.dispatcherEnabled && !!this.dispatcher,
      delegateReqToPeers: session.delegateReqToPeers === true,
      localOnly: session.localOnly === true,
      peerKey: session.peerKey || null,
      peerCount: Array.isArray(session.peers) ? session.peers.length : 0
    }, 'DelegationDebug: Delegating REQ to peers');

    const dispatcherEnabled = this.featureFlags?.dispatcherEnabled && !!this.dispatcher;

    if (dispatcherEnabled) {
      try {
        const job = {
          id: subscriptionId,
          filters,
          relayKey: session.relayKey,
          requester: {
            peerId: session.clientPubkey || session.connectionKey,
            relayKey: session.relayKey
          },
          createdAt: Date.now(),
          peers: Array.isArray(session.peers) ? [...session.peers] : []
        };
        const decision = await this.dispatcher.schedule(job);
        this.#incrementReq('scheduled');
        if (decision?.status === 'rejected') {
          this.#sendNotice(session, decision?.reason || 'Subscription rejected');
          await this.#forwardLegacy(session, rawMessage, null, { subscriptionId, storePending: true });
          return;
        }

        if (decision?.status === 'assigned' && decision.assignedPeer) {
          session.assignPeer?.(decision.assignedPeer, subscriptionId);
          try {
            await this.#forwardLegacy(session, rawMessage, decision.assignedPeer, { subscriptionId, storePending: true });
            this.dispatcher.acknowledge(subscriptionId, { peerId: decision.assignedPeer });
          } catch (error) {
            this.dispatcher.fail(subscriptionId, { peerId: decision.assignedPeer, error: error?.message || error });
            this.#incrementError('dispatch-forward');
            this.logger.error?.({
              relayKey: session.relayKey,
              subscriptionId,
              peerId: decision.assignedPeer,
              error: error?.message || error
            }, '[RelayWebsocketController] Assigned peer forwarding failed');
            await this.#forwardLegacy(session, rawMessage, null, { subscriptionId, storePending: true });
          }
          return;
        }
      } catch (error) {
        this.#incrementReq('schedule-error');
        this.logger.error?.({
          error: error?.message || error,
          relayKey: session.relayKey
        }, '[RelayWebsocketController] Dispatcher scheduling failed');
        await this.#forwardLegacy(session, rawMessage, null, { subscriptionId, storePending: true });
      }
      return;
    }

    this.#incrementReq('legacy-forward');
    await this.#forwardLegacy(session, rawMessage, null, { subscriptionId, storePending: true });
  }

  async #forwardLegacy(session, rawMessage, targetPeer = null, context = {}) {
    const storePending = context?.storePending === true;
    const subscriptionId = context?.subscriptionId || null;
    if (session?.localOnly) {
    if (session?.delegateReqToPeers && !storePending) {
        if (!Array.isArray(session.pendingDelegatedMessages)) {
          session.pendingDelegatedMessages = [];
        }
        const normalizedMessage = typeof rawMessage === 'string'
          ? rawMessage
          : Buffer.isBuffer(rawMessage)
            ? rawMessage.toString('utf8')
            : JSON.stringify(rawMessage);
        session.pendingDelegatedMessages.push({
          message: normalizedMessage,
          preferredPeer: targetPeer || null,
          queuedAt: Date.now(),
          subscriptionId
        });
        this.logger.debug?.({
          relayKey: session.relayKey,
          connectionKey: session.connectionKey,
          queueLength: session.pendingDelegatedMessages.length
        }, '[RelayWebsocketController] Queued delegated frame while session is local-only');
      }
      return;
    }

    try {
      await this.legacyForward(session, rawMessage, targetPeer, context);
    } catch (error) {
      this.#incrementError('legacy-forward');
      this.logger.warn?.({
        error: error?.message || error,
        relayKey: session.relayKey
      }, '[RelayWebsocketController] Legacy forward failed');
      this.#sendNotice(session, `Legacy forwarding error: ${error?.message || error}`);
    }
  }

  #sendNotice(session, message) {
    if (session.ws?.readyState === WebSocket.OPEN) {
      session.ws.send(JSON.stringify(['NOTICE', message]));
    }
  }

  #sendOk(session, eventId, success, message) {
    if (session.ws?.readyState === WebSocket.OPEN) {
      session.ws.send(JSON.stringify(['OK', eventId, success, message]));
    }
  }

  #incrementEvent(result) {
    try {
      this.metrics.eventCounter?.inc({ result });
    } catch (_) {}
  }

  #incrementReq(path) {
    try {
      this.metrics.reqCounter?.inc({ path });
    } catch (_) {}
  }

  #incrementError(stage) {
    try {
      this.metrics.errorCounter?.inc({ stage });
    } catch (_) {}
  }

  #recordSubscription(sessionKey, subscriptionId, filters) {
    if (!subscriptionId) return;
    let subs = this.subscriptions.get(sessionKey);
    if (!subs) {
      subs = new Map();
      this.subscriptions.set(sessionKey, subs);
    }
    const existing = subs.get(subscriptionId) || { filters: [], lastReturnedAt: null };
    existing.filters = filters || [];
    subs.set(subscriptionId, existing);
  }

  #removeSubscription(sessionKey, subscriptionId) {
    if (!subscriptionId) return;
    const subs = this.subscriptions.get(sessionKey);
    if (!subs) return;
    subs.delete(subscriptionId);
    this.dispatcher?.acknowledge(subscriptionId, { peerId: null });
    if (subs.size === 0) {
      this.subscriptions.delete(sessionKey);
    }
  }

  #getSubscriptionState(sessionKey, subscriptionId) {
    const subs = this.subscriptions.get(sessionKey);
    if (!subs) return null;
    return subs.get(subscriptionId) || null;
  }

  #updateSubscriptionCursor(sessionKey, subscriptionId, timestamp) {
    if (!Number.isFinite(timestamp)) return;
    const subs = this.subscriptions.get(sessionKey);
    if (!subs) return;
    const state = subs.get(subscriptionId);
    if (!state) return;
    state.lastReturnedAt = timestamp;
    subs.set(subscriptionId, state);
  }

  async #serveReqFromHyperbee(session, subscriptionId, filters, lastReturnedAt) {
    if (!this.hyperbeeAdapter?.hasReplica?.()) {
      return null;
    }

    if (session?.delegateReqToPeers === true && session?.localOnly !== true) {
      this.logger.debug?.({
        relayKey: session.relayKey,
        subscriptionId
      }, '[RelayWebsocketController] Skipping local serve due to delegation preference');
      return null;
    }

    try {
      const queryResult = await this.hyperbeeAdapter.query(filters || []);
      if (!queryResult?.stats?.served) {
        return null;
      }

      const events = Array.isArray(queryResult.events) ? queryResult.events : [];
      const filteredEvents = events.filter((event) => {
        const createdAt = Number(event?.created_at ?? 0);
        if (!Number.isFinite(lastReturnedAt)) return true;
        return createdAt > lastReturnedAt;
      });

      const latestTimestamp = filteredEvents.reduce((acc, event) => {
        const createdAt = Number(event?.created_at ?? 0);
        if (!Number.isFinite(createdAt)) return acc;
        return Math.max(acc, createdAt);
      }, Number.isFinite(lastReturnedAt) ? lastReturnedAt : -Infinity);

      for (const event of filteredEvents) {
        if (session.ws?.readyState === WebSocket.OPEN) {
          session.ws.send(JSON.stringify(['EVENT', subscriptionId, event]));
        }
      }

      if (session.ws?.readyState === WebSocket.OPEN) {
        session.ws.send(JSON.stringify(['EOSE', subscriptionId]));
      }

      this.#incrementReq('served-local');

      return {
        handled: true,
        latestTimestamp: Number.isFinite(latestTimestamp) ? latestTimestamp : lastReturnedAt ?? null,
        delivered: filteredEvents.length
      };
    } catch (error) {
      this.logger.warn?.({
        error: error?.message || error,
        relayKey: session.relayKey,
        subscriptionId
      }, '[RelayWebsocketController] Hyperbee query failed, falling back to peers');
      this.#incrementError('hyperbee-query');
      return null;
    }
  }
}
