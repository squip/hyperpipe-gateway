import { randomBytes } from 'node:crypto';
import WebSocket from 'ws';

const NOSTR_CONTACT_LIST_KIND = 3;
const MAX_CONTACT_LIST_EVENT_LIMIT = 128;
const DEFAULT_FETCH_BATCH_TIMEOUT_MS = 5_000;

function normalizeHexPubkey(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim().toLowerCase();
  return /^[0-9a-f]{64}$/.test(trimmed) ? trimmed : null;
}

function selectPreferredEvent(existing, next) {
  if (!existing) return next;
  const existingCreatedAt = Number(existing.created_at) || 0;
  const nextCreatedAt = Number(next.created_at) || 0;
  if (nextCreatedAt > existingCreatedAt) return next;
  if (nextCreatedAt < existingCreatedAt) return existing;
  return String(next.id || '').localeCompare(String(existing.id || '')) > 0 ? next : existing;
}

function extractFollowPubkeys(event) {
  const follows = [];
  const tags = Array.isArray(event?.tags) ? event.tags : [];
  for (const tag of tags) {
    if (!Array.isArray(tag) || tag[0] !== 'p') continue;
    const pubkey = normalizeHexPubkey(tag[1]);
    if (pubkey) follows.push(pubkey);
  }
  return follows;
}

function normalizeRelayUrls(relayUrls = []) {
  return Array.from(new Set(
    (Array.isArray(relayUrls) ? relayUrls : [])
      .map((value) => (typeof value === 'string' ? value.trim() : ''))
      .filter(Boolean)
  ));
}

class WotGraph {
  constructor(rootPubkey) {
    this.rootPubkey = rootPubkey;
    this.nodes = new Map([
      [rootPubkey, { pubkey: rootPubkey, depth: 0, followedBy: new Set() }]
    ]);
  }

  addFollowEdge(authorPubkey, followedPubkey, depth) {
    let node = this.nodes.get(followedPubkey);
    if (!node) {
      node = {
        pubkey: followedPubkey,
        depth,
        followedBy: new Set([authorPubkey])
      };
      this.nodes.set(followedPubkey, node);
      return;
    }
    if (depth < node.depth) {
      node.depth = depth;
    }
    node.followedBy.add(authorPubkey);
  }

  getDistance(pubkey) {
    return this.nodes.get(pubkey)?.depth ?? null;
  }

  getNode(pubkey) {
    return this.nodes.get(pubkey) || null;
  }
}

function createTimeoutError(message) {
  const error = new Error(message);
  error.name = 'TimeoutError';
  return error;
}

async function fetchRelayContactLists(relayUrl, authors, timeoutMs, logger = null) {
  return new Promise((resolve) => {
    const events = [];
    const subId = `wot-${randomBytes(6).toString('hex')}`;
    let settled = false;
    let socket = null;

    const finish = ({ error = null } = {}) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        if (socket && socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify(['CLOSE', subId]));
        }
      } catch (_) {}
      try {
        socket?.close?.();
      } catch (_) {}
      resolve({ relayUrl, events, error });
    };

    const timer = setTimeout(() => {
      logger?.debug?.({
        relayUrl,
        authorCount: authors.length,
        timeoutMs
      }, '[PublicGateway] WoT relay fetch timed out');
      finish({ error: createTimeoutError(`wot-relay-timeout:${relayUrl}`) });
    }, timeoutMs);

    try {
      socket = new WebSocket(relayUrl, {
        handshakeTimeout: timeoutMs
      });
    } catch (error) {
      finish({ error });
      return;
    }

    socket.on('open', () => {
      try {
        socket.send(JSON.stringify([
          'REQ',
          subId,
          {
            kinds: [NOSTR_CONTACT_LIST_KIND],
            authors,
            limit: Math.min(MAX_CONTACT_LIST_EVENT_LIMIT, Math.max(authors.length * 8, authors.length))
          }
        ]));
      } catch (error) {
        finish({ error });
      }
    });

    socket.on('message', (raw) => {
      let parsed = null;
      try {
        parsed = JSON.parse(Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw));
      } catch (_) {
        return;
      }
      if (!Array.isArray(parsed) || parsed.length < 2) return;
      const [type, incomingSubId, payload] = parsed;
      if (incomingSubId !== subId) return;
      if (type === 'EVENT' && payload && typeof payload === 'object') {
        const pubkey = normalizeHexPubkey(payload.pubkey);
        if (!pubkey || !authors.includes(pubkey)) return;
        events.push(payload);
        return;
      }
      if (type === 'EOSE' || type === 'CLOSED') {
        finish();
      }
    });

    socket.on('error', (error) => {
      finish({ error });
    });

    socket.on('close', () => {
      finish();
    });
  });
}

async function fetchLatestContactListEvents({
  relayUrls,
  authors,
  timeoutMs,
  logger = null
} = {}) {
  const normalizedRelayUrls = normalizeRelayUrls(relayUrls);
  const normalizedAuthors = Array.from(new Set(
    (Array.isArray(authors) ? authors : [])
      .map((value) => normalizeHexPubkey(value))
      .filter(Boolean)
  ));
  if (!normalizedRelayUrls.length || !normalizedAuthors.length) {
    return new Map();
  }

  const perRelayTimeoutMs = Math.max(
    1_000,
    Math.min(Number(timeoutMs) || DEFAULT_FETCH_BATCH_TIMEOUT_MS, DEFAULT_FETCH_BATCH_TIMEOUT_MS)
  );

  const relayResults = await Promise.all(
    normalizedRelayUrls.map((relayUrl) => fetchRelayContactLists(
      relayUrl,
      normalizedAuthors,
      perRelayTimeoutMs,
      logger
    ))
  );

  const latest = new Map();
  for (const relayResult of relayResults) {
    for (const event of relayResult.events || []) {
      const pubkey = normalizeHexPubkey(event?.pubkey);
      if (!pubkey) continue;
      latest.set(pubkey, selectPreferredEvent(latest.get(pubkey), event));
    }
  }
  return latest;
}

export async function buildWotGraphFromRelays({
  rootPubkey,
  relayUrls,
  depth = 1,
  timeoutMs = 30_000,
  logger = null
} = {}) {
  const normalizedRootPubkey = normalizeHexPubkey(rootPubkey);
  if (!normalizedRootPubkey) {
    throw new Error('invalid-wot-root-pubkey');
  }
  const normalizedRelayUrls = normalizeRelayUrls(relayUrls);
  const graph = new WotGraph(normalizedRootPubkey);
  const maxDepth = Math.max(1, Math.trunc(Number(depth) || 1));
  const deadline = Date.now() + Math.max(1_000, Math.trunc(Number(timeoutMs) || 30_000));
  const processedUsers = new Set();

  for (let currentDepth = 0; currentDepth < maxDepth; currentDepth += 1) {
    const authors = Array.from(graph.nodes.values())
      .filter((node) => node.depth === currentDepth && !processedUsers.has(node.pubkey))
      .map((node) => node.pubkey);
    if (!authors.length) break;
    for (const author of authors) {
      processedUsers.add(author);
    }

    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) {
      logger?.debug?.({
        currentDepth,
        processedUsers: processedUsers.size
      }, '[PublicGateway] WoT graph load deadline reached');
      break;
    }

    const contactLists = await fetchLatestContactListEvents({
      relayUrls: normalizedRelayUrls,
      authors,
      timeoutMs: remainingMs,
      logger
    });

    for (const event of contactLists.values()) {
      const authorPubkey = normalizeHexPubkey(event?.pubkey);
      if (!authorPubkey) continue;
      const follows = extractFollowPubkeys(event);
      for (const followedPubkey of follows) {
        graph.addFollowEdge(authorPubkey, followedPubkey, currentDepth + 1);
      }
    }
  }

  return graph;
}
