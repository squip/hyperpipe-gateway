import { mkdir, readFile, rename, stat, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

const PUBKEY_LIST_FILE_VERSION = 1;

function normalizeHexPubkey(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim().toLowerCase();
  return /^[0-9a-f]{64}$/.test(trimmed) ? trimmed : null;
}

function normalizePubkeys(values = []) {
  return Array.from(new Set(
    (Array.isArray(values) ? values : [])
      .map((value) => normalizeHexPubkey(value))
      .filter(Boolean)
  )).sort();
}

function sanitizePath(value) {
  if (!value || typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : null;
}

function normalizeKind(value, fallback = 'pubkey-list') {
  const trimmed = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return /^[a-z0-9-]+$/.test(trimmed) ? trimmed : fallback;
}

function normalizeDisplayName(value, kind) {
  const trimmed = typeof value === 'string' ? value.trim() : '';
  return trimmed || `${kind.charAt(0).toUpperCase()}${kind.slice(1)}`;
}

function createRecord(pubkeys = [], { updatedAt = null, updatedBy = null } = {}) {
  const normalizedUpdatedAt = Number.isFinite(Number(updatedAt))
    ? Math.max(0, Math.trunc(Number(updatedAt)))
    : Date.now();
  return {
    version: PUBKEY_LIST_FILE_VERSION,
    updatedAt: normalizedUpdatedAt,
    updatedBy: normalizeHexPubkey(updatedBy),
    pubkeys: normalizePubkeys(pubkeys)
  };
}

export default class PubkeyListStore {
  constructor({
    filePath,
    refreshMs = 5000,
    bootstrapPubkeys = [],
    logger = null,
    kind = 'pubkey-list',
    displayName = null
  } = {}) {
    this.filePath = sanitizePath(filePath);
    this.refreshMs = Number.isFinite(Number(refreshMs))
      ? Math.max(0, Math.trunc(Number(refreshMs)))
      : 5000;
    this.bootstrapPubkeys = normalizePubkeys(bootstrapPubkeys);
    this.logger = logger;
    this.kind = normalizeKind(kind);
    this.displayName = normalizeDisplayName(displayName, this.kind);
    this.state = {
      pubkeys: new Set(),
      loadedAt: 0,
      checkedAt: 0,
      mtimeMs: null,
      size: null,
      updatedAt: null,
      updatedBy: null,
      source: 'file',
      lastError: null
    };
  }

  get enabled() {
    return !!this.filePath;
  }

  has(pubkey) {
    const normalized = normalizeHexPubkey(pubkey);
    return !!normalized && this.state.pubkeys.has(normalized);
  }

  snapshot() {
    const pubkeys = Array.from(this.state.pubkeys).sort();
    return {
      version: PUBKEY_LIST_FILE_VERSION,
      updatedAt: this.state.updatedAt ?? null,
      updatedBy: this.state.updatedBy ?? null,
      pubkeys,
      count: pubkeys.length,
      source: this.state.source || 'file',
      lastError: this.state.lastError || null
    };
  }

  async initialize() {
    if (!this.enabled) return this.snapshot();

    const loaded = await this.#loadFromDisk({ allowMissing: true });
    if (loaded.found && loaded.record) {
      this.#applyRecord(loaded.record, {
        mtimeMs: loaded.mtimeMs,
        size: loaded.size,
        source: 'file',
        lastError: null
      });
      return this.snapshot();
    }
    if (loaded.found && loaded.error) {
      this.#setEmpty({
        mtimeMs: loaded.mtimeMs,
        size: loaded.size,
        source: 'file',
        lastError: loaded.error
      });
      this.logger?.warn?.(`[PublicGateway] ${this.displayName} file invalid; using empty in-memory state`, {
        filePath: this.filePath,
        error: loaded.error
      });
      return this.snapshot();
    }

    if (this.bootstrapPubkeys.length > 0) {
      const record = createRecord(this.bootstrapPubkeys, { updatedAt: Date.now(), updatedBy: null });
      const persisted = await this.#writeRecord(record);
      this.#applyRecord(record, {
        mtimeMs: persisted.mtimeMs,
        size: persisted.size,
        source: 'env-bootstrap',
        lastError: null
      });
      return this.snapshot();
    }

    const record = createRecord([], { updatedAt: Date.now(), updatedBy: null });
    const persisted = await this.#writeRecord(record);
    this.#applyRecord(record, {
      mtimeMs: persisted.mtimeMs,
      size: persisted.size,
      source: 'file',
      lastError: null
    });
    return this.snapshot();
  }

  async ensureFresh({ force = false } = {}) {
    if (!this.enabled) return this.snapshot();
    const now = Date.now();
    if (!force && this.state.checkedAt && (now - this.state.checkedAt) < this.refreshMs) {
      return this.snapshot();
    }

    let stats;
    try {
      stats = await stat(this.filePath);
    } catch (error) {
      this.state.checkedAt = now;
      this.state.lastError = error?.code === 'ENOENT'
        ? `${this.kind}-file-missing`
        : (error?.message || String(error));
      this.logger?.warn?.(`[PublicGateway] ${this.displayName} refresh failed`, {
        filePath: this.filePath,
        error: this.state.lastError
      });
      return this.snapshot();
    }

    if (
      !force
      && this.state.mtimeMs !== null
      && Number(stats.mtimeMs) === Number(this.state.mtimeMs)
      && Number(stats.size) === Number(this.state.size)
    ) {
      this.state.checkedAt = now;
      return this.snapshot();
    }

    const loaded = await this.#loadFromDisk({ allowMissing: false, stats });
    if (!loaded.record) {
      this.state.checkedAt = now;
      this.state.mtimeMs = Number.isFinite(Number(loaded.mtimeMs)) ? Number(loaded.mtimeMs) : this.state.mtimeMs;
      this.state.size = Number.isFinite(Number(loaded.size)) ? Number(loaded.size) : this.state.size;
      this.state.lastError = loaded.error || `invalid-${this.kind}-file`;
      this.logger?.warn?.(`[PublicGateway] ${this.displayName} reload failed; keeping last good state`, {
        filePath: this.filePath,
        error: this.state.lastError
      });
      return this.snapshot();
    }

    this.#applyRecord(loaded.record, {
      mtimeMs: loaded.mtimeMs,
      size: loaded.size,
      source: 'file',
      lastError: null
    });
    return this.snapshot();
  }

  async replacePubkeys(pubkeys = [], { updatedBy = null } = {}) {
    if (!this.enabled) {
      throw new Error(`${this.kind}-store-disabled`);
    }
    const record = createRecord(pubkeys, {
      updatedAt: Date.now(),
      updatedBy
    });
    const persisted = await this.#writeRecord(record);
    this.#applyRecord(record, {
      mtimeMs: persisted.mtimeMs,
      size: persisted.size,
      source: 'file',
      lastError: null
    });
    return this.snapshot();
  }

  #applyRecord(record, {
    mtimeMs = null,
    size = null,
    source = 'file',
    lastError = null
  } = {}) {
    const now = Date.now();
    this.state = {
      pubkeys: new Set(record.pubkeys || []),
      loadedAt: now,
      checkedAt: now,
      mtimeMs: Number.isFinite(Number(mtimeMs)) ? Number(mtimeMs) : null,
      size: Number.isFinite(Number(size)) ? Number(size) : null,
      updatedAt: record.updatedAt ?? null,
      updatedBy: record.updatedBy ?? null,
      source,
      lastError
    };
  }

  #setEmpty({
    mtimeMs = null,
    size = null,
    source = 'file',
    lastError = null
  } = {}) {
    const now = Date.now();
    this.state = {
      pubkeys: new Set(),
      loadedAt: now,
      checkedAt: now,
      mtimeMs: Number.isFinite(Number(mtimeMs)) ? Number(mtimeMs) : null,
      size: Number.isFinite(Number(size)) ? Number(size) : null,
      updatedAt: null,
      updatedBy: null,
      source,
      lastError
    };
  }

  #parseRecord(raw) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new Error(`invalid-${this.kind}-file`);
    }
    if (Number(raw.version) !== PUBKEY_LIST_FILE_VERSION) {
      throw new Error(`unsupported-${this.kind}-version`);
    }
    if (!Array.isArray(raw.pubkeys)) {
      throw new Error(`invalid-${this.kind}-pubkeys`);
    }
    const normalized = [];
    for (const value of raw.pubkeys) {
      const pubkey = normalizeHexPubkey(value);
      if (!pubkey) {
        throw new Error(`invalid-${this.kind}-pubkey`);
      }
      normalized.push(pubkey);
    }
    return {
      version: PUBKEY_LIST_FILE_VERSION,
      updatedAt: Number.isFinite(Number(raw.updatedAt))
        ? Math.max(0, Math.trunc(Number(raw.updatedAt)))
        : null,
      updatedBy: normalizeHexPubkey(raw.updatedBy),
      pubkeys: normalizePubkeys(normalized)
    };
  }

  async #loadFromDisk({ allowMissing = false, stats = null } = {}) {
    try {
      const fileStats = stats || await stat(this.filePath);
      const raw = await readFile(this.filePath, 'utf8');
      const parsed = this.#parseRecord(JSON.parse(raw));
      return {
        found: true,
        record: parsed,
        mtimeMs: Number(fileStats.mtimeMs),
        size: Number(fileStats.size)
      };
    } catch (error) {
      if (allowMissing && error?.code === 'ENOENT') {
        return { found: false, record: null, mtimeMs: null, error: null };
      }
      return {
        found: true,
        record: null,
        mtimeMs: stats ? Number(stats.mtimeMs) : null,
        size: stats ? Number(stats.size) : null,
        error: error?.message || String(error)
      };
    }
  }

  async #writeRecord(record) {
    await mkdir(dirname(this.filePath), { recursive: true });
    const tempPath = `${this.filePath}.tmp`;
    const payload = JSON.stringify(record, null, 2);
    await writeFile(tempPath, `${payload}\n`, 'utf8');
    await rename(tempPath, this.filePath);
    const fileStats = await stat(this.filePath);
    return {
      mtimeMs: Number(fileStats.mtimeMs),
      size: Number(fileStats.size)
    };
  }
}
