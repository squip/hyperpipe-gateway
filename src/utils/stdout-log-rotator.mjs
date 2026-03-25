import { createWriteStream } from 'node:fs';
import { mkdir, readdir, stat, unlink } from 'node:fs/promises';
import { join } from 'node:path';

function toInt(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  const num = Number(value);
  return Number.isFinite(num) && num > 0 ? Math.trunc(num) : fallback;
}

function formatStamp(ts = Date.now()) {
  const d = new Date(ts);
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, '0');
  const day = String(d.getUTCDate()).padStart(2, '0');
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mm = String(d.getUTCMinutes()).padStart(2, '0');
  const ss = String(d.getUTCSeconds()).padStart(2, '0');
  return `${y}${m}${day}-${hh}${mm}${ss}Z`;
}

async function pruneLogs({ logDir, prefix, retentionMs }) {
  if (!Number.isFinite(retentionMs) || retentionMs <= 0) return;
  let entries = [];
  try {
    entries = await readdir(logDir);
  } catch {
    return;
  }
  const now = Date.now();
  const candidates = entries.filter((name) => name.startsWith(`${prefix}-`) && name.endsWith('.log'));
  await Promise.all(candidates.map(async (name) => {
    const path = join(logDir, name);
    try {
      const info = await stat(path);
      if ((now - info.mtimeMs) > retentionMs) {
        await unlink(path);
      }
    } catch {
      // Ignore file-system races and permission issues.
    }
  }));
}

export function installStdoutLogRotation({
  logDir = null,
  rotateMs = null,
  retentionMs = null,
  prefix = null
} = {}) {
  const baseDir = typeof logDir === 'string' ? logDir.trim() : '';
  if (!baseDir) return;

  const rotateEveryMs = toInt(rotateMs, 24 * 60 * 60 * 1000);
  const keepForMs = toInt(retentionMs, 7 * 24 * 60 * 60 * 1000);
  const filePrefix = (typeof prefix === 'string' && prefix.trim()) ? prefix.trim() : 'public-gateway';
  const maxBufferedChunks = 5000;

  let stream = null;
  let streamOpenedAt = 0;
  let initialized = false;
  let initPromise = null;
  let writeHookInstalled = false;
  let timer = null;
  let pendingChunks = [];

  const openStream = async () => {
    await mkdir(baseDir, { recursive: true });
    const path = join(baseDir, `${filePrefix}-${formatStamp()}.log`);
    const next = createWriteStream(path, { flags: 'a' });
    stream = next;
    streamOpenedAt = Date.now();
    await pruneLogs({ logDir: baseDir, prefix: filePrefix, retentionMs: keepForMs });
  };

  const ensureReady = async () => {
    if (initialized && stream) return;
    if (!initPromise) {
      initPromise = (async () => {
        await openStream();
        initialized = true;
        if (pendingChunks.length && stream) {
          const buffered = pendingChunks;
          pendingChunks = [];
          for (const chunk of buffered) {
            try {
              stream.write(chunk);
            } catch {
              // Ignore logging failures to avoid impacting runtime.
            }
          }
        }
      })().catch(() => {
        initialized = false;
      }).finally(() => {
        initPromise = null;
      });
    }
    await initPromise;
  };

  const maybeRotate = async () => {
    if (!stream || !Number.isFinite(rotateEveryMs) || rotateEveryMs <= 0) return;
    if ((Date.now() - streamOpenedAt) < rotateEveryMs) return;
    try {
      stream.end();
    } catch {
      // Ignore.
    }
    await openStream();
  };

  const tee = (chunk) => {
    if (!chunk) return;
    if (!stream) {
      if (pendingChunks.length >= maxBufferedChunks) pendingChunks.shift();
      pendingChunks.push(chunk);
      ensureReady().catch(() => {});
      return;
    }
    try {
      if (typeof chunk === 'string') {
        stream.write(chunk);
      } else if (chunk) {
        stream.write(chunk);
      }
    } catch {
      // Ignore logging failures to avoid impacting runtime.
    }
  };

  if (!writeHookInstalled) {
    const stdoutWrite = process.stdout.write.bind(process.stdout);
    const stderrWrite = process.stderr.write.bind(process.stderr);

    process.stdout.write = function patchedStdout(chunk, encoding, cb) {
      tee(chunk);
      return stdoutWrite(chunk, encoding, cb);
    };
    process.stderr.write = function patchedStderr(chunk, encoding, cb) {
      tee(chunk);
      return stderrWrite(chunk, encoding, cb);
    };
    writeHookInstalled = true;
  }

  ensureReady().catch(() => {});

  timer = setInterval(() => {
    maybeRotate().catch(() => {});
  }, Math.max(1000, Math.min(rotateEveryMs, 60 * 1000)));
  timer.unref?.();

  const shutdown = () => {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    if (stream) {
      try {
        stream.end();
      } catch {
        // Ignore.
      }
      stream = null;
    }
  };

  process.once('beforeExit', shutdown);
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
}
