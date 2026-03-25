#!/usr/bin/env node

import process from 'node:process';
import { URL } from 'node:url';
import yargs from 'yargs/yargs';
import { hideBin } from 'yargs/helpers';

async function main() {
  const argv = yargs(hideBin(process.argv))
    .option('url', {
      alias: 'u',
      type: 'string',
      describe: 'Blind peer status endpoint URL',
      default: process.env.BLIND_PEER_STATUS_URL || 'http://127.0.0.1:4430/api/blind-peer'
    })
    .option('detail', {
      alias: 'd',
      type: 'boolean',
      describe: 'Include ownership detail (owners + cores)',
      default: parseBooleanEnv(process.env.BLIND_PEER_STATUS_DETAIL, false)
    })
    .option('owners', {
      type: 'number',
      describe: 'Maximum owners to include when detail=true',
      default: parseNumericEnv(process.env.BLIND_PEER_STATUS_OWNERS, undefined)
    })
    .option('cores-per-owner', {
      type: 'number',
      describe: 'Maximum core entries per owner when detail=true',
      default: parseNumericEnv(process.env.BLIND_PEER_STATUS_CORES_PER_OWNER, undefined)
    })
    .option('gc', {
      type: 'boolean',
      describe: 'Trigger blind-peer hygiene/GC run',
      default: false
    })
    .option('delete-core', {
      type: 'string',
      describe: 'Delete a mirrored core by key'
    })
    .option('reason', {
      type: 'string',
      describe: 'Optional reason to include when triggering admin actions'
    })
    .option('raw', {
      alias: 'r',
      type: 'boolean',
      describe: 'Print raw response body (no pretty JSON formatting)',
      default: false
    })
    .help()
    .alias('help', 'h')
    .parse();

  const target = new URL(argv.url);
  const originBase = `${target.protocol}//${target.host}`;

  if (argv.gc) {
    try {
      const gcUrl = new URL('/api/blind-peer/gc', originBase);
      const response = await fetch(gcUrl, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json'
        },
        body: JSON.stringify({ reason: argv.reason || 'manual-cli' })
      });
      if (!response.ok) {
        const body = await safeReadBody(response);
        throw new Error(`Request failed (${response.status} ${response.statusText})${body ? `: ${body}` : ''}`);
      }
      const payload = await response.json();
      if (argv.raw) {
        process.stdout.write(`${JSON.stringify(payload)}\n`);
      } else {
        process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
      }
      return;
    } catch (error) {
      process.stderr.write(`[blind-peer-status] ${error?.message || error}\n`);
      process.exitCode = 1;
      return;
    }
  }

  if (argv['delete-core']) {
    try {
      const deleteUrl = new URL(`/api/blind-peer/mirrors/${encodeURIComponent(argv['delete-core'])}`, originBase);
      if (argv.reason) {
        deleteUrl.searchParams.set('reason', argv.reason);
      }
      const response = await fetch(deleteUrl, {
        method: 'DELETE',
        headers: {
          accept: 'application/json'
        }
      });
      if (!response.ok) {
        const body = await safeReadBody(response);
        throw new Error(`Request failed (${response.status} ${response.statusText})${body ? `: ${body}` : ''}`);
      }
      const payload = await response.json();
      if (argv.raw) {
        process.stdout.write(`${JSON.stringify(payload)}\n`);
      } else {
        process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
      }
      return;
    } catch (error) {
      process.stderr.write(`[blind-peer-status] ${error?.message || error}\n`);
      process.exitCode = 1;
      return;
    }
  }

  if (argv.detail) {
    target.searchParams.set('detail', 'true');
    if (typeof argv.owners === 'number' && Number.isFinite(argv.owners) && argv.owners > 0) {
      target.searchParams.set('owners', String(Math.trunc(argv.owners)));
    }
    if (typeof argv['cores-per-owner'] === 'number' && Number.isFinite(argv['cores-per-owner']) && argv['cores-per-owner'] > 0) {
      target.searchParams.set('coresPerOwner', String(Math.trunc(argv['cores-per-owner'])));
    }
  }

  try {
    const response = await fetch(target);
    if (!response.ok) {
      const body = await safeReadBody(response);
      throw new Error(`Request failed (${response.status} ${response.statusText})${body ? `: ${body}` : ''}`);
    }
    const payload = await response.json();
    if (argv.raw) {
      process.stdout.write(JSON.stringify(payload));
    } else {
      process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
    }
  } catch (error) {
    process.stderr.write(`[blind-peer-status] ${error?.message || error}\n`);
    process.exitCode = 1;
  }
}

function parseBooleanEnv(value, fallback) {
  if (value === undefined || value === null) return fallback;
  const normalized = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return fallback;
}

function parseNumericEnv(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

async function safeReadBody(response) {
  try {
    const text = await response.text();
    return text ? text.slice(0, 512) : '';
  } catch (_) {
    return '';
  }
}

main().catch((error) => {
  process.stderr.write(`[blind-peer-status] ${error?.message || error}\n`);
  process.exitCode = 1;
});
