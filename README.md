# Hyperpipe Gateway

`hyperpipe-gateway` is the public HTTPS/WebSocket edge service for Hyperpipe-hosted
relays. It consumes the published `@squip/hyperpipe-bridge` package and forwards
traffic through the same relay protocol used by `@squip/hyperpipe-core`.

It provides:

- public HTTPS and WebSocket ingress for remote relay access
- sponsor/member token issuance and verification
- optional allowlist, blocklist, and web-of-trust host authorization
- discovery publishing, health checks, metrics, and structured logging
- Docker-oriented deployment support

## Running the Gateway

### Local Development

```bash
cd hyperpipe-gateway
npm install
npm run dev # loads configuration from .env.local if present
```

By default the service listens on `4430` and expects signed registration payloads from the desktop worker. Use `GATEWAY_REGISTRATION_SECRET` to set the shared HMAC secret.

### Docker

The repository ships with a Dockerfile rooted at `hyperpipe-gateway/Dockerfile`.

```bash
# build from the repository root
docker build -f hyperpipe-gateway/Dockerfile -t hyperpipe/hyperpipe-gateway .

# run with TLS disabled, Redis-backed state, and WoT-based host authorization
docker run -p 4430:4430 \
  -e GATEWAY_PUBLIC_URL=https://gateway.example.com \
  -e GATEWAY_REGISTRATION_SECRET=replace-this \
  -e GATEWAY_REGISTRATION_REDIS=redis://redis:6379 \
  -e GATEWAY_DISCOVERY_ENABLED=true \
  -e GATEWAY_DISCOVERY_DISPLAY_NAME="Example Gateway" \
  -e GATEWAY_NOSTR_DISCOVERY_RELAYS="wss://relay.damus.io/,wss://relay.primal.net/,wss://nos.lol/" \
  -e GATEWAY_AUTH_HOST_POLICY=allowlist+wot \
  -e GATEWAY_AUTH_MEMBER_DELEGATION=all-members \
  -e GATEWAY_AUTH_OPERATOR_PUBKEY=<64-char-hex> \
  -e GATEWAY_AUTH_WOT_MAX_DEPTH=2 \
  -e GATEWAY_AUTH_WOT_MIN_FOLLOWERS_DEPTH2=2 \
  -e GATEWAY_AUTH_WOT_RELAYS="wss://relay.primal.net/,wss://nos.lol/" \
  -e GATEWAY_AUTH_WOT_LOAD_TIMEOUT_MS=12000 \
  -e GATEWAY_AUTH_ALLOWLIST_PUBKEYS=<64-char-hex>,<64-char-hex> \
  -e GATEWAY_AUTH_ALLOWLIST_FILE=/data/config/allowlist.json \
  -e GATEWAY_AUTH_ALLOWLIST_REFRESH_MS=5000 \
  -e GATEWAY_AUTH_BLOCKLIST_FILE=/data/config/blocklist.json \
  -e GATEWAY_AUTH_BLOCKLIST_REFRESH_MS=5000 \
  hyperpipe/hyperpipe-gateway
```

For container builds, install dependencies from npm before copying the runtime source. The gateway now consumes the published `@squip/hyperpipe-bridge` package and no longer expects a sibling Bridge workspace in the image context.

The gateway now defaults to relay-scoped bearer auth for restricted hosting. `GATEWAY_REGISTRATION_SECRET` is still required because the gateway signs and verifies sponsor/member tokens with that secret even when `GATEWAY_AUTH_HOST_POLICY` is not `open`.

WoT host checks default to the discovery relay list, but can now be isolated with `GATEWAY_AUTH_WOT_RELAYS`. Use that when you want a smaller or more reliable relay set for auth decisions than the one you advertise for discovery. `GATEWAY_AUTH_WOT_LOAD_TIMEOUT_MS` and `GATEWAY_AUTH_WOT_REFRESH_MS` let you tune how aggressively the gateway fetches and refreshes the cached WoT graph.

If you want to manage access lists live without restarting the container, set `GATEWAY_AUTH_ALLOWLIST_FILE` and/or `GATEWAY_AUTH_BLOCKLIST_FILE`. The gateway will hot-reload those files and expose an operator-only access manager at `/admin/allowlist`.

If you want approved clients to receive verified operator identity metadata without storing the operator `nsec` on the gateway host, generate an offline-signed attestation artifact and point `GATEWAY_AUTH_OPERATOR_ATTESTATION_FILE` at it. When attestation mode is enabled, the gateway stops advertising `operatorPubkey` in public discovery metadata and only returns the signed operator identity to already-approved clients through `/api/auth/verify`.

### Configuration Reference

| Environment Variable | Description |
| -------------------- | ----------- |
| `PORT` | HTTP/HTTPS bind port. Defaults to `4430`. |
| `GATEWAY_PUBLIC_URL` | External HTTPS base used when generating share links. |
| `GATEWAY_TLS_ENABLED` | Enables TLS when set to `true`. |
| `GATEWAY_TLS_KEY` | Path to the TLS private key when TLS is enabled. |
| `GATEWAY_TLS_CERT` | Path to the TLS certificate when TLS is enabled. |
| `GATEWAY_METRICS_ENABLED` | Enables the Prometheus-style metrics endpoint unless set to `false`. |
| `GATEWAY_METRICS_PATH` | Metrics path. Defaults to `/metrics`. |
| `GATEWAY_REGISTRATION_SECRET` | Shared HMAC secret used to issue and verify sponsor/member bearer tokens and legacy registration tokens. Required for restricted gateways. |
| `GATEWAY_REGISTRATION_REDIS` | Optional Redis connection string for distributed registration state. Falls back to in-memory cache when omitted or unavailable. |
| `GATEWAY_REGISTRATION_REDIS_PREFIX` | Namespace prefix for Redis keys. Defaults to `gateway:registrations:`. |
| `GATEWAY_REGISTRATION_TTL` | Relay registration TTL in seconds. Defaults to `1800`. |
| `GATEWAY_DEFAULT_TOKEN_TTL` | Default sponsor/member token lifetime in seconds. Defaults to `3600`. |
| `GATEWAY_TOKEN_REFRESH_WINDOW` | Default refresh window in seconds before token expiry. Defaults to `300`. |
| `GATEWAY_RATELIMIT_ENABLED` | Enables request rate limiting when set to `true`. |
| `GATEWAY_RATELIMIT_WINDOW` | Rate-limit window in seconds. Defaults to `60`. |
| `GATEWAY_RATELIMIT_MAX` | Max requests per window. Defaults to `120`. |
| `GATEWAY_DISCOVERY_ENABLED` | Enables gateway discovery announcements when set to `true`. |
| `GATEWAY_DISCOVERY_DISPLAY_NAME` | Human-readable gateway name advertised over discovery. |
| `GATEWAY_DISCOVERY_REGION` | Region label advertised over discovery. |
| `GATEWAY_DISCOVERY_KEY_SEED` | Stable seed used to derive the gateway discovery identity and gateway ID. Keep this persistent across restarts if you use operator attestation. |
| `GATEWAY_NOSTR_DISCOVERY_ENABLED` | Enables Nostr discovery publishing and subscription unless set to `false`. |
| `GATEWAY_NOSTR_DISCOVERY_RELAYS` | Comma-separated Nostr relay URLs used for gateway discovery publishing. Also used as the WoT relay fallback when `GATEWAY_AUTH_WOT_RELAYS` is unset. |
| `GATEWAY_AUTH_HOST_POLICY` | Host sponsorship policy: `open`, `allowlist`, `wot`, or `allowlist+wot`. |
| `GATEWAY_AUTH_MEMBER_DELEGATION` | Relay member delegation policy: `none`, `closed-members`, or `all-members`. |
| `GATEWAY_AUTH_OPERATOR_PUBKEY` | Operator pubkey in 64-character hex. Auto-approved for WoT checks and used as the expected signer for optional operator attestation. |
| `GATEWAY_AUTH_OPERATOR_ATTESTATION_FILE` | Optional JSON attestation artifact signed offline by the operator key. When set, successful `/api/auth/verify` responses may include `operatorIdentity`, and public discovery omits `operatorPubkey`. |
| `GATEWAY_AUTH_ALLOWLIST_PUBKEYS` | Comma-separated 64-character hex pubkeys approved for `allowlist` or `allowlist+wot`. |
| `GATEWAY_AUTH_ALLOWLIST_FILE` | Optional JSON file path for the live allowlist store. When set with `allowlist` or `allowlist+wot`, the gateway hot-reloads this file and exposes `/admin/allowlist`. |
| `GATEWAY_AUTH_ALLOWLIST_REFRESH_MS` | How often to re-stat the allowlist file before auth checks and admin reads. Defaults to `5000`. |
| `GATEWAY_AUTH_BLOCKLIST_PUBKEYS` | Optional comma-separated 64-character hex pubkeys denied across `open`, `allowlist`, `wot`, and `allowlist+wot`. |
| `GATEWAY_AUTH_BLOCKLIST_FILE` | Optional JSON file path for the live blocklist store. When set, `/admin/allowlist` can manage the Block List without restarting the container. |
| `GATEWAY_AUTH_BLOCKLIST_REFRESH_MS` | How often to re-stat the blocklist file before auth checks and admin reads. Defaults to `5000`. |
| `GATEWAY_AUTH_WOT_ROOT_PUBKEY` | Optional 64-character hex WoT root. Falls back to `GATEWAY_AUTH_OPERATOR_PUBKEY` when omitted. |
| `GATEWAY_AUTH_WOT_MAX_DEPTH` | Maximum allowed WoT distance from the root. Defaults to `1`. |
| `GATEWAY_AUTH_WOT_MIN_FOLLOWERS_DEPTH2` | Optional follower threshold applied only to depth-2 approvals. Defaults to `0`. |
| `GATEWAY_AUTH_WOT_RELAYS` | Optional comma-separated relay URLs used only for WoT contact-list loading. Falls back to `GATEWAY_NOSTR_DISCOVERY_RELAYS` when omitted. |
| `GATEWAY_AUTH_WOT_LOAD_TIMEOUT_MS` | Max time in milliseconds to spend building the cached WoT graph before failing closed. Defaults to `30000`. |
| `GATEWAY_AUTH_WOT_REFRESH_MS` | Cached WoT graph refresh interval in milliseconds. Defaults to `600000`. |
| `GATEWAY_AUTH_MAX_RELAYS_PER_SPONSOR` | Max relays a sponsored host may register. Defaults to `100`. |
| `GATEWAY_AUTH_MAX_MEMBERS_PER_RELAY` | Max relay member ACL rows per relay. Defaults to `500`. |
| `GATEWAY_AUTH_MAX_OPEN_JOIN_POOL` | Max open-join pool entries per relay. Defaults to `100`. |
| `GATEWAY_AUTH_MAX_MIRRORED_BYTES_PER_RELAY` | Optional mirrored-byte quota per relay. `0` disables the quota. |
| `GATEWAY_FEATURE_HYPERBEE_RELAY` | Enables the embedded gateway relay runtime when set to `true`. |
| `GATEWAY_RELAY_STORAGE` | Filesystem path for relay storage. |
| `GATEWAY_RELAY_SEED` | Optional legacy 64-character seed. When present, the gateway derives the real Hypercore relay keypair from it at startup. |
| `GATEWAY_RELAY_ADMIN_PUBLIC_KEY` | 64-character hex relay admin pubkey. Ignored when only a legacy 64-character seed is provided. |
| `GATEWAY_RELAY_ADMIN_SECRET_KEY` | Preferred 128-character hex Hypercore relay admin secret key. A legacy 64-character seed is also accepted for backward compatibility. |
| `GATEWAY_RELAY_NAMESPACE` | Dataset namespace for the embedded relay. Defaults to `public-gateway-relay`. |

### WoT Notes

- Use raw 64-character hex pubkeys for all auth env vars. `npub` values are not accepted by the current config normalizer.
- `GATEWAY_AUTH_HOST_POLICY=wot` means only WoT-approved pubkeys may sponsor new relays on the gateway.
- `GATEWAY_AUTH_HOST_POLICY=allowlist+wot` means a pubkey may sponsor a relay if it is either explicitly allowlisted or passes WoT.
- `GATEWAY_AUTH_MEMBER_DELEGATION=all-members` is the setting that preserves offline join parity for sponsored relays, because it lets trusted relay sponsors delegate relay-scoped mirror access to their members.
- The current WoT implementation uses a bounded relay fetcher that loads the latest kind `3` contact lists for the configured root and its reachable follow graph, then evaluates trust from that root outward by depth. Depth-2 approvals can optionally require multiple in-graph followers via `GATEWAY_AUTH_WOT_MIN_FOLLOWERS_DEPTH2`.
- If one discovery relay is slow or unreliable, prefer setting `GATEWAY_AUTH_WOT_RELAYS` to a smaller dedicated relay set rather than coupling auth to every discovery relay.

### Suggested Policies

- Tight private gateway:
  - `GATEWAY_AUTH_HOST_POLICY=allowlist+wot`
  - `GATEWAY_AUTH_WOT_MAX_DEPTH=1`
  - `GATEWAY_AUTH_MEMBER_DELEGATION=closed-members`
- Hobby/community gateway:
  - `GATEWAY_AUTH_HOST_POLICY=wot`
  - `GATEWAY_AUTH_WOT_MAX_DEPTH=2`
  - `GATEWAY_AUTH_WOT_MIN_FOLLOWERS_DEPTH2=2`
  - `GATEWAY_AUTH_MEMBER_DELEGATION=all-members`

### Access Manager

- Live Allow List management is opt-in. Set `GATEWAY_AUTH_ALLOWLIST_FILE=/data/config/allowlist.json` and use `GATEWAY_AUTH_HOST_POLICY=allowlist` or `allowlist+wot`.
- Live Block List management is opt-in. Set `GATEWAY_AUTH_BLOCKLIST_FILE=/data/config/blocklist.json`. Blocklisted pubkeys are denied across every host policy, including `open`.
- Verified operator identity is opt-in. Generate an offline attestation artifact and set `GATEWAY_AUTH_OPERATOR_ATTESTATION_FILE=/app/public-gateway/artifacts/operator-attestation.json`.
- The file format is:

```json
{
  "version": 1,
  "updatedAt": 1770000000000,
  "updatedBy": "64-char-hex-pubkey",
  "pubkeys": [
    "64-char-hex-pubkey"
  ]
}
```

- The gateway normalizes `pubkeys` to lowercase, unique, sorted 64-character hex strings.
- If the file is missing on first boot and the matching env list is non-empty, the gateway seeds the file from the env value once and then continues from the file.
- The operator access manager lives at `/admin/allowlist`.
- Admin auth is operator-only and uses a signed kind `22242` auth event with purpose `gateway:allowlist-admin`.
- Admin bearer tokens are short-lived, in-memory only, and scoped to access-list editing.
- The page exposes user-friendly tabs for **Allow List**, **Web of Trust**, and **Block List** when those features are enabled. It also uses the configured discovery relays to fetch kind `0` profile metadata for displayed pubkeys.

### Testing

```bash
cd hyperpipe-gateway
npm test
```

This runs lightweight unit tests for token helpers and the in-memory registration store using Node's built-in test runner.
