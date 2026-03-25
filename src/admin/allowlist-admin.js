import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';

const root = document.querySelector('#allowlist-admin-root');
const configNode = document.querySelector('#access-manager-config');

if (!root) {
  throw new Error('Access manager root element is missing.');
}

if (!configNode) {
  throw new Error('Access manager config is missing.');
}

const config = parseConfig(configNode.textContent || '{}');
const TAB_LABELS = {
  allowlist: 'Allow List',
  wot: 'Web of Trust',
  blocklist: 'Block List'
};
const PROFILE_TIMEOUT_MS = 4500;
const AUTOSAVE_DELAY_MS = 600;
const INITIAL_ACTIVE_TAB = firstEnabledTabForConfig(config);

const state = {
  token: null,
  tokenExpiresAt: null,
  authBusy: false,
  signerState: detectSignerState(),
  operatorInput: normalizePubkey(config.operatorPubkey) || '',
  privateKeyInput: '',
  authPanelOpen: true,
  navOpen: false,
  activeTab: INITIAL_ACTIVE_TAB,
  banner: null,
  modal: {
    open: false,
    kind: null,
    inputValue: ''
  },
  allowlist: createListState(config.allowlistEnabled),
  blocklist: createListState(config.blocklistEnabled),
  wot: {
    enabled: !!config.wotEnabled,
    loading: false,
    loaded: false,
    entries: [],
    meta: {
      rootPubkey: null,
      maxDepth: null,
      minFollowersDepth2: null,
      loadedAt: null,
      expiresAt: null,
      relayUrls: [],
      lastError: null
    }
  },
  profileCache: new Map()
};

renderShell();
bindEvents();
render();

function parseConfig(raw) {
  try {
    const parsed = JSON.parse(raw || '{}');
    return {
      operatorPubkey: normalizePubkey(parsed.operatorPubkey) || '',
      relay: typeof parsed.relay === 'string' ? parsed.relay.trim() : '',
      purpose: typeof parsed.purpose === 'string' && parsed.purpose.trim()
        ? parsed.purpose.trim()
        : 'gateway:allowlist-admin',
      hostPolicy: typeof parsed.hostPolicy === 'string' ? parsed.hostPolicy.trim().toLowerCase() : 'open',
      allowlistEnabled: parsed.allowlistEnabled === true,
      blocklistEnabled: parsed.blocklistEnabled === true,
      wotEnabled: parsed.wotEnabled === true,
      discoveryRelayUrls: Array.from(new Set(
        (Array.isArray(parsed.discoveryRelayUrls) ? parsed.discoveryRelayUrls : [])
          .map((value) => (typeof value === 'string' ? value.trim() : ''))
          .filter(Boolean)
      ))
    };
  } catch (error) {
    throw new Error(`Invalid access manager config: ${error?.message || error}`);
  }
}

function createListState(enabled) {
  return {
    enabled: !!enabled,
    loading: false,
    saving: false,
    saveState: 'idle',
    saveError: null,
    saveTimer: null,
    draftPubkeys: [],
    serverPubkeys: [],
    meta: {
      source: null,
      updatedAt: null,
      updatedBy: null,
      lastError: null
    }
  };
}

function normalizePubkey(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toLowerCase();
  return /^[0-9a-f]{64}$/.test(normalized) ? normalized : null;
}

function normalizePrivateKey(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toLowerCase();
  return /^[0-9a-f]{64}$/.test(normalized) ? normalized : null;
}

function normalizeImageUrl(value) {
  const text = typeof value === 'string' ? value.trim() : '';
  if (!text) return null;
  if (text.startsWith('data:')) return text;
  try {
    const parsed = new URL(text);
    return parsed.protocol === 'https:' ? parsed.toString() : null;
  } catch {
    return null;
  }
}

function normalizeProfilePayload(value = {}) {
  const displayName = [
    value.display_name,
    value.displayName,
    value.name,
    value.nip05
  ].find((entry) => typeof entry === 'string' && entry.trim());
  const subtitle = [
    value.nip05,
    value.name && displayName !== value.name ? value.name : null,
    value.about
  ].find((entry) => typeof entry === 'string' && entry.trim());
  return {
    displayName: displayName ? displayName.trim() : null,
    subtitle: subtitle ? subtitle.trim() : null,
    picture: normalizeImageUrl(value.picture || value.image || value.avatar || ''),
    about: typeof value.about === 'string' && value.about.trim() ? value.about.trim() : null
  };
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function uniqueSortedPubkeys(values = []) {
  return Array.from(new Set(
    (Array.isArray(values) ? values : [])
      .map((value) => normalizePubkey(value))
      .filter(Boolean)
  )).sort();
}

function shortPubkey(pubkey) {
  return typeof pubkey === 'string' && pubkey.length >= 16
    ? `${pubkey.slice(0, 8)}…${pubkey.slice(-8)}`
    : pubkey;
}

function countLabel(count, noun = 'pubkey') {
  return `${count} ${count === 1 ? noun : `${noun}s`}`;
}

function formatTimestamp(timestamp) {
  if (!Number.isFinite(Number(timestamp))) return 'Never';
  try {
    return new Date(Number(timestamp)).toLocaleString();
  } catch (_) {
    return 'Unknown';
  }
}

function detectSignerState() {
  const signer = window.nostr;
  if (signer && typeof signer.signEvent === 'function') {
    return 'ready';
  }
  return 'missing';
}

function firstEnabledTabForConfig(currentConfig) {
  if (currentConfig.allowlistEnabled) return 'allowlist';
  if (currentConfig.wotEnabled) return 'wot';
  if (currentConfig.blocklistEnabled) return 'blocklist';
  return 'allowlist';
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function getEnabledTabs() {
  const tabs = [];
  if (state.allowlist.enabled) tabs.push({ key: 'allowlist', label: TAB_LABELS.allowlist });
  if (state.wot.enabled) tabs.push({ key: 'wot', label: TAB_LABELS.wot });
  if (state.blocklist.enabled) tabs.push({ key: 'blocklist', label: TAB_LABELS.blocklist });
  return tabs;
}

function humanizeSource(source) {
  if (!source) return null;
  if (source === 'env-bootstrap') return 'Env bootstrap';
  if (source === 'file') return 'File';
  return source;
}

function setBanner(message, tone = 'info') {
  if (!message) {
    state.banner = null;
    renderBanner();
    return;
  }
  state.banner = { message, tone };
  renderBanner();
}

function getProfile(pubkey) {
  return state.profileCache.get(pubkey) || null;
}

function setProfile(pubkey, value) {
  state.profileCache.set(pubkey, value);
}

function listStateFor(kind) {
  if (kind === 'allowlist') return state.allowlist;
  if (kind === 'blocklist') return state.blocklist;
  return null;
}

function isDirty(kind) {
  const current = listStateFor(kind);
  return isDirtyState(current);
}

function isDirtyState(current) {
  if (!current) return false;
  return JSON.stringify(current.draftPubkeys) !== JSON.stringify(current.serverPubkeys);
}

function activeTabPubkeys() {
  if (state.activeTab === 'allowlist') return state.allowlist.draftPubkeys;
  if (state.activeTab === 'blocklist') return state.blocklist.draftPubkeys;
  if (state.activeTab === 'wot') return state.wot.entries.map((entry) => entry.pubkey);
  return [];
}

function saveStatusLabel(current) {
  if (!current) return '';
  if (current.loading) return 'Refreshing…';
  if (current.saving) return 'Saving…';
  if (current.saveState === 'error') return 'Save failed';
  if (isDirtyState(current)) return 'Syncing…';
  if (current.saveState === 'saved') return 'Saved';
  return '';
}

function tabCount(key) {
  if (key === 'allowlist') return state.allowlist.draftPubkeys.length;
  if (key === 'blocklist') return state.blocklist.draftPubkeys.length;
  if (key === 'wot') return state.wot.entries.length;
  return 0;
}

function openAddModal(kind) {
  if (!listStateFor(kind)?.enabled) return;
  state.modal = {
    open: true,
    kind,
    inputValue: ''
  };
  renderModal();
  requestAnimationFrame(() => {
    root.querySelector('#modal-pubkey-input')?.focus();
  });
}

function closeAddModal() {
  state.modal = {
    open: false,
    kind: null,
    inputValue: ''
  };
  renderModal();
}

function renderInlineMeta(parts) {
  const items = parts.filter(Boolean);
  if (!items.length) return '';
  return `
    <div class="inline-meta">
      ${items.map((item) => `<span>${escapeHtml(item)}</span>`).join('')}
    </div>
  `;
}

function renderShell() {
  root.innerHTML = `
    <div class="access-app">
      <div id="nav-backdrop" class="nav-backdrop" data-action="close-nav"></div>
      <aside id="sidebar-region"></aside>
      <main class="access-main">
        <header id="topbar-region"></header>
        <div id="status-banner" class="status-banner"></div>
        <section id="auth-panel"></section>
        <section id="content-region"></section>
      </main>
      <div id="modal-region"></div>
    </div>
  `;
}

function bindEvents() {
  root.addEventListener('click', handleClick);
  root.addEventListener('input', handleInput);
  root.addEventListener('keydown', handleKeyDown);
}

function handleClick(event) {
  const target = event.target.closest('[data-action]');
  if (!target) return;
  const action = target.dataset.action;

  if (action === 'toggle-nav') {
    state.navOpen = !state.navOpen;
    renderSidebar();
    return;
  }
  if (action === 'close-nav') {
    state.navOpen = false;
    renderSidebar();
    return;
  }
  if (action === 'toggle-auth-panel') {
    state.authPanelOpen = !state.authPanelOpen;
    renderAuthPanel();
    renderTopbar();
    renderSidebar();
    return;
  }
  if (action === 'sign-out') {
    clearAllSaveTimers();
    state.token = null;
    state.tokenExpiresAt = null;
    state.authPanelOpen = true;
    setBanner(null);
    render();
    return;
  }
  if (action === 'authenticate-signer') {
    void authenticateWithSigner();
    return;
  }
  if (action === 'authenticate-private-key') {
    void authenticateWithPrivateKey();
    return;
  }
  if (action === 'clear-private-key') {
    state.privateKeyInput = '';
    renderAuthPanel();
    return;
  }
  if (action === 'switch-tab') {
    const tab = target.dataset.tab;
    if (tab && tab !== state.activeTab) {
      state.activeTab = tab;
      state.navOpen = false;
      render();
      void ensureProfilesLoaded(activeTabPubkeys());
    }
    return;
  }
  if (action === 'reload-list') {
    const kind = target.dataset.list;
    if (kind) {
      void loadList(kind);
    }
    return;
  }
  if (action === 'reload-wot') {
    void loadWot();
    return;
  }
  if (action === 'open-add-modal') {
    const kind = target.dataset.list;
    if (kind) {
      openAddModal(kind);
    }
    return;
  }
  if (action === 'close-modal') {
    closeAddModal();
    return;
  }
  if (action === 'submit-add-modal') {
    submitModalPubkey();
    return;
  }
  if (action === 'remove-pubkey') {
    const kind = target.dataset.list;
    const pubkey = target.dataset.pubkey;
    if (kind && pubkey) {
      removeDraftPubkey(kind, pubkey);
    }
    return;
  }
  if (action === 'copy-pubkey') {
    const pubkey = target.dataset.pubkey;
    if (pubkey) {
      navigator.clipboard.writeText(pubkey).then(() => {
        const original = target.textContent;
        target.textContent = 'Copied!';
        target.classList.add('is-copied');
        setTimeout(() => {
          target.textContent = original;
          target.classList.remove('is-copied');
        }, 1200);
      }).catch(() => {});
    }
    return;
  }
  if (action === 'queue-block') {
    const pubkey = normalizePubkey(target.dataset.pubkey);
    if (pubkey) {
      queuePubkeyForBlocklist(pubkey);
    }
  }
}

function handleInput(event) {
  const target = event.target;
  if (!(target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement)) return;

  if (target.id === 'operator-pubkey-input') {
    state.operatorInput = target.value.trim().toLowerCase();
    return;
  }
  if (target.id === 'private-key-input') {
    state.privateKeyInput = target.value.trim().toLowerCase();
    return;
  }
  if (target.id === 'modal-pubkey-input') {
    state.modal.inputValue = target.value.trim().toLowerCase();
  }
}

function handleKeyDown(event) {
  const target = event.target;
  if (!(target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement)) {
    if (event.key === 'Escape' && state.modal.open) {
      closeAddModal();
    }
    return;
  }

  if (event.key === 'Escape' && state.modal.open) {
    closeAddModal();
    return;
  }

  if (target.id === 'modal-pubkey-input' && event.key === 'Enter') {
    event.preventDefault();
    submitModalPubkey();
  }
}

function render() {
  renderSidebar();
  renderTopbar();
  renderBanner();
  renderAuthPanel();
  renderContent();
  renderModal();
  if (state.token) {
    void ensureProfilesLoaded(activeTabPubkeys());
  }
}

function renderSidebar() {
  const region = root.querySelector('#sidebar-region');
  const backdrop = root.querySelector('#nav-backdrop');
  if (!region || !backdrop) return;
  const authenticated = !!state.token;
  const tabs = getEnabledTabs();
  region.className = `access-sidebar${state.navOpen ? ' is-open' : ''}`;
  backdrop.className = `nav-backdrop${state.navOpen ? ' is-visible' : ''}`;
  region.innerHTML = `
    <div class="sidebar__header">
      <button class="icon-button sidebar__close" type="button" data-action="close-nav" aria-label="Close navigation">×</button>
      <p class="eyebrow">Public Gateway</p>
      <h1>Access Manager</h1>
    </div>
    <nav class="sidebar__nav" aria-label="Access manager lists">
      ${tabs.map((tab) => `
        <button
          class="nav-item${tab.key === state.activeTab ? ' is-active' : ''}"
          type="button"
          data-action="switch-tab"
          data-tab="${tab.key}"
        >
          <span>${escapeHtml(tab.label)}</span>
          <span class="nav-item__meta">${escapeHtml(String(tabCount(tab.key)))}</span>
        </button>
      `).join('')}
    </nav>
    <div class="sidebar__footer">
      <div class="sidebar__status">
        <span class="signer-status" data-state="${state.signerState}">
          ${state.signerState === 'ready' ? 'Browser signer detected' : 'Browser signer unavailable'}
        </span>
        ${authenticated ? '<span class="session-pill">Session active</span>' : '<span class="sidebar__muted">Authenticate as the operator</span>'}
      </div>
      <button class="button-ghost sidebar__session-button" type="button" data-action="toggle-auth-panel">
        ${authenticated ? 'Session' : 'Authenticate'}
      </button>
    </div>
  `;
}

function renderTopbar() {
  const region = root.querySelector('#topbar-region');
  if (!region) return;
  const authenticated = !!state.token;
  region.className = 'access-topbar';
  region.innerHTML = `
    <div class="topbar__leading">
      <button class="icon-button topbar__menu" type="button" data-action="toggle-nav" aria-label="Open navigation">☰</button>
      <div class="topbar__titles">
        <p class="eyebrow">Public Gateway</p>
        <h2>Access Manager</h2>
      </div>
    </div>
    <div class="topbar__actions">
      ${authenticated ? '<span class="session-pill session-pill--subtle">Operator</span>' : ''}
      <button class="button-ghost" type="button" data-action="toggle-auth-panel">
        ${authenticated ? 'Session' : 'Authenticate'}
      </button>
    </div>
  `;
}

function renderBanner() {
  const banner = root.querySelector('#status-banner');
  if (!banner) return;
  if (!state.banner?.message) {
    banner.textContent = '';
    banner.removeAttribute('data-tone');
    banner.style.display = 'none';
    return;
  }
  banner.textContent = state.banner.message;
  banner.dataset.tone = state.banner.tone || 'info';
  banner.style.display = 'block';
}

function renderAuthPanel() {
  const panel = root.querySelector('#auth-panel');
  if (!panel) return;
  if (!state.authPanelOpen) {
    panel.innerHTML = '';
    panel.className = 'auth-panel hidden';
    return;
  }
  const authenticated = !!state.token;
  panel.className = 'auth-panel';
  panel.innerHTML = authenticated ? renderSessionCard() : renderAuthenticationCard();
}

function renderAuthenticationCard() {
  return `
    <section class="gateway-card session-card">
      <div class="session-card__header">
        <div>
          <h3>Authenticate</h3>
          <p class="muted">Use the configured operator identity. Admin tokens stay in browser memory only and expire automatically.</p>
        </div>
      </div>
      <div class="session-grid">
        <label>
          Operator pubkey
          <input id="operator-pubkey-input" type="text" autocomplete="off" spellcheck="false" value="${escapeHtml(state.operatorInput)}">
        </label>
        <div class="session-meta">
          <div class="session-meta__row"><span>Gateway policy</span><span>${escapeHtml(config.hostPolicy)}</span></div>
          <div class="session-meta__row"><span>Session</span><span>Not authenticated</span></div>
        </div>
      </div>
      <div class="button-row button-row--inline">
        <button class="button-primary" type="button" data-action="authenticate-signer" ${state.authBusy || state.signerState !== 'ready' ? 'disabled' : ''}>
          ${state.authBusy ? 'Authenticating…' : 'Authenticate with signer'}
        </button>
      </div>
      <details class="advanced-panel"${state.privateKeyInput ? ' open' : ''}>
        <summary>Advanced fallback</summary>
        <div class="field-stack">
          <label>
            Operator private key
            <textarea id="private-key-input" rows="3" autocomplete="off" spellcheck="false" placeholder="64-char hex private key">${escapeHtml(state.privateKeyInput)}</textarea>
          </label>
          <div class="button-row button-row--inline">
            <button class="button-secondary" type="button" data-action="authenticate-private-key" ${state.authBusy ? 'disabled' : ''}>Authenticate with private key</button>
            <button class="button-ghost" type="button" data-action="clear-private-key">Clear</button>
          </div>
        </div>
      </details>
    </section>
  `;
}

function renderSessionCard() {
  return `
    <section class="gateway-card session-card session-card--active">
      <div class="session-card__header">
        <div>
          <h3>Session</h3>
          <p class="muted">Operator access is active until ${escapeHtml(formatTimestamp(state.tokenExpiresAt))}.</p>
        </div>
        <div class="button-row button-row--inline">
          <button class="button-ghost" type="button" data-action="toggle-auth-panel">Close</button>
          <button class="button-ghost" type="button" data-action="sign-out">Sign out</button>
        </div>
      </div>
      <div class="session-grid">
        <div class="session-meta">
          <div class="session-meta__row"><span>Operator</span><code>${escapeHtml(shortPubkey(config.operatorPubkey || 'Unknown'))}</code></div>
          <div class="session-meta__row"><span>Gateway policy</span><span>${escapeHtml(config.hostPolicy)}</span></div>
        </div>
        <div class="session-meta">
          <div class="session-meta__row"><span>Session expires</span><span>${escapeHtml(formatTimestamp(state.tokenExpiresAt))}</span></div>
          <div class="session-meta__row"><span>Browser signer</span><span>${state.signerState === 'ready' ? 'Detected' : 'Unavailable'}</span></div>
        </div>
      </div>
    </section>
  `;
}

function renderContent() {
  const region = root.querySelector('#content-region');
  if (!region) return;
  if (!state.token) {
    region.innerHTML = `
      <section class="gateway-card placeholder-card">
        <div class="placeholder-card__body">
          <h3>Authenticate to manage gateway access</h3>
          <p class="muted">Once authenticated as the configured operator, you can manage the live Allow List, inspect the Web of Trust graph, and maintain the Block List.</p>
        </div>
      </section>
    `;
    return;
  }

  if (state.activeTab === 'allowlist' && state.allowlist.enabled) {
    region.innerHTML = renderListPanel('allowlist');
    return;
  }

  if (state.activeTab === 'blocklist' && state.blocklist.enabled) {
    region.innerHTML = renderListPanel('blocklist');
    return;
  }

  if (state.activeTab === 'wot' && state.wot.enabled) {
    region.innerHTML = renderWotPanel();
    return;
  }

  region.innerHTML = `
    <section class="gateway-card placeholder-card">
      <div class="placeholder-card__body">
        <h3>This view is unavailable</h3>
        <p class="muted">The active gateway policy does not expose this list in the current deployment.</p>
      </div>
    </section>
  `;
}

function renderListPanel(kind) {
  const current = listStateFor(kind);
  const title = TAB_LABELS[kind];
  const listRows = current.draftPubkeys.length
    ? current.draftPubkeys.map((pubkey) => renderPubkeyRow(pubkey, {
      actionLabel: 'Remove',
      action: 'remove-pubkey',
      actionKind: kind,
      badges: kind === 'blocklist' ? [{ label: 'Denied', tone: 'danger' }] : []
    })).join('')
    : '<div class="empty-state">No pubkeys yet.</div>';
  const meta = renderInlineMeta([
    countLabel(current.draftPubkeys.length, 'entry'),
    humanizeSource(current.meta.source),
    current.meta.updatedAt ? `Updated ${formatTimestamp(current.meta.updatedAt)}` : null
  ]);
  const saveStatus = saveStatusLabel(current);

  return `
    <section class="gateway-card list-surface">
      <div class="view-toolbar">
        <div class="view-toolbar__copy">
          <h3>${escapeHtml(title)}</h3>
          ${meta}
        </div>
        <div class="view-toolbar__actions">
          ${saveStatus ? `<span class="save-status${current.saveState === 'error' ? ' is-error' : ''}">${escapeHtml(saveStatus)}</span>` : ''}
          <button
            class="icon-button"
            type="button"
            data-action="reload-list"
            data-list="${kind}"
            ${current.loading || current.saving ? 'disabled' : ''}
            aria-label="Reload ${escapeHtml(title)}"
            title="Reload ${escapeHtml(title)}"
          >↻</button>
          <button class="button-primary" type="button" data-action="open-add-modal" data-list="${kind}" ${current.loading ? 'disabled' : ''}>Add Pubkey</button>
        </div>
      </div>
      ${current.meta.lastError ? `<div class="inline-note inline-note--warning">${escapeHtml(current.meta.lastError)}</div>` : ''}
      ${current.saveError ? `<div class="inline-note inline-note--error">${escapeHtml(current.saveError)}</div>` : ''}
      <div class="entry-list">${listRows}</div>
    </section>
  `;
}

function renderWotPanel() {
  const entries = state.wot.entries;
  const approvedCount = entries.filter((entry) => entry.approved).length;
  const body = entries.length
    ? entries.map((entry, index) => renderWotRow(entry, index)).join('')
    : '<div class="empty-state">No Web of Trust entries are currently loaded.</div>';
  const meta = renderInlineMeta([
    countLabel(entries.length, 'entry'),
    `${approvedCount} approved`,
    state.wot.meta.loadedAt ? `Updated ${formatTimestamp(state.wot.meta.loadedAt)}` : null
  ]);

  return `
    <section class="gateway-card list-surface">
      <div class="view-toolbar">
        <div class="view-toolbar__copy">
          <h3>${escapeHtml(TAB_LABELS.wot)}</h3>
          ${meta}
        </div>
        <div class="view-toolbar__actions">
          ${state.wot.loading ? '<span class="save-status">Refreshing…</span>' : ''}
          <button
            class="icon-button"
            type="button"
            data-action="reload-wot"
            ${state.wot.loading ? 'disabled' : ''}
            aria-label="Reload Web of Trust"
            title="Reload Web of Trust"
          >↻</button>
        </div>
      </div>
      <div class="context-row">
        <span class="context-chip">Root ${escapeHtml(shortPubkey(state.wot.meta.rootPubkey || 'Unknown'))}</span>
        <span class="context-chip">Max depth ${escapeHtml(state.wot.meta.maxDepth ?? 'Unknown')}</span>
        <span class="context-chip">Depth-2 threshold ${escapeHtml(state.wot.meta.minFollowersDepth2 ?? 'Unknown')}</span>
      </div>
      ${state.wot.meta.lastError ? `<div class="inline-note inline-note--warning">${escapeHtml(state.wot.meta.lastError)}</div>` : ''}
      <div class="entry-list">${body}</div>
    </section>
  `;
}

function renderPubkeyRow(pubkey, {
  actionLabel,
  action,
  actionKind,
  badges = []
} = {}) {
  const profile = getProfile(pubkey);
  const identity = renderIdentity(pubkey, profile, { badges });
  return `
    <article class="entry-row">
      ${identity}
      <div class="entry-actions">
        <button class="button-danger" type="button" data-action="${action}" data-list="${actionKind}" data-pubkey="${pubkey}">${escapeHtml(actionLabel)}</button>
      </div>
    </article>
  `;
}

function renderWotRow(entry, index) {
  const draftBlocked = state.blocklist.draftPubkeys.includes(entry.pubkey);
  const savedBlocked = state.blocklist.serverPubkeys.includes(entry.pubkey);
  const canBlock = state.blocklist.enabled && !draftBlocked && !savedBlocked;
  const badges = [
    { label: `#${index + 1}` },
    { label: `Depth ${entry.depth ?? 'N/A'}` },
    { label: `${entry.followerCount} followers` },
    { label: entry.approved ? 'Approved' : 'Outside threshold', tone: entry.approved ? 'success' : 'warning' }
  ];
  if (entry.isOperator) badges.push({ label: 'Operator', tone: 'success' });
  if (entry.isRoot) badges.push({ label: 'Root', tone: 'success' });
  if (savedBlocked || draftBlocked) badges.push({ label: 'Blocked', tone: 'danger' });
  return `
    <article class="entry-row">
      ${renderIdentity(entry.pubkey, getProfile(entry.pubkey), { badges })}
      <div class="entry-actions">
        <button
          class="${canBlock ? 'button-danger' : 'button-ghost'}"
          type="button"
          data-action="queue-block"
          data-pubkey="${entry.pubkey}"
          ${canBlock ? '' : 'disabled'}
        >${savedBlocked || draftBlocked ? 'Blocked' : (state.blocklist.enabled ? 'Block' : 'Block List disabled')}</button>
      </div>
    </article>
  `;
}

function renderIdentity(pubkey, profileState, { badges = [], meta = [] } = {}) {
  const profile = profileState?.status === 'ready' ? profileState.profile : null;
  const displayName = profile?.displayName || shortPubkey(pubkey);
  const avatar = profile?.picture
    ? `<img class="identity-avatar__image" src="${escapeHtml(profile.picture)}" alt="">`
    : `<span class="identity-avatar__fallback">${escapeHtml((displayName || '?').slice(0, 1).toUpperCase())}</span>`;
  const metaHtml = meta.length
    ? meta.map((m) => `<span class="identity-meta__item">${escapeHtml(m)}</span>`).join('')
    : '';
  const badgeHtml = badges.length
    ? `<div class="badge-row">${badges.map((badge) => `<span class="badge${badge.tone ? ` badge--${badge.tone}` : ''}">${escapeHtml(badge.label)}</span>`).join('')}</div>`
    : '';
  return `
    <div class="identity">
      <div class="identity-avatar">${avatar}</div>
      <div class="identity-copy">
        <div class="identity-headline">
          <span class="identity-title">${escapeHtml(displayName)}</span>
          <code class="identity-pubkey" data-action="copy-pubkey" data-pubkey="${escapeHtml(pubkey)}" title="Click to copy full pubkey">${escapeHtml(shortPubkey(pubkey))}</code>
          ${metaHtml ? `<span class="identity-meta">${metaHtml}</span>` : ''}
        </div>
        ${badgeHtml}
      </div>
    </div>
  `;
}

function renderModal() {
  const region = root.querySelector('#modal-region');
  if (!region) return;
  if (!state.modal.open || !state.modal.kind) {
    region.innerHTML = '';
    return;
  }
  const title = state.modal.kind === 'allowlist' ? 'Add to Allow List' : 'Add to Block List';
  region.innerHTML = `
    <div class="modal-backdrop" data-action="close-modal"></div>
    <section class="modal-sheet" role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <div class="modal-sheet__header">
        <div>
          <h3 id="modal-title">${escapeHtml(title)}</h3>
        </div>
        <button class="icon-button" type="button" data-action="close-modal" aria-label="Close add dialog">×</button>
      </div>
      <div class="modal-sheet__body">
        <label>
          Pubkey
          <input
            id="modal-pubkey-input"
            type="text"
            autocomplete="off"
            spellcheck="false"
            placeholder="64-char hex pubkey"
            value="${escapeHtml(state.modal.inputValue)}"
          >
        </label>
        <div class="button-row button-row--inline">
          <button class="button-primary" type="button" data-action="submit-add-modal">Add Pubkey</button>
          <button class="button-ghost" type="button" data-action="close-modal">Cancel</button>
        </div>
      </div>
    </section>
  `;
}

function clearListSaveTimer(current) {
  if (current?.saveTimer) {
    clearTimeout(current.saveTimer);
    current.saveTimer = null;
  }
}

function clearAllSaveTimers() {
  clearListSaveTimer(state.allowlist);
  clearListSaveTimer(state.blocklist);
}

function scheduleListSave(kind, { immediate = false } = {}) {
  const current = listStateFor(kind);
  if (!current?.enabled || !state.token) return;
  clearListSaveTimer(current);
  if (!isDirtyState(current)) {
    if (current.saveState !== 'error') {
      current.saveState = current.serverPubkeys.length ? 'saved' : 'idle';
    }
    renderContent();
    return;
  }
  if (!current.saving) {
    current.saveState = 'queued';
  }
  current.saveTimer = window.setTimeout(() => {
    current.saveTimer = null;
    void flushListSave(kind);
  }, immediate ? 0 : AUTOSAVE_DELAY_MS);
  renderContent();
}

async function flushListSave(kind) {
  const current = listStateFor(kind);
  if (!state.token || !current?.enabled || current.loading || current.saving || !isDirtyState(current)) return;
  const snapshot = [...current.draftPubkeys];
  current.saving = true;
  current.saveState = 'saving';
  current.saveError = null;
  renderContent();
  try {
    const response = await apiFetch(`/api/admin/${kind}`, {
      method: 'PUT',
      body: JSON.stringify({ pubkeys: snapshot })
    });
    const normalized = uniqueSortedPubkeys(response.pubkeys);
    const draftUnchanged = JSON.stringify(current.draftPubkeys) === JSON.stringify(snapshot);
    current.serverPubkeys = normalized;
    current.meta = {
      source: response.source || null,
      updatedAt: response.updatedAt || null,
      updatedBy: response.updatedBy || null,
      lastError: response.lastError || null
    };
    if (draftUnchanged) {
      current.draftPubkeys = [...normalized];
    }
    current.saveState = 'saved';
    current.saveError = null;
    setBanner(null);
    void ensureProfilesLoaded(current.draftPubkeys);
  } catch (error) {
    if (error.status !== 401) {
      current.saveState = 'error';
      current.saveError = error?.message || `Failed to save ${TAB_LABELS[kind]}.`;
      setBanner(current.saveError, 'error');
    }
  } finally {
    current.saving = false;
    render();
    if (state.token && isDirty(kind)) {
      scheduleListSave(kind, { immediate: true });
    }
  }
}

async function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('content-type', 'application/json');
  if (state.token) {
    headers.set('authorization', `Bearer ${state.token}`);
  }
  const response = await fetch(path, {
    ...options,
    headers
  });
  const text = await response.text();
  let payload = {};
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    payload = { raw: text };
  }
  if (response.status === 401 && state.token) {
    clearAllSaveTimers();
    state.token = null;
    state.tokenExpiresAt = null;
    state.authPanelOpen = true;
    setBanner('Admin session expired. Authenticate again to continue.', 'error');
    render();
  }
  if (!response.ok) {
    const error = new Error(payload?.message || payload?.error || `Request failed with status ${response.status}`);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

async function requestAdminChallenge(pubkey) {
  return apiFetch('/api/admin/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({ pubkey })
  });
}

function buildUnsignedAuthEvent(pubkey, challenge) {
  return {
    kind: 22242,
    created_at: Math.floor(Date.now() / 1000),
    pubkey,
    tags: [
      ['challenge', challenge],
      ['relay', config.relay],
      ['purpose', config.purpose]
    ],
    content: ''
  };
}

async function signEventWithSigner(event, expectedPubkey) {
  if (!window.nostr || typeof window.nostr.signEvent !== 'function') {
    throw new Error('Browser signer is unavailable.');
  }
  if (typeof window.nostr.getPublicKey === 'function') {
    const signerPubkey = normalizePubkey(await window.nostr.getPublicKey());
    if (signerPubkey && signerPubkey !== expectedPubkey) {
      throw new Error('The active browser signer does not match the configured operator pubkey.');
    }
  }
  const signed = await window.nostr.signEvent({ ...event });
  const pubkey = normalizePubkey(signed?.pubkey);
  if (!pubkey || pubkey !== expectedPubkey) {
    throw new Error('The signed event pubkey does not match the configured operator.');
  }
  return signed;
}

async function signEventWithPrivateKey(event, privateKey, expectedPubkey) {
  const normalizedPrivateKey = normalizePrivateKey(privateKey);
  if (!normalizedPrivateKey) {
    throw new Error('Operator private key must be a 64-char hex string.');
  }
  const derivedPubkey = bytesToHex(secp256k1.getPublicKey(normalizedPrivateKey, true)).slice(2);
  if (derivedPubkey !== expectedPubkey) {
    throw new Error('The provided private key does not match the configured operator pubkey.');
  }
  const serialized = JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content
  ]);
  const id = bytesToHex(sha256(new TextEncoder().encode(serialized)));
  const signature = bytesToHex(await schnorr.sign(id, normalizedPrivateKey));
  return {
    ...event,
    id,
    sig: signature
  };
}

async function verifyAdminEvent(authEvent) {
  return apiFetch('/api/admin/auth/verify', {
    method: 'POST',
    body: JSON.stringify({ authEvent })
  });
}

async function authenticateWithSigner() {
  const requestedPubkey = normalizePubkey(state.operatorInput);
  if (!requestedPubkey || requestedPubkey !== config.operatorPubkey) {
    setBanner('The operator pubkey must match the configured gateway operator.', 'error');
    return;
  }
  state.authBusy = true;
  renderAuthPanel();
  try {
    const challenge = await requestAdminChallenge(requestedPubkey);
    const unsignedEvent = buildUnsignedAuthEvent(requestedPubkey, challenge.challenge);
    const signedEvent = await signEventWithSigner(unsignedEvent, requestedPubkey);
    const verification = await verifyAdminEvent(signedEvent);
    state.token = verification.token;
    state.tokenExpiresAt = verification.expiresAt || null;
    state.authPanelOpen = false;
    setBanner(null);
    await loadAllAccessData();
  } catch (error) {
    setBanner(error?.message || 'Failed to authenticate with browser signer.', 'error');
  } finally {
    state.authBusy = false;
    render();
  }
}

async function authenticateWithPrivateKey() {
  const requestedPubkey = normalizePubkey(state.operatorInput);
  if (!requestedPubkey || requestedPubkey !== config.operatorPubkey) {
    setBanner('The operator pubkey must match the configured gateway operator.', 'error');
    return;
  }
  state.authBusy = true;
  renderAuthPanel();
  try {
    const challenge = await requestAdminChallenge(requestedPubkey);
    const unsignedEvent = buildUnsignedAuthEvent(requestedPubkey, challenge.challenge);
    const signedEvent = await signEventWithPrivateKey(unsignedEvent, state.privateKeyInput, requestedPubkey);
    const verification = await verifyAdminEvent(signedEvent);
    state.token = verification.token;
    state.tokenExpiresAt = verification.expiresAt || null;
    state.privateKeyInput = '';
    state.authPanelOpen = false;
    setBanner(null);
    await loadAllAccessData();
  } catch (error) {
    setBanner(error?.message || 'Failed to authenticate with the private-key fallback.', 'error');
  } finally {
    state.authBusy = false;
    render();
  }
}

async function loadAllAccessData() {
  const tasks = [];
  if (state.allowlist.enabled) tasks.push(loadList('allowlist'));
  if (state.blocklist.enabled) tasks.push(loadList('blocklist'));
  if (state.wot.enabled) tasks.push(loadWot());
  await Promise.allSettled(tasks);
}

async function loadList(kind) {
  const current = listStateFor(kind);
  if (!state.token || !current?.enabled) return;
  clearListSaveTimer(current);
  current.loading = true;
  current.saveError = null;
  render();
  try {
    const response = await apiFetch(`/api/admin/${kind}`, { method: 'GET' });
    current.serverPubkeys = uniqueSortedPubkeys(response.pubkeys);
    current.draftPubkeys = [...current.serverPubkeys];
    current.meta = {
      source: response.source || null,
      updatedAt: response.updatedAt || null,
      updatedBy: response.updatedBy || null,
      lastError: response.lastError || null
    };
    current.saveState = current.serverPubkeys.length ? 'saved' : 'idle';
    current.saveError = null;
    void ensureProfilesLoaded(current.draftPubkeys);
  } catch (error) {
    if (error.status !== 401) {
      current.saveState = 'error';
      current.saveError = error?.message || `Failed to load ${TAB_LABELS[kind]}.`;
      setBanner(current.saveError, 'error');
    }
  } finally {
    current.loading = false;
    render();
  }
}

async function loadWot() {
  if (!state.token || !state.wot.enabled) return;
  state.wot.loading = true;
  renderContent();
  try {
    const response = await apiFetch('/api/admin/wot', { method: 'GET' });
    state.wot.entries = Array.isArray(response.pubkeys) ? response.pubkeys : [];
    state.wot.meta = {
      rootPubkey: normalizePubkey(response.rootPubkey) || null,
      maxDepth: Number.isFinite(Number(response.maxDepth)) ? Number(response.maxDepth) : null,
      minFollowersDepth2: Number.isFinite(Number(response.minFollowersDepth2)) ? Number(response.minFollowersDepth2) : null,
      loadedAt: Number.isFinite(Number(response.loadedAt)) ? Number(response.loadedAt) : null,
      expiresAt: Number.isFinite(Number(response.expiresAt)) ? Number(response.expiresAt) : null,
      relayUrls: Array.isArray(response.relayUrls) ? response.relayUrls : [],
      lastError: response.lastError || null
    };
    state.wot.loaded = true;
    void ensureProfilesLoaded(state.wot.entries.map((entry) => entry.pubkey));
  } catch (error) {
    if (error.status !== 401) {
      setBanner(error?.message || 'Failed to load the Web of Trust snapshot.', 'error');
    }
  } finally {
    state.wot.loading = false;
    renderContent();
  }
}

function submitModalPubkey() {
  const kind = state.modal.kind;
  const current = listStateFor(kind);
  if (!current) return;
  const normalized = normalizePubkey(state.modal.inputValue);
  if (!normalized) {
    setBanner('Pubkeys must be 64-char lowercase hex strings.', 'error');
    return;
  }
  current.draftPubkeys = uniqueSortedPubkeys([...current.draftPubkeys, normalized]);
  current.saveError = null;
  closeAddModal();
  render();
  void ensureProfilesLoaded(current.draftPubkeys);
  scheduleListSave(kind);
}

function removeDraftPubkey(kind, pubkey) {
  const current = listStateFor(kind);
  if (!current) return;
  current.draftPubkeys = current.draftPubkeys.filter((entry) => entry !== pubkey);
  current.saveError = null;
  render();
  scheduleListSave(kind);
}

function queuePubkeyForBlocklist(pubkey) {
  if (!state.blocklist.enabled) {
    setBanner('Block List management is not enabled for this deployment.', 'error');
    return;
  }
  state.blocklist.draftPubkeys = uniqueSortedPubkeys([...state.blocklist.draftPubkeys, pubkey]);
  state.blocklist.saveError = null;
  render();
  void ensureProfilesLoaded(state.blocklist.draftPubkeys);
  scheduleListSave('blocklist', { immediate: true });
}

function createSubId(prefix = 'kind0') {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(16).slice(2, 10)}`;
}

function selectPreferredEvent(existing, next) {
  if (!existing) return next;
  const existingCreatedAt = Number(existing.created_at) || 0;
  const nextCreatedAt = Number(next.created_at) || 0;
  if (nextCreatedAt > existingCreatedAt) return next;
  if (nextCreatedAt < existingCreatedAt) return existing;
  return String(next.id || '').localeCompare(String(existing.id || '')) > 0 ? next : existing;
}

async function fetchRelayProfiles(relayUrl, authors, timeoutMs = PROFILE_TIMEOUT_MS) {
  return new Promise((resolvePromise) => {
    const subId = createSubId('kind0');
    const events = [];
    let settled = false;
    let socket = null;

    const finish = () => {
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
      resolvePromise({ relayUrl, events });
    };

    const timer = setTimeout(finish, timeoutMs);

    try {
      socket = new WebSocket(relayUrl);
    } catch (_) {
      finish();
      return;
    }

    socket.addEventListener('open', () => {
      try {
        socket.send(JSON.stringify([
          'REQ',
          subId,
          {
            kinds: [0],
            authors,
            limit: Math.max(authors.length * 2, authors.length)
          }
        ]));
      } catch (_) {
        finish();
      }
    });

    socket.addEventListener('message', (message) => {
      let parsed = null;
      try {
        parsed = JSON.parse(String(message.data));
      } catch (_) {
        return;
      }
      if (!Array.isArray(parsed) || parsed.length < 2) return;
      const [type, incomingSubId, payload] = parsed;
      if (incomingSubId !== subId) return;
      if (type === 'EVENT' && payload && typeof payload === 'object') {
        const pubkey = normalizePubkey(payload.pubkey);
        if (pubkey && authors.includes(pubkey)) {
          events.push(payload);
        }
        return;
      }
      if (type === 'EOSE' || type === 'CLOSED') {
        finish();
      }
    });

    socket.addEventListener('error', finish);
    socket.addEventListener('close', finish);
  });
}

async function fetchLatestProfiles(relayUrls, authors) {
  const normalizedAuthors = uniqueSortedPubkeys(authors);
  if (!normalizedAuthors.length || !relayUrls.length) {
    return new Map();
  }
  const results = await Promise.all(
    relayUrls.map((relayUrl) => fetchRelayProfiles(relayUrl, normalizedAuthors))
  );
  const latest = new Map();
  for (const result of results) {
    for (const event of result.events) {
      const pubkey = normalizePubkey(event?.pubkey);
      if (!pubkey) continue;
      latest.set(pubkey, selectPreferredEvent(latest.get(pubkey), event));
    }
  }
  return latest;
}

async function ensureProfilesLoaded(pubkeys) {
  const targets = uniqueSortedPubkeys(pubkeys).filter((pubkey) => {
    const profile = getProfile(pubkey);
    return !profile || (profile.status !== 'loading' && profile.status !== 'ready' && profile.status !== 'missing');
  });
  if (!targets.length || !config.discoveryRelayUrls.length) return;

  for (const pubkey of targets) {
    setProfile(pubkey, { status: 'loading' });
  }
  renderContent();

  try {
    const latest = await fetchLatestProfiles(config.discoveryRelayUrls, targets);
    for (const pubkey of targets) {
      const event = latest.get(pubkey);
      if (!event) {
        setProfile(pubkey, { status: 'missing' });
        continue;
      }
      let content = {};
      try {
        content = event.content ? JSON.parse(event.content) : {};
      } catch {
        content = {};
      }
      setProfile(pubkey, {
        status: 'ready',
        profile: normalizeProfilePayload(content)
      });
    }
  } catch (_) {
    for (const pubkey of targets) {
      if (getProfile(pubkey)?.status === 'loading') {
        setProfile(pubkey, { status: 'error' });
      }
    }
  } finally {
    renderContent();
  }
}
