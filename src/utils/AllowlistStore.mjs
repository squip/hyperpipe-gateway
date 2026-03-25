import PubkeyListStore from './PubkeyListStore.mjs';

export default class AllowlistStore extends PubkeyListStore {
  constructor(options = {}) {
    super({
      ...options,
      kind: 'allowlist',
      displayName: 'Allowlist'
    });
  }
}
