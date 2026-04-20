# Contributing

The `hyperpipe` monorepo is the canonical source of truth for all first-party Hyperpipe
packages and applications.

Repository policy:

- Development happens in this monorepo.
- Public repos are synchronized mirrors, not the authoritative development history.
- Versioning is package-specific and release tags are namespaced by package or app.

Current first-party packages:

- `@squip/hyperpipe-bridge`
- `@squip/hyperpipe-core`
- `@squip/hyperpipe-core-host`

Current first-party applications:

- `hyperpipe-desktop`
- `hyperpipe-tui`
- `hyperpipe-gateway`

Release tags:

- `bridge-vX.Y.Z`
- `core-vX.Y.Z`
- `core-host-vX.Y.Z`
- `desktop-vX.Y.Z`
- `tui-vX.Y.Z`
- `gateway-vX.Y.Z`

Install policy:

- the root `package-lock.json` is the only tracked lockfile in this monorepo
- run `npm install` or `npm ci` from the monorepo root
- nested workspace `package-lock.json` files should not be committed

Pull request expectations:

- keep changes scoped to one package, application, or release concern when practical
- include tests or a clear explanation when tests are not practical
- update README/docs when changing public behavior, package names, or release flow
- do not commit secrets, local runtime `.env` files, or generated `node_modules`
- prefer changesets or namespaced release-tag updates when a publishable package changes

Issue routing:

- use the bug report or feature request templates when filing issues
- do not use public issues for vulnerability reports; follow [SECURITY.md](./SECURITY.md)

Behavior expectations:

- this project follows the rules in [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)
