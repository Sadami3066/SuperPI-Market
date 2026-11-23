# SuperPI Market

[简体中文](README.cn.md) | English

Official plugin, skill, and remote MCP catalog for [SuperPI](https://github.com/Sadami3066/SuperPI). This repository serves the **ECDSA-signed registry** (`https://sadami3066.github.io/SuperPI-Market/registry.json`) and hosts verified `.ddp`/`.zip` releases. It contains no app source code.

## Quick Start: Submit an Entry

Requirements: Node.js ≥ 22 and `git`.

1. **Create an entry JSON** under `entries/plugin/`, `entries/skill/`, or `entries/mcp/` (start from `entries/sample.json`):
   - Set bilingual `name`, `summary`, `description`, `tags` (`zh` & `en`), unique `id`, and semver `version`.
   - Plugins must declare `plugin.apiLevel = 7`, `plugin.minHostVersion >= "2.0.0"`, `plugin.publisherKeyId` (`ed25519:...`), and `plugin.requiredAccess` (`normal` | `adb` | `root`).
   - Add an icon (`icons/<name>.png`, ≤ 128 KB); optional portrait previews (`previews/`) may use `https://raw.githubusercontent.com/Sadami3066/SuperPI-Market/master/previews/<file>`.
2. **Attach release checksums**:
   - Compute `sha256sum` and byte `size` for your public `.ddp` (≤ 50 MB) or skill `.zip` (≤ 20 MB) asset.
3. **Validate locally & open a PR**:

```bash
node scripts/publish.mjs
node scripts/validate.mjs --no-sig
```

PRs run `validate.yml` (`--schema-only`). Once reviewed against the [PR Review Checklist](https://github.com/Sadami3066/SuperPI/blob/main/docs/plugins/pr-review.md) and [Marketplace Policy](https://github.com/Sadami3066/SuperPI/blob/main/docs/plugins/market-policy.md) and merged to `master`, `release.yml` signs `registry.json` with `MARKET_PRIVATE_KEY`, deploys to GitHub Pages, and verifies the live endpoint byte-for-byte.

## Repository Layout

| Path | Purpose |
|---|---|
| `entries/{plugin,skill,mcp}/` | Source manifests (1 JSON per entry; `registry.json` is generated, never hand-edited) |
| `icons/` · `previews/` | Entry icons (served via Pages) and plugin preview screenshots |
| `keys/market-public.pem` | ECDSA P-256 public verification key (private key is never stored in git) |
| `scripts/` | `publish.mjs`, `validate.mjs`, `sign.mjs`, `verify-ddp.mjs` |
| `.github/workflows/` | PR schema validation, Pages signed deployment, daily artifact verification |

> [!NOTE]
> `SuperPI-Market` keeps `master` as its default branch so existing preview URLs (`raw.githubusercontent.com/.../master/previews/...`) remain stable.

## Links & Feedback

- Main monorepo & Plugin SDK docs: [Sadami3066/SuperPI](https://github.com/Sadami3066/SuperPI) · [Plugin Developer Docs](https://github.com/Sadami3066/SuperPI/blob/main/docs/plugins/README.md)
- Submissions, updates, or takedown requests: open an Issue or PR here. Report security issues privately.
- Scripts and workflows are licensed under [Apache-2.0](LICENSE).
