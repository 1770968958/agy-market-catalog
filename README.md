# AGY Market Catalog (`agy-market-catalog`)

Zero-backend GitOps plugin registry for **[AGY Market](https://github.com/azwosile/agy-market)** ([`azwosile/agy-market-catalog`](https://github.com/azwosile/agy-market-catalog)) — powering automated plugin indexing, two-layer namespace collision prevention, 4-layer static capability profiling, and dual-channel global (`GitHub Pages` / `gh-pages`: `https://raw.githubusercontent.com/azwosile/agy-market-catalog/gh-pages/index.json` & `https://azwosile.github.io/agy-market-catalog/index.json`) + mainland China (`@agy-market/catalog` on `npmmirror` / Tencent Cloud) catalog delivery.

---

## Verified Catalog Entries (Track 1)

| ID | Canonical Name | Version | Repository | Capability Badges |
| :--- | :--- | :--- | :--- | :--- |
| `azwosile__agy-market` | `agy-market` | `1.0.0` | [`azwosile/agy-market`](https://github.com/azwosile/agy-market) | `sidecar-ui` |
| `azwosile__agy-wallpaper-prism` | `agy-wallpaper-prism` | `2.0.3` | [`azwosile/agy-wallpaper-prism`](https://github.com/azwosile/agy-wallpaper-prism) | `sidecar-ui`, `host-enhancement` (`cdp`) |
| `yunjuanyunshu114-byte__antigravity-observer` | `gemini-neko-cockpit` | `1.2.0` | [`yunjuanyunshu114-byte/antigravity-observer`](https://github.com/yunjuanyunshu114-byte/antigravity-observer) | `sidecar-ui`, `host-enhancement` (`app-asar`) |
| `zou172866__agy-dart` | `agy-dart` | `1.5.0` | [`zou172866/agy-dart`](https://github.com/zou172866/agy-dart) | `global-rules`, `sidecar-ui`, `mcp-stdio`, `lifecycle-hooks` |

---

## Submitting a Plugin (Track 1)

Add a single YAML file at `data/plugins/<owner>__<repo>.yml` pointing to a GitHub repository (`>= 1` day old, `>= 3` commits with distinct Git tree hashes) that publishes a prebuilt GitHub Release `.tar.gz` containing a valid Antigravity `plugin.json`:

```yaml
url: https://github.com/author/my-agy-plugin
pluginRoot: .
category: productivity
description:
  zh: 插件中文功能简介（1-2 句）
  en: Concise English summary of what the plugin provides.
```

Once merged, subsequent SemVer GitHub Releases sync automatically every 30 minutes with zero Pull Requests required. Repositories tagged with GitHub topic `antigravity-plugin` are also discovered automatically every 6 hours in Track 2 (`unverified-index.json`) with `<owner>--<slug>` scoped isolation.

---

## Commands

```powershell
# Validate data/plugins/*.yml schemas & allowlists
npm run validate

# Build dist/{index,unverified-index,readmes}.json
npm run build

# Run anti-collision, RepoJacking, tar-safety & 4-layer capability scanner tests
npm test
```

## Architecture & CI Pipeline Rules

Read **[`AGENTS.md`](./AGENTS.md)** and **[`../AGENTS.md`](../AGENTS.md)** before modifying scripts, schemas, or GitHub Actions workflows.
