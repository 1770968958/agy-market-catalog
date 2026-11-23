# AGY Market Catalog (`agy-market-catalog`)

Zero-backend GitOps plugin registry for **[AGY Market](../agy-market)** — powering automated plugin indexing, multi-layer collision prevention, static capability transparency, and dual-channel global + mainland China catalog delivery.

## Submitting a Plugin (Track 1)

Add a single YAML file at `data/plugins/<owner>__<repo>.yml` pointing to a GitHub repository (>= 1 day old, >= 3 non-empty commits) with a prebuilt GitHub Release `.tar.gz` containing a valid Antigravity `plugin.json`:

```yaml
url: https://github.com/author/my-agy-plugin
pluginRoot: .
category: productivity
description:
  zh: 插件中文功能简介（1-2 句）
  en: Concise English summary of what the plugin provides.
```

Once merged, subsequent GitHub Releases are indexed automatically with zero Pull Requests required. Plugins tagged with GitHub topic `antigravity-plugin` are also discovered automatically in the experimental Track-2 feed (`unverified-index.json`).

## Architecture & CI Pipeline Rules

Read **[`AGENTS.md`](./AGENTS.md)** and **[`../AGENTS.md`](../AGENTS.md)** before modifying scripts, schemas, or GitHub Actions workflows.
