#!/usr/bin/env node
// Deterministic Static Feed Compiler (`scripts/build-catalog.mjs`).
// Compiles `state/ledger.json` + `state/versions-lock.json` + `data/plugins/*.yml` (+ `state/unverified-cache.json`)
// into `dist/{index.json, unverified-index.json, readmes.json}` matching AGENTS.md §4.5.

import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { DEFAULT_CATALOG_BASE_URL, toScopedPluginName } from './lib/constants.mjs';
import { validateEntriesDirectory } from './validate-entries.mjs';
import { containsChineseCjk, isPredominantlyChinese } from './validate-plugin-tarball.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');

export function computeCatalogVersion(now = new Date(), runSeq = 1) {
  const yyyy = now.getUTCFullYear();
  const mm = String(now.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(now.getUTCDate()).padStart(2, '0');
  return `${yyyy}.${mm}${dd}.${runSeq}`;
}

export function compileCatalogArtifacts({
  entries = [],
  ledger = { schemaVersion: 1, entries: {} },
  versionsLock = { schemaVersion: 1, locks: {} },
  unverifiedCache = { schemaVersion: 1, plugins: [], readmes: {}, readmesZh: {}, readmesEn: {} },
  catalogBaseUrl = process.env.AGY_MARKET_CATALOG_BASE_URL || DEFAULT_CATALOG_BASE_URL,
  generatedAt = new Date().toISOString(),
  catalogVersion = computeCatalogVersion(new Date(generatedAt)),
} = {}) {
  const entryMap = new Map(entries.map((e) => [e.entrySlug, e]));
  const verifiedPlugins = [];
  const readmes = { ...(unverifiedCache.readmes || {}) };
  const readmesZh = { ...(unverifiedCache.readmesZh || {}) };
  const readmesEn = { ...(unverifiedCache.readmesEn || {}) };

  const sortedLedgerRecords = Object.values(ledger.entries || {}).sort((a, b) =>
    String(a.entrySlug).localeCompare(String(b.entrySlug)),
  );

  for (const rec of sortedLedgerRecords) {
    // Exclude hard-blocked RepoJacking records from active index
    if (rec.status === 'REPOJACKING_BLOCKED') continue;

    const lock = versionsLock.locks?.[rec.entrySlug];
    if (!lock?.latest || !lock.versions?.[lock.latest]) continue;

    const verData = lock.versions[lock.latest];
    const yamlEntry = entryMap.get(rec.entrySlug);
    const manifest = verData.manifest || {};
    const companion = verData.companion || {};
    const owner = String(rec.repoFullName || '').split('/')[0] || rec.entrySlug.split('__')[0];

    const categories = companion.categories?.length
      ? companion.categories
      : yamlEntry?.category
        ? [yamlEntry.category]
        : ['productivity'];

    const description = yamlEntry?.description || {
      zh: manifest.description || '',
      en: manifest.description || '',
    };

    const iconUrl = verData.iconExt ? `${catalogBaseUrl}/icons/${rec.entrySlug}${verData.iconExt}` : null;

    verifiedPlugins.push({
      id: rec.entrySlug,
      canonicalName: rec.canonicalName,
      scopedName: toScopedPluginName(owner, rec.canonicalName),
      forceScopedInstall: false,
      displayName: manifest.displayName || rec.canonicalName,
      description,
      version: lock.latest,
      gitTag: verData.gitTag,
      commitSha: verData.commitSha,
      repository: {
        url: `https://github.com/${rec.repoFullName}`,
        repositoryId: rec.repositoryId,
        ownerId: rec.ownerId,
        stars: Number(verData.stars || 0),
        pluginRoot: rec.pluginRoot || '.',
      },
      distribution: {
        tarballUrl: verData.tarballUrl,
        sha256: verData.sha256,
        sizeBytes: Number(verData.sizeBytes || 0),
        npmMirrorPkg: verData.npmMirrorPkg || null,
        preservePaths: companion.preservePaths || [],
      },
      media: {
        iconUrl,
        screenshots: companion.screenshots || [],
      },
      taxonomy: {
        categories,
        tags: companion.tags || [],
        platforms: companion.platforms?.length ? companion.platforms : ['win32', 'darwin', 'linux'],
      },
      capabilities: verData.capabilities || {
        badges: [],
        rulesEstimatedTokens: 0,
        mcpServers: [],
        mcpRemoteDomains: [],
        hookEvents: [],
        hostEnhancementKind: [],
      },
      updatedAt: verData.publishedAt || generatedAt,
    });

    if (verData.readmeMarkdown) {
      readmes[rec.entrySlug] = verData.readmeMarkdown;
    }

    if (typeof verData.readmeZhMarkdown === 'string') {
      if (verData.readmeZhMarkdown) {
        readmesZh[rec.entrySlug] = verData.readmeZhMarkdown;
      }
    } else if (verData.readmeMarkdown && isPredominantlyChinese(verData.readmeMarkdown)) {
      readmesZh[rec.entrySlug] = verData.readmeMarkdown;
    }

    if (typeof verData.readmeEnMarkdown === 'string') {
      if (verData.readmeEnMarkdown) {
        readmesEn[rec.entrySlug] = verData.readmeEnMarkdown;
      }
    } else if (
      verData.readmeMarkdown &&
      (!containsChineseCjk(verData.readmeMarkdown) || !isPredominantlyChinese(verData.readmeMarkdown))
    ) {
      readmesEn[rec.entrySlug] = verData.readmeMarkdown;
    }
  }

  const track1RepoIds = new Set(verifiedPlugins.map((p) => p.repository.repositoryId));
  const unverifiedPlugins = (unverifiedCache.plugins || [])
    .filter((p) => !track1RepoIds.has(p.repository?.repositoryId))
    .map((p) => ({
      ...p,
      forceScopedInstall: true,
    }));

  const indexJson = {
    schemaVersion: 1,
    track: 'verified',
    generatedAt,
    catalogVersion,
    plugins: verifiedPlugins,
  };

  const unverifiedIndexJson = {
    schemaVersion: 1,
    track: 'unverified',
    generatedAt,
    catalogVersion,
    plugins: unverifiedPlugins,
  };

  const readmesJson = {
    schemaVersion: 1,
    generatedAt,
    entries: readmes,
    entriesZh: readmesZh,
    entriesEn: readmesEn,
  };

  return { indexJson, unverifiedIndexJson, readmesJson };
}

export function buildCatalogToDisk({ repoRoot = REPO_ROOT, generatedAt, catalogVersion } = {}) {
  const entries = validateEntriesDirectory(join(repoRoot, 'data', 'plugins'));
  const ledgerPath = join(repoRoot, 'state', 'ledger.json');
  const lockPath = join(repoRoot, 'state', 'versions-lock.json');
  const unverifiedPath = join(repoRoot, 'state', 'unverified-cache.json');

  const ledger = existsSync(ledgerPath) ? JSON.parse(readFileSync(ledgerPath, 'utf8')) : { schemaVersion: 1, entries: {} };
  const versionsLock = existsSync(lockPath)
    ? JSON.parse(readFileSync(lockPath, 'utf8'))
    : { schemaVersion: 1, locks: {} };
  const unverifiedCache = existsSync(unverifiedPath)
    ? JSON.parse(readFileSync(unverifiedPath, 'utf8'))
    : { schemaVersion: 1, plugins: [], readmes: {}, readmesZh: {}, readmesEn: {} };

  const { indexJson, unverifiedIndexJson, readmesJson } = compileCatalogArtifacts({
    entries,
    ledger,
    versionsLock,
    unverifiedCache,
    generatedAt,
    catalogVersion,
  });

  const distDir = join(repoRoot, 'dist');
  const distIconsDir = join(distDir, 'icons');
  const stateIconsDir = join(repoRoot, 'state', 'icons');
  mkdirSync(distIconsDir, { recursive: true });
  if (existsSync(stateIconsDir)) {
    for (const iconFile of readdirSync(stateIconsDir)) {
      if (iconFile.startsWith('.')) continue;
      cpSync(join(stateIconsDir, iconFile), join(distIconsDir, iconFile));
    }
  }
  writeFileSync(join(distDir, 'index.json'), `${JSON.stringify(indexJson, null, 2)}\n`, 'utf8');
  writeFileSync(join(distDir, 'unverified-index.json'), `${JSON.stringify(unverifiedIndexJson, null, 2)}\n`, 'utf8');
  writeFileSync(join(distDir, 'readmes.json'), `${JSON.stringify(readmesJson, null, 2)}\n`, 'utf8');

  return { distDir, indexJson, unverifiedIndexJson, readmesJson };
}

if (import.meta.url === pathToFileURL(resolve(process.argv[1] || '')).href) {
  const out = buildCatalogToDisk();
  console.log(
    `[build-catalog] Built dist/index.json (${out.indexJson.plugins.length} verified), dist/unverified-index.json (${out.unverifiedIndexJson.plugins.length} experimental), & dist/readmes.json (entries=${Object.keys(out.readmesJson.entries).length}, zh=${Object.keys(out.readmesJson.entriesZh).length}, en=${Object.keys(out.readmesJson.entriesEn).length})`,
  );
}
