#!/usr/bin/env node
// Track-2 Experimental Topic Discovery Crawler (`scripts/crawl-topics.mjs`).
// Scans GitHub `topic:antigravity-plugin archived:false`, excludes Track-1 `repositoryId`s,
// runs the identical 4-layer static capability & tarball safety scan, and forces `<owner>--<slug>` scoped install.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildSourceArchiveUrl, DEFAULT_CATALOG_BASE_URL, toScopedPluginName } from './lib/constants.mjs';
import { validatePluginTarball } from './validate-plugin-tarball.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');

/**
 * Pure builder for a Track-2 unverified plugin entry.
 * Always sets `forceScopedInstall: true` and `scopedName: <owner-lower>--<slug>`.
 */
export function buildTrack2PluginRecord({
  repoMeta,
  releaseInfo,
  tarballBuffer,
  track1RepoIds = new Set(),
  catalogBaseUrl = process.env.AGY_MARKET_CATALOG_BASE_URL || DEFAULT_CATALOG_BASE_URL,
}) {
  if (!repoMeta || track1RepoIds.has(repoMeta.id)) {
    return null;
  }
  if (repoMeta.archived || repoMeta.disabled) {
    return null;
  }

  const inspected = validatePluginTarball(tarballBuffer, {
    pluginRoot: '.',
    allowScopedName: true,
    fallbackVersion: releaseInfo.tagName,
    requireSelfContained: Boolean(releaseInfo.requireSelfContained),
  });

  const ownerLogin = String(repoMeta.owner?.login || 'community');
  const repoName = String(repoMeta.name || inspected.manifest.name);
  const entrySlug = `${ownerLogin.toLowerCase()}__${repoName.toLowerCase()}`;
  const rawBaseSlug = inspected.manifest.name.includes('--')
    ? inspected.manifest.name.split('--').pop()
    : inspected.manifest.name;
  const scopedName = toScopedPluginName(ownerLogin, rawBaseSlug);

  const companion = inspected.companion || {};
  const descText = String(inspected.manifest.description || repoMeta.description || '').trim();

  return {
    pluginEntry: {
      id: entrySlug,
      canonicalName: rawBaseSlug,
      scopedName,
      forceScopedInstall: true,
      displayName: inspected.manifest.displayName || inspected.manifest.name,
      description: {
        zh: descText,
        en: descText,
      },
      version: inspected.version,
      gitTag: releaseInfo.tagName,
      commitSha: releaseInfo.commitSha,
      repository: {
        url: repoMeta.html_url || `https://github.com/${ownerLogin}/${repoName}`,
        repositoryId: repoMeta.id,
        ownerId: repoMeta.owner.id,
        stars: Number(repoMeta.stargazers_count || 0),
        pluginRoot: '.',
      },
      distribution: {
        tarballUrl: releaseInfo.tarballUrl,
        sha256: inspected.sha256,
        sizeBytes: inspected.sizeBytes,
        npmMirrorPkg: null,
        preservePaths: companion.preservePaths || [],
      },
      media: {
        iconUrl: inspected.iconArtifact ? `${catalogBaseUrl}/icons/${entrySlug}${inspected.iconArtifact.ext}` : null,
        screenshots: companion.screenshots || [],
      },
      taxonomy: {
        categories: companion.categories?.length ? companion.categories : ['other'],
        tags: companion.tags?.length ? companion.tags : ['experimental'],
        platforms: companion.platforms?.length ? companion.platforms : ['win32', 'darwin', 'linux'],
      },
      capabilities: inspected.capabilities,
      updatedAt: releaseInfo.publishedAt || new Date().toISOString(),
    },
    readmeMarkdown: inspected.readmeMarkdown,
    readmeZhMarkdown: inspected.readmeZhMarkdown || '',
    readmeEnMarkdown: inspected.readmeEnMarkdown || '',
    iconArtifact: inspected.iconArtifact,
  };
}

export function buildShardedDateWindows(nowMs = Date.now(), windowCount = 4, windowDays = 90) {
  const windows = [];
  const dayMs = 86_400_000;
  let cursorEnd = nowMs;
  for (let i = 0; i < windowCount; i++) {
    const start = cursorEnd - windowDays * dayMs;
    const fromDate = new Date(start).toISOString().slice(0, 10);
    const toDate = new Date(cursorEnd).toISOString().slice(0, 10);
    windows.push(`pushed:${fromDate}..${toDate}`);
    cursorEnd = start - dayMs;
  }
  const oldestCutoff = new Date(cursorEnd).toISOString().slice(0, 10);
  windows.push(`pushed:<=${oldestCutoff}`);
  return windows;
}

export async function crawlExperimentalTopics({ repoRoot = REPO_ROOT } = {}) {
  const ledgerPath = join(repoRoot, 'state', 'ledger.json');
  const cachePath = join(repoRoot, 'state', 'unverified-cache.json');
  const ledger = existsSync(ledgerPath) ? JSON.parse(readFileSync(ledgerPath, 'utf8')) : { schemaVersion: 1, entries: {} };
  const track1RepoIds = new Set(Object.values(ledger.entries).map((e) => e.repositoryId));

  const token = process.env.GITHUB_TOKEN || '';
  if (!token) {
    if (!existsSync(cachePath)) {
      mkdirSync(dirname(cachePath), { recursive: true });
      writeFileSync(
        cachePath,
        `${JSON.stringify({ schemaVersion: 1, plugins: [], readmes: {}, readmesZh: {}, readmesEn: {} }, null, 2)}\n`,
        'utf8',
      );
    }
    console.log('[crawl-topics] No GITHUB_TOKEN set; preserving local unverified-cache.json.');
    return { discovered: 0 };
  }

  const headers = {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${token}`,
    'User-Agent': 'agy-market-topic-crawler/1.0',
  };

  const seenRepoIds = new Set();
  const discoveredPlugins = [];
  const readmes = {};
  const readmesZh = {};
  const readmesEn = {};
  const stateIconsDir = join(repoRoot, 'state', 'icons');
  const iconsDir = join(repoRoot, 'dist', 'icons');
  mkdirSync(stateIconsDir, { recursive: true });
  mkdirSync(iconsDir, { recursive: true });

  for (const pushedWindow of buildShardedDateWindows()) {
    const q = encodeURIComponent(`topic:antigravity-plugin archived:false ${pushedWindow}`);
    const searchRes = await fetch(`https://api.github.com/search/repositories?q=${q}&sort=updated&per_page=50`, {
      headers,
    });
    if (!searchRes.ok) continue;
    const searchJson = await searchRes.json();

    for (const repo of searchJson.items || []) {
      if (seenRepoIds.has(repo.id) || track1RepoIds.has(repo.id)) continue;
      seenRepoIds.add(repo.id);

      const relRes = await fetch(`https://api.github.com/repositories/${repo.id}/releases/latest`, { headers });
      if (!relRes.ok) continue;
      const rel = await relRes.json();
      if (rel.draft || rel.prerelease) continue;
      const asset = (rel.assets || []).find((a) => /\.(?:tar\.gz|tgz)$/i.test(a.name));
      const requireSelfContained = !asset;

      const refRes = await fetch(
        `https://api.github.com/repositories/${repo.id}/commits/${encodeURIComponent(rel.tag_name)}`,
        { headers },
      );
      if (!refRes.ok) continue;
      const refJson = await refRes.json();
      const downloadUrl = asset
        ? asset.browser_download_url
        : buildSourceArchiveUrl(repo.full_name, refJson.sha, rel.tag_name);

      const dl = await fetch(downloadUrl, { headers: { 'User-Agent': 'agy-market-topic-crawler/1.0' } });
      if (!dl.ok) continue;
      const buf = Buffer.from(await dl.arrayBuffer());

      try {
        const built = buildTrack2PluginRecord({
          repoMeta: repo,
          releaseInfo: {
            tagName: rel.tag_name,
            commitSha: refJson.sha,
            tarballUrl: downloadUrl,
            publishedAt: rel.published_at,
            requireSelfContained,
          },
          tarballBuffer: buf,
          track1RepoIds,
        });
        if (built) {
          discoveredPlugins.push(built.pluginEntry);
          if (built.readmeMarkdown) {
            readmes[built.pluginEntry.id] = built.readmeMarkdown;
          }
          if (built.readmeZhMarkdown) {
            readmesZh[built.pluginEntry.id] = built.readmeZhMarkdown;
          }
          if (built.readmeEnMarkdown) {
            readmesEn[built.pluginEntry.id] = built.readmeEnMarkdown;
          }
          if (built.iconArtifact) {
            const iconFile = `${built.pluginEntry.id}${built.iconArtifact.ext}`;
            writeFileSync(join(stateIconsDir, iconFile), built.iconArtifact.sanitizedBuffer);
            writeFileSync(join(iconsDir, iconFile), built.iconArtifact.sanitizedBuffer);
          }
        }
      } catch {
        /* invalid or unsafe experimental plugin skipped */
      }
    }
  }

  discoveredPlugins.sort((a, b) => a.id.localeCompare(b.id));
  writeFileSync(
    cachePath,
    `${JSON.stringify({ schemaVersion: 1, plugins: discoveredPlugins, readmes, readmesZh, readmesEn }, null, 2)}\n`,
    'utf8',
  );
  return { discovered: discoveredPlugins.length };
}

if (import.meta.url === pathToFileURL(resolve(process.argv[1] || '')).href) {
  const out = await crawlExperimentalTopics();
  console.log(`[crawl-topics] Discovered ${out.discovered} Track-2 plugins`);
}
