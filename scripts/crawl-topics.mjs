#!/usr/bin/env node
// Track-2 Multi-Source + Aggregator Discovery Crawler (`scripts/crawl-topics.mjs`).
//
// Channels:
//   - Channel A: High-SNR GitHub Repo Search (singular + plural topics, name queries, noise-reduced broad queries;
//                never blind-scanning bare `topic:antigravity`) + Fail-Open throttled Code Search.
//   - Channel B: `data/aggregators.json` curated Awesome Lists, JSON indexes & Monorepos + all-4-layout archive scan.
//   - Channel C: Immutable 3-tier snapshot resolver (Release -> SemVer Tag -> 40-hex Commit SHA `/archive/<sha>.tar.gz`)
//                with monotonic `<baseVer>-git.<YYYYMMDDHHmmss>.<short7>` versioning and zero-REST-API-quota fallback.
//
// Security invariants:
//   - Zero untrusted code execution; strictly streaming/static inspection.
//   - Forces `forceScopedInstall: true` & `<owner>--<slug>` scoped isolation.
//   - Never modifies Track-1 `state/ledger.json` or `state/versions-lock.json`.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  buildSourceArchiveUrl,
  DEFAULT_CATALOG_BASE_URL,
  FIRST_PARTY_REPO_OWNERS,
  normalizeRelPosix,
  parseSemver,
} from './lib/constants.mjs';
import {
  buildChannelARepoQueries,
  buildShardedDateWindows,
  buildTrack2EntryIdentity,
  CHANNEL_A_CODE_QUERIES,
  CODE_SEARCH_DELAY_MS,
  DEFAULT_MAX_PLUGINS_PER_REPO,
  deriveExplicitSubpathFromCodePath,
  discoverPluginRootsInArchive,
  downloadTarballBuffer,
  fetchAggregatorCandidates,
  fetchWithLimit,
  loadAggregatorsConfig,
  parseGitHubRepoHtmlMeta,
  parseSafeGitHubCandidateUrl,
  pickHighestStableSemverTag,
  REPO_SEARCH_DELAY_MS,
  resolveRepoSnapshotZeroQuota,
  selectReleaseTarballAsset,
  synthesizeGitCommitVersion,
} from './lib/discovery-sources.mjs';
import { inspectTarGzBuffer } from './lib/tar-stream.mjs';
import { validatePluginTarball } from './validate-plugin-tarball.mjs';

export { buildShardedDateWindows };

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const USER_AGENT = 'agy-market-topic-crawler/1.4';
const NEG_CACHE_TTL_MS = 7 * 86_400_000; // 7 days

function sleep(ms) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

export function extractErrorCode(err) {
  const msg = String(err?.message || err || 'ERR_UNKNOWN');
  const m = /^([A-Z][A-Z0-9_]+):/.exec(msg);
  if (m) return m[1];
  if (err?.name === 'AbortError' || /abort|timeout|ETIMEDOUT/i.test(msg)) return 'ERR_TIMEOUT';
  if (/fetch failed|ENOTFOUND|ECONNREFUSED|ECONNRESET|EAI_AGAIN|EHOSTUNREACH|ENETUNREACH|EACCES|socket|network|TLS/i.test(msg)) {
    return 'ERR_NETWORK';
  }
  return 'ERR_UNKNOWN';
}

function isTransientErrorCode(code) {
  return code === 'ERR_TRANSIENT_HTTP' || code === 'ERR_TIMEOUT' || code === 'ERR_NETWORK';
}

function sortRecordKeys(obj) {
  const sorted = {};
  for (const k of Object.keys(obj || {}).sort((a, b) => a.localeCompare(b))) {
    sorted[k] = obj[k];
  }
  return sorted;
}

function repoKeyFromUrl(url) {
  const m = /^https:\/\/github\.com\/([^/]+\/[^/]+?)(?:\/|\.git)?$/i.exec(String(url || '').trim());
  return m ? m[1].toLowerCase() : '';
}

function isFirstPartyRepoMeta(repoMeta) {
  const ownerLogin = String(repoMeta?.owner?.login || '').toLowerCase();
  if (FIRST_PARTY_REPO_OWNERS.has(ownerLogin)) return true;
  if (repoMeta?.fork && repoMeta?.parent?.owner?.login) {
    if (FIRST_PARTY_REPO_OWNERS.has(String(repoMeta.parent.owner.login).toLowerCase())) {
      return true;
    }
  }
  return false;
}

/**
 * Pure builder for a single Track-2 unverified plugin entry (backward-compatible with root & subdir plugins).
 * Always sets `forceScopedInstall: true` and `scopedName: <owner-lower>--<slug>`.
 */
export function buildTrack2PluginRecord({
  repoMeta,
  releaseInfo,
  tarballBuffer,
  tarInfo = null,
  pluginRoot = '.',
  totalValidRootsInRepo = 1,
  usedScopedNames = null,
  track1RepoIds = null,
  track1RepoRoots = null,
  track1RepoUrlRoots = null,
  catalogBaseUrl = process.env.AGY_MARKET_CATALOG_BASE_URL || DEFAULT_CATALOG_BASE_URL,
}) {
  if (!repoMeta) return null;
  if (repoMeta.archived || repoMeta.disabled || repoMeta.is_template) return null;
  if (isFirstPartyRepoMeta(repoMeta)) return null;

  const normRoot = normalizeRelPosix(pluginRoot);
  const repoId = Number(repoMeta.id || 0);
  const ownerLogin = String(repoMeta.owner?.login || 'community');
  const repoName = String(repoMeta.name || (repoMeta.full_name ? String(repoMeta.full_name).split('/')[1] : '') || '');
  const fullName = String(repoMeta.full_name || `${ownerLogin}/${repoName}`);
  const repoUrl = repoMeta.html_url || `https://github.com/${fullName}`;

  if (track1RepoRoots && repoId > 0 && track1RepoRoots.has(`${repoId}:${normRoot}`)) {
    return null;
  }
  if (!track1RepoRoots && track1RepoIds && repoId > 0 && track1RepoIds.has(repoId)) {
    return null;
  }
  if (track1RepoUrlRoots && track1RepoUrlRoots.has(`${fullName.toLowerCase()}:${normRoot}`)) {
    return null;
  }

  const fallbackName = normRoot === '.' ? repoName : normRoot.split('/').pop() || repoName;
  const inspected = validatePluginTarball(tarballBuffer, {
    pluginRoot: normRoot,
    allowScopedName: true,
    fallbackVersion: releaseInfo?.tagName || '',
    requireSelfContained: Boolean(releaseInfo?.requireSelfContained),
    lenientManifest: true,
    requireAntigravityComponent: true,
    fallbackDescription: String(repoMeta.description || ''),
    fallbackName,
    affinityContext: {
      repoName,
      repoFullName: fullName,
      repoDescription: String(repoMeta.description || ''),
      topics: Array.isArray(repoMeta.topics) ? repoMeta.topics : [],
    },
    tarInfo,
  });

  const identity = buildTrack2EntryIdentity({
    ownerLogin,
    repoName: repoName || inspected.manifest.name,
    pluginRoot: normRoot,
    manifestName: inspected.manifest.name,
    totalValidRootsInRepo,
    usedScopedNames,
  });

  const hasTag = typeof releaseInfo?.tagName === 'string' && releaseInfo.tagName.trim().length > 0;
  const gitTag = hasTag ? releaseInfo.tagName.trim() : null;
  const commitSha = String(releaseInfo?.commitSha || '');

  let version = inspected.version;
  if (!gitTag) {
    version = synthesizeGitCommitVersion(inspected.manifest.version, releaseInfo?.publishedAt, commitSha);
  } else if (!parseSemver(inspected.manifest.version) && !parseSemver(gitTag) && commitSha) {
    version = synthesizeGitCommitVersion(null, releaseInfo?.publishedAt, commitSha);
  }

  const companion = inspected.companion || {};
  const descText = String(inspected.manifest.description || repoMeta.description || '').trim();

  return {
    pluginEntry: {
      id: identity.id,
      canonicalName: identity.canonicalName,
      scopedName: identity.scopedName,
      forceScopedInstall: true,
      displayName: inspected.manifest.displayName || inspected.manifest.name,
      description: {
        zh: descText,
        en: descText,
      },
      version,
      gitTag,
      commitSha,
      repository: {
        url: repoUrl,
        repositoryId: repoId,
        ownerId: Number(repoMeta.owner?.id || 0),
        stars: Number(repoMeta.stargazers_count || 0),
        pluginRoot: normRoot,
      },
      distribution: {
        tarballUrl: releaseInfo.tarballUrl,
        sha256: inspected.sha256,
        sizeBytes: inspected.sizeBytes,
        npmMirrorPkg: null,
        preservePaths: companion.preservePaths || [],
      },
      media: {
        iconUrl: inspected.iconArtifact ? `${catalogBaseUrl}/icons/${identity.id}${inspected.iconArtifact.ext}` : null,
        screenshots: companion.screenshots || [],
      },
      taxonomy: {
        categories: companion.categories?.length ? companion.categories : ['other'],
        tags: companion.tags?.length ? companion.tags : ['experimental'],
        platforms: companion.platforms?.length ? companion.platforms : ['win32', 'darwin', 'linux'],
      },
      capabilities: inspected.capabilities,
      updatedAt: releaseInfo?.publishedAt || new Date().toISOString(),
    },
    readmeMarkdown: inspected.readmeMarkdown,
    readmeZhMarkdown: inspected.readmeZhMarkdown || '',
    readmeEnMarkdown: inspected.readmeEnMarkdown || '',
    iconArtifact: inspected.iconArtifact,
  };
}

/**
 * Unpacks a repository tarball ONCE in memory, discovers all candidate plugin roots across all 4 layouts
 * (root / `.antigravity-plugin/plugin.json` / `.agents/plugins/*` / `plugins/*` / named subdirs),
 * validates each root independently, and returns `{ records, skipped, candidateRoots }`.
 */
export function buildTrack2PluginRecordsForArchive({
  repoMeta,
  releaseInfo,
  tarballBuffer,
  explicitSubpaths = [],
  subdirGlobs = [],
  isMonorepo = false,
  maxPlugins = DEFAULT_MAX_PLUGINS_PER_REPO,
  track1RepoRoots = null,
  track1RepoUrlRoots = null,
  catalogBaseUrl = process.env.AGY_MARKET_CATALOG_BASE_URL || DEFAULT_CATALOG_BASE_URL,
}) {
  if (!repoMeta || repoMeta.archived || repoMeta.disabled || repoMeta.is_template || isFirstPartyRepoMeta(repoMeta)) {
    return { records: [], skipped: [{ pluginRoot: '.', code: 'ERR_REPO_INELIGIBLE' }], candidateRoots: [] };
  }

  const tarInfo = inspectTarGzBuffer(tarballBuffer);
  const candidateRoots = discoverPluginRootsInArchive(tarInfo.files, {
    explicitSubpaths,
    subdirGlobs,
    isMonorepo,
    maxPlugins,
  });

  if (candidateRoots.length === 0) {
    throw new Error('ERR_MISSING_PLUGIN_JSON: No plugin.json or .antigravity-plugin/plugin.json found in archive');
  }

  // Pass 1: validate every candidate root so we know the exact count of valid roots for single-subdir ID simplification.
  const validDrafts = [];
  const skipped = [];
  for (const pluginRoot of candidateRoots) {
    try {
      const built = buildTrack2PluginRecord({
        repoMeta,
        releaseInfo,
        tarballBuffer,
        tarInfo,
        pluginRoot,
        totalValidRootsInRepo: candidateRoots.length,
        track1RepoRoots,
        track1RepoUrlRoots,
        catalogBaseUrl,
      });
      if (built) {
        validDrafts.push({ pluginRoot, built });
      } else {
        skipped.push({ pluginRoot, code: 'SKIP_TRACK1_OR_INELIGIBLE' });
      }
    } catch (err) {
      skipped.push({
        pluginRoot,
        code: extractErrorCode(err),
        message: String(err?.message || err),
      });
    }
  }

  if (validDrafts.length === 0) {
    return { records: [], skipped, candidateRoots };
  }

  // Pass 2: finalize IDs & collision-free scopedNames using exact `validDrafts.length`.
  const ownerLogin = String(repoMeta.owner?.login || 'community');
  const repoName = String(repoMeta.name || (repoMeta.full_name ? String(repoMeta.full_name).split('/')[1] : '') || '');
  const usedScopedNames = new Set();
  const records = validDrafts.map(({ pluginRoot, built }) => {
    const identity = buildTrack2EntryIdentity({
      ownerLogin,
      repoName: repoName || built.pluginEntry.canonicalName,
      pluginRoot,
      manifestName: built.pluginEntry.canonicalName,
      totalValidRootsInRepo: validDrafts.length,
      usedScopedNames,
    });
    const nextEntry = {
      ...built.pluginEntry,
      id: identity.id,
      canonicalName: identity.canonicalName,
      scopedName: identity.scopedName,
      media: {
        ...built.pluginEntry.media,
        iconUrl: built.iconArtifact ? `${catalogBaseUrl}/icons/${identity.id}${built.iconArtifact.ext}` : null,
      },
    };
    return {
      ...built,
      pluginEntry: nextEntry,
    };
  });

  return { records, skipped, candidateRoots };
}

export function parseCrawlerCliArgs(argv = process.argv.slice(2)) {
  const opts = {
    aggregatorsFlag: false,
    searchFlag: false,
    repos: [],
    maxNew: 0,
    maxRepos: 0,
    concurrency: 4,
    ignoreNegCache: false,
    forceRefresh: false,
    zeroQuota: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--aggregators' || arg === '--aggregators-only') {
      opts.aggregatorsFlag = true;
    } else if (arg === '--search') {
      opts.searchFlag = true;
    } else if (arg === '--repos' && i + 1 < argv.length) {
      const raw = argv[++i];
      for (const part of raw.split(',')) {
        const trimmed = part.trim();
        if (trimmed) opts.repos.push(trimmed);
      }
    } else if (arg.startsWith('--repos=')) {
      const raw = arg.slice('--repos='.length);
      for (const part of raw.split(',')) {
        const trimmed = part.trim();
        if (trimmed) opts.repos.push(trimmed);
      }
    } else if (arg === '--max-new' && i + 1 < argv.length) {
      opts.maxNew = Math.max(0, parseInt(argv[++i], 10) || 0);
    } else if (arg.startsWith('--max-new=')) {
      opts.maxNew = Math.max(0, parseInt(arg.slice('--max-new='.length), 10) || 0);
    } else if (arg === '--max-repos' && i + 1 < argv.length) {
      opts.maxRepos = Math.max(0, parseInt(argv[++i], 10) || 0);
    } else if (arg.startsWith('--max-repos=')) {
      opts.maxRepos = Math.max(0, parseInt(arg.slice('--max-repos='.length), 10) || 0);
    } else if (arg === '--concurrency' && i + 1 < argv.length) {
      opts.concurrency = Math.min(8, Math.max(1, parseInt(argv[++i], 10) || 4));
    } else if (arg.startsWith('--concurrency=')) {
      opts.concurrency = Math.min(8, Math.max(1, parseInt(arg.slice('--concurrency='.length), 10) || 4));
    } else if (arg === '--no-neg-cache') {
      opts.ignoreNegCache = true;
    } else if (arg === '--force-refresh') {
      opts.forceRefresh = true;
    } else if (arg === '--zero-quota') {
      opts.zeroQuota = true;
    }
  }

  const hasExplicitScope = opts.aggregatorsFlag || opts.searchFlag || opts.repos.length > 0;
  return {
    enableSearch: hasExplicitScope ? opts.searchFlag : true,
    enableAggregators: hasExplicitScope ? opts.aggregatorsFlag : true,
    explicitRepos: opts.repos,
    maxNew: opts.maxNew,
    maxRepos: opts.maxRepos,
    concurrency: opts.concurrency,
    ignoreNegCache: opts.ignoreNegCache,
    forceRefresh: opts.forceRefresh,
    zeroQuota: opts.zeroQuota,
  };
}

function loadJsonFileSafe(filePath, fallback) {
  if (!existsSync(filePath)) return fallback;
  try {
    return JSON.parse(readFileSync(filePath, 'utf8'));
  } catch {
    return fallback;
  }
}

export async function crawlExperimentalTopics({
  repoRoot = REPO_ROOT,
  enableSearch = true,
  enableAggregators = true,
  explicitRepos = [],
  maxNew = 0,
  maxRepos = 0,
  concurrency = 4,
  ignoreNegCache = false,
  forceRefresh = false,
  zeroQuota = false,
  token = process.env.GITHUB_TOKEN || '',
  fetchImpl = fetch,
  nowMs = Date.now(),
  searchDelayMs = REPO_SEARCH_DELAY_MS,
  codeSearchDelayMs = CODE_SEARCH_DELAY_MS,
  catalogBaseUrl = process.env.AGY_MARKET_CATALOG_BASE_URL || DEFAULT_CATALOG_BASE_URL,
} = {}) {
  const ledgerPath = join(repoRoot, 'state', 'ledger.json');
  const cachePath = join(repoRoot, 'state', 'unverified-cache.json');
  const negCachePath = join(repoRoot, 'state', 'crawl-negative-cache.json');

  const ledger = loadJsonFileSafe(ledgerPath, { schemaVersion: 1, entries: {} });
  const existingCache = loadJsonFileSafe(cachePath, {
    schemaVersion: 1,
    plugins: [],
    readmes: {},
    readmesZh: {},
    readmesEn: {},
  });
  const negCache = loadJsonFileSafe(negCachePath, { schemaVersion: 1, entries: {} });
  if (!negCache.entries || typeof negCache.entries !== 'object') {
    negCache.entries = {};
  }

  // Build Track-1 composite dedup indices (never modifying ledger.json!)
  const track1RepoRoots = new Set();
  const track1RepoUrlRoots = new Set();
  const track1Ids = new Set();
  for (const e of Object.values(ledger.entries || {})) {
    const normRoot = normalizeRelPosix(e.pluginRoot || '.');
    if (e.entrySlug) track1Ids.add(e.entrySlug);
    if (Number(e.repositoryId) > 0) {
      track1RepoRoots.add(`${e.repositoryId}:${normRoot}`);
    }
    if (e.repoFullName) {
      track1RepoUrlRoots.add(`${String(e.repoFullName).toLowerCase()}:${normRoot}`);
    }
    for (const prev of e.previousRepoFullNames || []) {
      track1RepoUrlRoots.add(`${String(prev).toLowerCase()}:${normRoot}`);
    }
  }

  // Index existing positive cache by repoKey and repositoryId
  const cachedByRepoKey = new Map();
  const cachedByRepoId = new Map();
  for (const p of existingCache.plugins || []) {
    const rk = repoKeyFromUrl(p?.repository?.url);
    if (rk) {
      if (!cachedByRepoKey.has(rk)) cachedByRepoKey.set(rk, []);
      cachedByRepoKey.get(rk).push(p);
    }
    const rid = Number(p?.repository?.repositoryId || 0);
    if (rid > 0) {
      if (!cachedByRepoId.has(rid)) cachedByRepoId.set(rid, []);
      cachedByRepoId.get(rid).push(p);
    }
  }

  const stateIconsDir = join(repoRoot, 'state', 'icons');
  const iconsDir = join(repoRoot, 'dist', 'icons');
  mkdirSync(dirname(cachePath), { recursive: true });
  mkdirSync(stateIconsDir, { recursive: true });
  mkdirSync(iconsDir, { recursive: true });

  const apiHeaders = {
    Accept: 'application/vnd.github+json',
    'User-Agent': USER_AGENT,
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };

  const restState = {
    disabled: Boolean(zeroQuota),
    rateLimited: false,
    codeSearchDisabled: !token || Boolean(zeroQuota),
  };

  async function githubApiGetJson(url, { isCodeSearch = false } = {}) {
    if (restState.disabled || restState.rateLimited) {
      return { ok: false, status: 403, rateLimited: true, data: null };
    }
    if (isCodeSearch && restState.codeSearchDisabled) {
      return { ok: false, status: 401, rateLimited: false, data: null };
    }
    try {
      const res = await fetchWithLimit(url, {
        headers: apiHeaders,
        timeoutMs: 15_000,
        maxBytes: 4 * 1024 * 1024,
        fetchImpl,
      });
      const remaining = res.headers.get('x-ratelimit-remaining');
      if (remaining === '0') {
        if (isCodeSearch) {
          restState.codeSearchDisabled = true;
        } else {
          restState.rateLimited = true;
        }
      }
      if (res.status === 401 || res.status === 403 || res.status === 422 || res.status === 429) {
        const bodyText = res.buffer.toString('utf8');
        if (isCodeSearch) {
          restState.codeSearchDisabled = true;
          console.warn(`[crawl-topics] Code Search fail-open (HTTP ${res.status}); continuing with Repo Search & Aggregators.`);
          return { ok: false, status: res.status, rateLimited: res.status === 429 || res.status === 403, data: null };
        }
        if (res.status === 429 || remaining === '0' || /rate limit/i.test(bodyText)) {
          restState.rateLimited = true;
          console.warn(`[crawl-topics] GitHub REST API rate-limited (HTTP ${res.status}); switching remaining repos to zero-quota fallback.`);
          return { ok: false, status: res.status, rateLimited: true, data: null };
        }
        return { ok: false, status: res.status, rateLimited: false, data: null };
      }
      if (!res.ok) {
        return { ok: false, status: res.status, rateLimited: false, data: null };
      }
      return { ok: true, status: res.status, rateLimited: false, data: JSON.parse(res.buffer.toString('utf8')) };
    } catch {
      return { ok: false, status: 0, rateLimited: false, data: null };
    }
  }

  // Stage 1: Multi-channel candidate discovery & deduplication
  const candidates = new Map();
  const skipStats = {};
  const bumpSkip = (code) => {
    skipStats[code] = (skipStats[code] || 0) + 1;
  };

  function upsertCandidate(
    fullName,
    {
      repoMeta = null,
      explicitSubpaths = [],
      subdirGlobs = [],
      isMonorepo = false,
      maxPlugins = DEFAULT_MAX_PLUGINS_PER_REPO,
      source = 'unknown',
      priority = 50,
    } = {},
  ) {
    const cleanFull = String(fullName || '').trim().replace(/^https?:\/\/github\.com\//i, '').replace(/\/+$/, '');
    const parts = cleanFull.split('/');
    if (parts.length !== 2 || !parts[0] || !parts[1]) return;
    if (FIRST_PARTY_REPO_OWNERS.has(parts[0].toLowerCase())) return;
    if (repoMeta && (repoMeta.archived || repoMeta.disabled || repoMeta.is_template || isFirstPartyRepoMeta(repoMeta))) {
      return;
    }

    const key = cleanFull.toLowerCase();
    if (!candidates.has(key)) {
      candidates.set(key, {
        key,
        fullName: cleanFull,
        repoMeta: repoMeta || null,
        explicitSubpaths: new Set(),
        subdirGlobs: new Set(),
        isMonorepo: Boolean(isMonorepo),
        maxPlugins: maxPlugins || DEFAULT_MAX_PLUGINS_PER_REPO,
        discoverySources: new Set(),
        priority,
      });
    }
    const entry = candidates.get(key);
    if (repoMeta && (!entry.repoMeta || (!entry.repoMeta.id && repoMeta.id))) {
      entry.repoMeta = repoMeta;
      if (repoMeta.full_name) entry.fullName = repoMeta.full_name;
    }
    for (const sp of explicitSubpaths || []) {
      if (sp) entry.explicitSubpaths.add(normalizeRelPosix(sp));
    }
    for (const g of subdirGlobs || []) {
      if (g) entry.subdirGlobs.add(normalizeRelPosix(g));
    }
    if (isMonorepo) entry.isMonorepo = true;
    if (maxPlugins && maxPlugins > entry.maxPlugins) entry.maxPlugins = maxPlugins;
    if (source) entry.discoverySources.add(source);
    if (priority < entry.priority) entry.priority = priority;
  }

  // Priority 0: Explicit CLI `--repos`
  for (const rawRepo of explicitRepos || []) {
    const parsedUrl = rawRepo.startsWith('https://')
      ? parseSafeGitHubCandidateUrl(rawRepo)
      : parseSafeGitHubCandidateUrl(`https://github.com/${rawRepo}`);
    if (!parsedUrl) continue;
    upsertCandidate(parsedUrl.fullName, {
      explicitSubpaths: parsedUrl.explicitSubpath ? [parsedUrl.explicitSubpath] : [],
      source: 'cli-repo',
      priority: 0,
    });
  }

  // Priority 10-20: Channel B (`data/aggregators.json`) — zero REST API quota!
  if (enableAggregators) {
    const aggregators = loadAggregatorsConfig(repoRoot);
    for (const agg of aggregators) {
      if (agg.kind === 'monorepo' || agg.scanSubdirs) {
        upsertCandidate(agg.repo, {
          subdirGlobs: agg.subdirGlobs,
          isMonorepo: true,
          maxPlugins: agg.maxPlugins,
          source: `aggregator:${agg.id}`,
          priority: 10,
        });
      } else if (agg.kind === 'json-index') {
        upsertCandidate(agg.repo, {
          source: `aggregator:${agg.id}`,
          priority: 15,
        });
      }

      if (agg.files.length > 0) {
        const fetched = await fetchAggregatorCandidates(agg, { fetchImpl, userAgent: USER_AGENT });
        for (const item of fetched.candidates) {
          const isSelf = item.fullName.toLowerCase() === agg.repo.toLowerCase();
          upsertCandidate(item.fullName, {
            explicitSubpaths: item.explicitSubpaths,
            isMonorepo: isSelf && agg.kind === 'monorepo',
            subdirGlobs: isSelf ? agg.subdirGlobs : [],
            maxPlugins: isSelf ? agg.maxPlugins : DEFAULT_MAX_PLUGINS_PER_REPO,
            source: `aggregator:${agg.id}`,
            priority: isSelf ? 10 : 20,
          });
        }
      }
    }
  }

  // Priority 30-40: Channel A (High-SNR Repo Search + Fail-Open Code Search)
  if (enableSearch && !restState.disabled && !restState.rateLimited) {
    const repoQueries = buildChannelARepoQueries(nowMs);
    for (const qSpec of repoQueries) {
      if (restState.rateLimited) break;
      for (let page = 1; page <= qSpec.maxPages; page++) {
        if (restState.rateLimited) break;
        const url = `https://api.github.com/search/repositories?q=${encodeURIComponent(qSpec.query)}&sort=${encodeURIComponent(qSpec.sort)}&per_page=${qSpec.perPage}&page=${page}`;
        const res = await githubApiGetJson(url);
        if (!res.ok || !res.data) break;
        const items = Array.isArray(res.data.items) ? res.data.items : [];
        for (const repo of items) {
          upsertCandidate(repo.full_name, {
            repoMeta: repo,
            source: `search:${qSpec.id}`,
            priority: 30,
          });
        }
        const totalCount = Number(res.data.total_count || 0);
        if (items.length < qSpec.perPage || page * qSpec.perPage >= Math.min(1000, totalCount)) {
          break;
        }
        if (searchDelayMs > 0) await sleep(searchDelayMs);
      }
      if (searchDelayMs > 0 && !restState.rateLimited) await sleep(Math.min(searchDelayMs, 1000));
    }

    if (!restState.codeSearchDisabled && !restState.rateLimited) {
      for (const cSpec of CHANNEL_A_CODE_QUERIES) {
        if (restState.codeSearchDisabled || restState.rateLimited) break;
        for (let page = 1; page <= cSpec.maxPages; page++) {
          if (restState.codeSearchDisabled || restState.rateLimited) break;
          const url = `https://api.github.com/search/code?q=${encodeURIComponent(cSpec.query)}&per_page=100&page=${page}`;
          const res = await githubApiGetJson(url, { isCodeSearch: true });
          if (!res.ok || !res.data) break;
          const items = Array.isArray(res.data.items) ? res.data.items : [];
          for (const item of items) {
            const repoFullName = item?.repository?.full_name;
            if (!repoFullName) continue;
            const subpath = deriveExplicitSubpathFromCodePath(item.path);
            upsertCandidate(repoFullName, {
              explicitSubpaths: subpath ? [subpath] : [],
              source: `code:${cSpec.id}`,
              priority: 35,
            });
          }
          const totalCount = Number(res.data.total_count || 0);
          if (items.length < 100 || page * 100 >= Math.min(1000, totalCount)) {
            break;
          }
          if (codeSearchDelayMs > 0) await sleep(codeSearchDelayMs);
        }
        if (codeSearchDelayMs > 0 && !restState.codeSearchDisabled) await sleep(codeSearchDelayMs);
      }
    }
  }

  // Sort candidates by priority, then lexicographically for deterministic execution
  const orderedCandidates = [...candidates.values()].sort(
    (a, b) => a.priority - b.priority || a.key.localeCompare(b.key),
  );
  const effectiveCandidates = maxRepos > 0 ? orderedCandidates.slice(0, maxRepos) : orderedCandidates;

  // Stage 2 & 3: Snapshot resolution, cache reuse, negative cache, streaming download & validation
  const discoveredById = new Map();
  const readmes = {};
  const readmesZh = {};
  const readmesEn = {};
  const removedRepoKeys = new Set();
  const processedRepoKeys = new Set();
  let reusedCount = 0;
  let newlyValidatedRepos = 0;
  let newlyDiscoveredPlugins = 0;

  async function resolveRepoMeta(candidate) {
    if (candidate.repoMeta && Number(candidate.repoMeta.id) > 0) {
      return candidate.repoMeta;
    }
    if (!restState.disabled && !restState.rateLimited) {
      const apiRes = await githubApiGetJson(`https://api.github.com/repos/${candidate.fullName}`);
      if (apiRes.status === 404) {
        throw new Error(`ERR_REPO_NOT_FOUND: GitHub API returned 404 for ${candidate.fullName}`);
      }
      if (apiRes.ok && apiRes.data) {
        return apiRes.data;
      }
    }
    // Zero-quota fallback: try existing cache first, else lightweight HTML <meta> tags
    const cachedList = cachedByRepoKey.get(candidate.key) || [];
    if (cachedList.length > 0) {
      const sample = cachedList[0];
      const [ownerLogin, repoName] = candidate.fullName.split('/');
      return {
        id: Number(sample.repository?.repositoryId || 0),
        name: repoName,
        full_name: candidate.fullName,
        html_url: sample.repository?.url || `https://github.com/${candidate.fullName}`,
        description: sample.description?.en || sample.description?.zh || '',
        archived: false,
        disabled: false,
        stargazers_count: Number(sample.repository?.stars || 0),
        owner: { id: Number(sample.repository?.ownerId || 0), login: ownerLogin },
        topics: [],
      };
    }
    try {
      const htmlRes = await fetchWithLimit(`https://github.com/${candidate.fullName}`, {
        timeoutMs: 12_000,
        maxBytes: 512 * 1024,
        headers: { 'User-Agent': USER_AGENT, Accept: 'text/html' },
        fetchImpl,
      });
      if (htmlRes.status === 404) {
        throw new Error(`ERR_REPO_NOT_FOUND: GitHub returned 404 for ${candidate.fullName}`);
      }
      if (htmlRes.ok) {
        return parseGitHubRepoHtmlMeta(htmlRes.buffer.toString('utf8'), candidate.fullName);
      }
    } catch (err) {
      if (extractErrorCode(err) === 'ERR_REPO_NOT_FOUND') throw err;
    }
    const [ownerLogin, repoName] = candidate.fullName.split('/');
    return {
      id: 0,
      name: repoName,
      full_name: candidate.fullName,
      html_url: `https://github.com/${candidate.fullName}`,
      description: '',
      archived: false,
      disabled: false,
      stargazers_count: 0,
      owner: { id: 0, login: ownerLogin },
      topics: [],
    };
  }

  async function resolveSnapshot(repoMeta, candidate) {
    const repoId = Number(repoMeta.id || 0);
    const fullName = repoMeta.full_name || candidate.fullName;

    if (!restState.disabled && !restState.rateLimited && repoId > 0) {
      // Tier 1: Published non-draft, non-prerelease GitHub Release
      const relRes = await githubApiGetJson(`https://api.github.com/repositories/${repoId}/releases/latest`);
      if (relRes.ok && relRes.data && !relRes.data.draft && !relRes.data.prerelease) {
        const rel = relRes.data;
        const allowRelease = !candidate.isMonorepo || Boolean(parseSemver(rel.tag_name));
        if (allowRelease) {
          const asset = candidate.isMonorepo ? null : selectReleaseTarballAsset(rel.assets);
          const refRes = await githubApiGetJson(
            `https://api.github.com/repositories/${repoId}/commits/${encodeURIComponent(rel.tag_name)}`,
          );
          if (refRes.ok && refRes.data?.sha) {
            const tarballUrl = asset
              ? asset.browser_download_url
              : buildSourceArchiveUrl(fullName, refRes.data.sha, rel.tag_name);
            return {
              fullName,
              tier: 'release',
              tagName: rel.tag_name,
              commitSha: refRes.data.sha,
              tarballUrl,
              publishedAt: rel.published_at || refRes.data.commit?.committer?.date || new Date().toISOString(),
              requireSelfContained: !asset,
            };
          }
        }
      }

      // Tier 2: Pure stable SemVer Git Tags
      if (!restState.rateLimited) {
        const tagsRes = await githubApiGetJson(`https://api.github.com/repositories/${repoId}/tags?per_page=30`);
        if (tagsRes.ok && Array.isArray(tagsRes.data) && tagsRes.data.length > 0) {
          const bestTagName = pickHighestStableSemverTag(tagsRes.data.map((t) => t?.name).filter(Boolean));
          if (bestTagName) {
            const tagObj = tagsRes.data.find((t) => t?.name === bestTagName);
            const sha = tagObj?.commit?.sha || '';
            if (/^[0-9a-f]{40}$/i.test(sha)) {
              let publishedAt = new Date().toISOString();
              const commitRes = await githubApiGetJson(`https://api.github.com/repositories/${repoId}/commits/${sha}`);
              if (commitRes.ok && commitRes.data?.commit?.committer?.date) {
                publishedAt = commitRes.data.commit.committer.date;
              }
              const normSha = sha.toLowerCase();
              return {
                fullName,
                tier: 'tag',
                tagName: bestTagName,
                commitSha: normSha,
                tarballUrl: buildSourceArchiveUrl(fullName, normSha, bestTagName),
                publishedAt,
                requireSelfContained: true,
              };
            }
          }
        }
      }

      // Tier 3 (Channel C): Default branch 40-hex Commit SHA
      if (!restState.rateLimited) {
        const branch = repoMeta.default_branch || 'main';
        const headRes = await githubApiGetJson(
          `https://api.github.com/repositories/${repoId}/commits/${encodeURIComponent(branch)}`,
        );
        if (headRes.ok && headRes.data?.sha) {
          const sha = String(headRes.data.sha).toLowerCase();
          return {
            fullName,
            tier: 'commit',
            tagName: null,
            commitSha: sha,
            tarballUrl: `https://github.com/${fullName}/archive/${sha}.tar.gz`,
            publishedAt:
              headRes.data.commit?.committer?.date || headRes.data.commit?.author?.date || new Date().toISOString(),
            requireSelfContained: true,
          };
        }
      }
    }

    // Zero-REST-API-quota fallback (HEAD /releases/latest + git-upload-pack info/refs + .atom)
    return resolveRepoSnapshotZeroQuota(fullName, {
      fetchImpl,
      userAgent: USER_AGENT,
      preferFullRepoArchive: candidate.isMonorepo,
    });
  }

  function recordCacheReuse(cachedList, repoMeta) {
    for (const oldEntry of cachedList) {
      const normRoot = normalizeRelPosix(oldEntry.repository?.pluginRoot || '.');
      const rid = Number(repoMeta?.id || oldEntry.repository?.repositoryId || 0);
      const rk = repoKeyFromUrl(oldEntry.repository?.url);
      if (track1Ids.has(oldEntry.id)) continue;
      if (rid > 0 && track1RepoRoots.has(`${rid}:${normRoot}`)) continue;
      if (rk && track1RepoUrlRoots.has(`${rk}:${normRoot}`)) continue;

      const updatedEntry = {
        ...oldEntry,
        repository: {
          ...oldEntry.repository,
          repositoryId: rid || oldEntry.repository?.repositoryId || 0,
          ownerId: Number(repoMeta?.owner?.id || oldEntry.repository?.ownerId || 0),
          stars:
            Number(repoMeta?.stargazers_count || 0) > 0
              ? Number(repoMeta.stargazers_count)
              : Number(oldEntry.repository?.stars || 0),
          pluginRoot: normRoot,
        },
        forceScopedInstall: true,
      };
      discoveredById.set(updatedEntry.id, updatedEntry);
      if (existingCache.readmes?.[updatedEntry.id]) {
        readmes[updatedEntry.id] = existingCache.readmes[updatedEntry.id];
      }
      if (existingCache.readmesZh?.[updatedEntry.id]) {
        readmesZh[updatedEntry.id] = existingCache.readmesZh[updatedEntry.id];
      }
      if (existingCache.readmesEn?.[updatedEntry.id]) {
        readmesEn[updatedEntry.id] = existingCache.readmesEn[updatedEntry.id];
      }
      reusedCount += 1;
    }
  }

  function saveBuiltRecord(built) {
    const entry = built.pluginEntry;
    discoveredById.set(entry.id, entry);
    if (built.readmeMarkdown) readmes[entry.id] = built.readmeMarkdown;
    if (built.readmeZhMarkdown) readmesZh[entry.id] = built.readmeZhMarkdown;
    if (built.readmeEnMarkdown) readmesEn[entry.id] = built.readmeEnMarkdown;
    if (built.iconArtifact) {
      const iconFile = `${entry.id}${built.iconArtifact.ext}`;
      writeFileSync(join(stateIconsDir, iconFile), built.iconArtifact.sanitizedBuffer);
      writeFileSync(join(iconsDir, iconFile), built.iconArtifact.sanitizedBuffer);
    }
    newlyDiscoveredPlugins += 1;
  }

  async function processCandidate(candidate) {
    processedRepoKeys.add(candidate.key);

    // Check negative cache for confirmed 404 before network
    const existingNeg = negCache.entries[candidate.key];
    if (
      !ignoreNegCache &&
      !forceRefresh &&
      existingNeg &&
      existingNeg.reason === 'ERR_REPO_NOT_FOUND' &&
      nowMs < Date.parse(existingNeg.retryAfter || 0)
    ) {
      bumpSkip('NEG_CACHE_HIT');
      return;
    }

    let repoMeta;
    try {
      repoMeta = await resolveRepoMeta(candidate);
    } catch (err) {
      const code = extractErrorCode(err);
      bumpSkip(code);
      if (code === 'ERR_REPO_NOT_FOUND') {
        removedRepoKeys.add(candidate.key);
        negCache.entries[candidate.key] = {
          repositoryId: 0,
          headSha: null,
          reason: code,
          checkedAt: new Date(nowMs).toISOString(),
          retryAfter: new Date(nowMs + NEG_CACHE_TTL_MS).toISOString(),
        };
      }
      return;
    }

    if (repoMeta.archived || repoMeta.disabled || repoMeta.is_template || isFirstPartyRepoMeta(repoMeta)) {
      removedRepoKeys.add(candidate.key);
      bumpSkip('ERR_REPO_INELIGIBLE');
      return;
    }

    // Fast skip for known single-plugin Track-1 repositories (preserving Monorepos that may host other subplugins)
    const repoId = Number(repoMeta.id || 0);
    const canonicalKey = String(repoMeta.full_name || candidate.fullName).toLowerCase();
    if (
      !candidate.isMonorepo &&
      candidate.explicitSubpaths.size === 0 &&
      ((repoId > 0 && track1RepoRoots.has(`${repoId}:.`)) || track1RepoUrlRoots.has(`${canonicalKey}:.`))
    ) {
      bumpSkip('SKIP_TRACK1');
      return;
    }

    let snapshot;
    try {
      snapshot = await resolveSnapshot(repoMeta, candidate);
    } catch (err) {
      const code = extractErrorCode(err);
      bumpSkip(code);
      if (code === 'ERR_REPO_NOT_FOUND') {
        removedRepoKeys.add(candidate.key);
        negCache.entries[candidate.key] = {
          repositoryId: repoId,
          headSha: null,
          reason: code,
          checkedAt: new Date(nowMs).toISOString(),
          retryAfter: new Date(nowMs + NEG_CACHE_TTL_MS).toISOString(),
        };
      } else if (isTransientErrorCode(code)) {
        const prevList =
          (repoId > 0 ? cachedByRepoId.get(repoId) : null) || cachedByRepoKey.get(candidate.key) || [];
        if (prevList.length > 0) recordCacheReuse(prevList, repoMeta);
      }
      return;
    }

    // Sync redirected fullName back into repoMeta
    if (snapshot.fullName && snapshot.fullName.toLowerCase() !== String(repoMeta.full_name || '').toLowerCase()) {
      const [newOwner, newName] = snapshot.fullName.split('/');
      repoMeta = {
        ...repoMeta,
        full_name: snapshot.fullName,
        name: newName || repoMeta.name,
        html_url: `https://github.com/${snapshot.fullName}`,
        owner: { ...repoMeta.owner, login: newOwner || repoMeta.owner?.login },
      };
    }

    const updatedCanonicalKey = String(repoMeta.full_name || candidate.fullName).toLowerCase();
    if (
      !candidate.isMonorepo &&
      candidate.explicitSubpaths.size === 0 &&
      track1RepoUrlRoots.has(`${updatedCanonicalKey}:.`)
    ) {
      bumpSkip('SKIP_TRACK1');
      return;
    }

    // Positive cache reuse: skip tarball download when (tarballUrl, commitSha) unchanged
    const cachedList =
      (repoId > 0 ? cachedByRepoId.get(repoId) : null) ||
      cachedByRepoKey.get(updatedCanonicalKey) ||
      cachedByRepoKey.get(candidate.key) ||
      [];
    if (
      !forceRefresh &&
      cachedList.length > 0 &&
      cachedList.every(
        (p) => p.distribution?.tarballUrl === snapshot.tarballUrl && p.commitSha === snapshot.commitSha,
      )
    ) {
      recordCacheReuse(cachedList, repoMeta);
      return;
    }

    // Negative cache check (skip when HEAD commitSha unchanged & TTL active)
    const negEntry = negCache.entries[updatedCanonicalKey] || negCache.entries[candidate.key];
    if (
      !ignoreNegCache &&
      !forceRefresh &&
      negEntry &&
      negEntry.headSha &&
      negEntry.headSha === snapshot.commitSha &&
      nowMs < Date.parse(negEntry.retryAfter || 0)
    ) {
      bumpSkip('NEG_CACHE_HIT');
      return;
    }

    // Budget guard for `--max-new`
    if (maxNew > 0 && newlyValidatedRepos >= maxNew) {
      if (cachedList.length > 0) recordCacheReuse(cachedList, repoMeta);
      bumpSkip('MAX_NEW_CAP');
      return;
    }

    let tarballBuf;
    try {
      tarballBuf = await downloadTarballBuffer(snapshot.tarballUrl, { fetchImpl, userAgent: USER_AGENT });
    } catch (err) {
      const code = extractErrorCode(err);
      bumpSkip(code);
      if (isTransientErrorCode(code) && cachedList.length > 0) {
        recordCacheReuse(cachedList, repoMeta);
      }
      return;
    }

    try {
      const out = buildTrack2PluginRecordsForArchive({
        repoMeta,
        releaseInfo: {
          tagName: snapshot.tagName,
          commitSha: snapshot.commitSha,
          tarballUrl: snapshot.tarballUrl,
          publishedAt: snapshot.publishedAt || new Date(nowMs).toISOString(),
          requireSelfContained: snapshot.requireSelfContained,
        },
        tarballBuffer: tarballBuf,
        explicitSubpaths: [...candidate.explicitSubpaths],
        subdirGlobs: [...candidate.subdirGlobs],
        isMonorepo: candidate.isMonorepo,
        maxPlugins: candidate.maxPlugins,
        track1RepoRoots,
        track1RepoUrlRoots,
        catalogBaseUrl,
      });

      if (out.records.length > 0) {
        delete negCache.entries[candidate.key];
        delete negCache.entries[updatedCanonicalKey];
        newlyValidatedRepos += 1;
        for (const built of out.records) {
          saveBuiltRecord(built);
        }
        for (const sk of out.skipped) {
          bumpSkip(`SUBDIR_${sk.code}`);
        }
      } else {
        const primaryCode = out.skipped[0]?.code || 'ERR_NOT_ANTIGRAVITY_PLUGIN';
        bumpSkip(primaryCode);
        negCache.entries[updatedCanonicalKey] = {
          repositoryId: repoId,
          headSha: snapshot.commitSha,
          reason: primaryCode,
          checkedAt: new Date(nowMs).toISOString(),
          retryAfter: new Date(nowMs + NEG_CACHE_TTL_MS).toISOString(),
        };
      }
    } catch (err) {
      const code = extractErrorCode(err);
      bumpSkip(code);
      if (!isTransientErrorCode(code)) {
        negCache.entries[updatedCanonicalKey] = {
          repositoryId: repoId,
          headSha: snapshot.commitSha,
          reason: code,
          checkedAt: new Date(nowMs).toISOString(),
          retryAfter: new Date(nowMs + NEG_CACHE_TTL_MS).toISOString(),
        };
      } else if (cachedList.length > 0) {
        recordCacheReuse(cachedList, repoMeta);
      }
    }
  }

  // Gentle bounded concurrency worker pool
  let cursor = 0;
  const workerCount = Math.min(Math.max(1, concurrency), Math.max(1, effectiveCandidates.length));
  await Promise.all(
    Array.from({ length: workerCount }, async () => {
      while (cursor < effectiveCandidates.length) {
        const idx = cursor++;
        await processCandidate(effectiveCandidates[idx]);
      }
    }),
  );

  // Merge preserved entries from existing cache when running partial/targeted crawls
  // (or when a previously valid repo wasn't visited in this partial run).
  const isPartialRun = !enableSearch || maxNew > 0 || maxRepos > 0 || restState.rateLimited;
  if (isPartialRun) {
    for (const oldEntry of existingCache.plugins || []) {
      if (!oldEntry?.id || discoveredById.has(oldEntry.id)) continue;
      const rk = repoKeyFromUrl(oldEntry.repository?.url);
      if (rk && removedRepoKeys.has(rk)) continue;
      if (rk && processedRepoKeys.has(rk) && forceRefresh) continue;
      const normRoot = normalizeRelPosix(oldEntry.repository?.pluginRoot || '.');
      const rid = Number(oldEntry.repository?.repositoryId || 0);
      if (track1Ids.has(oldEntry.id)) continue;
      if (rid > 0 && track1RepoRoots.has(`${rid}:${normRoot}`)) continue;
      if (rk && track1RepoUrlRoots.has(`${rk}:${normRoot}`)) continue;

      discoveredById.set(oldEntry.id, {
        ...oldEntry,
        repository: { ...oldEntry.repository, pluginRoot: normRoot },
        forceScopedInstall: true,
      });
      if (existingCache.readmes?.[oldEntry.id]) readmes[oldEntry.id] = existingCache.readmes[oldEntry.id];
      if (existingCache.readmesZh?.[oldEntry.id]) readmesZh[oldEntry.id] = existingCache.readmesZh[oldEntry.id];
      if (existingCache.readmesEn?.[oldEntry.id]) readmesEn[oldEntry.id] = existingCache.readmesEn[oldEntry.id];
    }
  }

  // Prune expired negative cache entries (> 14 days old)
  const prunedNegEntries = {};
  for (const [k, v] of Object.entries(negCache.entries)) {
    if (!v || !v.retryAfter) continue;
    if (nowMs - Date.parse(v.retryAfter) > NEG_CACHE_TTL_MS) continue;
    prunedNegEntries[k] = v;
  }

  const discoveredPlugins = [...discoveredById.values()].sort((a, b) => a.id.localeCompare(b.id));

  writeFileSync(
    cachePath,
    `${JSON.stringify(
      {
        schemaVersion: 1,
        plugins: discoveredPlugins,
        readmes: sortRecordKeys(readmes),
        readmesZh: sortRecordKeys(readmesZh),
        readmesEn: sortRecordKeys(readmesEn),
      },
      null,
      2,
    )}\n`,
    'utf8',
  );

  writeFileSync(
    negCachePath,
    `${JSON.stringify({ schemaVersion: 1, entries: sortRecordKeys(prunedNegEntries) }, null, 2)}\n`,
    'utf8',
  );

  console.log(
    `[crawl-topics] Summary: candidates=${effectiveCandidates.length}, total=${discoveredPlugins.length}, newPlugins=${newlyDiscoveredPlugins}, reused=${reusedCount}, skipped=${JSON.stringify(sortRecordKeys(skipStats))}`,
  );

  return {
    candidates: effectiveCandidates.length,
    discovered: discoveredPlugins.length,
    newPlugins: newlyDiscoveredPlugins,
    reused: reusedCount,
    skipped: sortRecordKeys(skipStats),
  };
}

if (import.meta.url === pathToFileURL(resolve(process.argv[1] || '')).href) {
  const cliOpts = parseCrawlerCliArgs(process.argv.slice(2));
  const out = await crawlExperimentalTopics(cliOpts);
  console.log(`[crawl-topics] Done (${out.discovered} Track-2 plugins in cache)`);
}
