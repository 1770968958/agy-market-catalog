// Two-Stage Alias-Batched GitHub GraphQL Client (`scripts/lib/graphql-batch.mjs`).
//
// Zero-dependency ESM engine for:
//   - Stage 2A-Heartbeat (`B=50`, NO `rootTree`, ~1 pt / 50 cached repos)
//   - Stage 2A-Novel (`B=20`, depth-2 `Tree` + manifest existence, ~1 pt / 20 novel repos, 99.1% verified recall)
//   - Stage 2B-Inspect (`B=20`, `releases(first:5)` + `refs(TAG_COMMIT_DATE)` w/ `committedDate` + manifest blobs)
//   - Author-Centric Snowball Expansion (`B=20`, `repositoryOwner(login).repositories(ownerAffiliations:[OWNER])`)
//   - Track-1 Dual Lookup (`nodes(ids:)` + aliased `repository(owner,name)` + `releases(first:10)` for RepoJacking/Rename)
//
// Hardening invariants:
//   - All owner/repo/login values passed strictly via GraphQL `variables` (zero query string injection).
//   - Adaptive batch halving (`50 -> 25 -> 10` or `20 -> 10 -> 5`) on HTTP 502/504 or GraphQL timeout.
//   - Partial `NOT_FOUND` tolerance: never aborts an entire batch when individual aliases return `NOT_FOUND`.
//   - Empty repository guard: `defaultBranchRef == null` -> `ERR_EMPTY_REPO` without throwing.

import {
  buildSourceArchiveUrl,
  FIRST_PARTY_REPO_OWNERS,
  normalizeRelPosix,
  parseSemver,
} from './constants.mjs';
import {
  EXCLUDED_SCAN_DIR_SEGMENTS,
  pickHighestStableSemverTag,
  selectReleaseTarballAsset,
} from './discovery-sources.mjs';

export const GITHUB_GRAPHQL_ENDPOINT = 'https://api.github.com/graphql';
export const DEFAULT_GRAPHQL_USER_AGENT = 'agy-market-catalog-graphql/1.6';

export const EXTENDED_FIRST_PARTY_OWNERS = new Set([
  ...FIRST_PARTY_REPO_OWNERS,
  'google-labs-code',
  'googlecloudplatform',
]);

// Empirically verified on 114 genuine non-root repos in live state (depth-2 Tree + AGY-name bypass = 99.1% recall).
export const NOVEL_STAGE2A_SUBDIR_WHITELIST = new Set([
  'plugins',
  'plugin',
  'packages',
  'extensions',
  '.agents',
  '.agent',
  'antigravity',
  'antigravity-plugin',
  'agy',
  'community',
  'adapters',
  'skills',
  'host_resources',
]);

export const NOVEL_STAGE2A_EXCLUDED_DIRS = new Set([
  ...EXCLUDED_SCAN_DIR_SEGMENTS,
  '.claude-plugin',
  '.cursor-plugin',
  '.codex-plugin',
  '.opencode',
  'locales',
  'plugin-src',
  'dsh',
  'copilot',
]);

const GITHUB_OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const GITHUB_REPO_RE = /^[A-Za-z0-9._-]+$/;
const AGY_NAME_RE = /(?:antigravity|^agy-)/i;
const AGY_PLUGIN_TOPIC_RE = /^antigravity-plugins?$/i;

/**
 * Normalizes a repository specifier (`"owner/repo"`, `{ owner, repo }`, `{ fullName }`, `{ repoFullName }`)
 * into `{ owner, repo, fullName, key }`. Returns `null` if malformed.
 */
export function parseOwnerRepoSpec(spec) {
  let owner = '';
  let repo = '';
  if (typeof spec === 'string') {
    const cleaned = spec
      .trim()
      .replace(/^https?:\/\/github\.com\//i, '')
      .replace(/\.git$/i, '')
      .replace(/\/+$/, '');
    const parts = cleaned.split('/');
    if (parts.length !== 2) return null;
    [owner, repo] = parts;
  } else if (spec && typeof spec === 'object') {
    if (typeof spec.owner === 'string' && typeof spec.repo === 'string') {
      owner = spec.owner.trim();
      repo = spec.repo.trim().replace(/\.git$/i, '');
    } else {
      const raw = spec.fullName || spec.repoFullName || spec.full_name || '';
      return parseOwnerRepoSpec(String(raw));
    }
  } else {
    return null;
  }

  if (!owner || !repo || repo === '.' || repo === '..') return null;
  if (!GITHUB_OWNER_RE.test(owner) || !GITHUB_REPO_RE.test(repo)) return null;
  const fullName = `${owner}/${repo}`;
  return { owner, repo, fullName, key: fullName.toLowerCase() };
}

function deterministicHash32(str) {
  let h = 2166136261;
  const s = String(str || '');
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function extractOwnerId(ownerObj) {
  if (!ownerObj || typeof ownerObj !== 'object') return 0;
  return Number(ownerObj.databaseId || 0);
}

function normalizeParentNode(parent) {
  if (!parent || typeof parent !== 'object' || !parent.nameWithOwner) return null;
  const oid = parent.defaultBranchRef?.target?.oid || null;
  return {
    fullName: String(parent.nameWithOwner),
    pushedAt: parent.pushedAt || null,
    isArchived: Boolean(parent.isArchived),
    defaultBranch: parent.defaultBranchRef?.name || null,
    headSha: oid ? String(oid).toLowerCase() : null,
  };
}

function normalizeTagNode(refNode) {
  if (!refNode || typeof refNode.name !== 'string') return null;
  const target = refNode.target || null;
  if (!target) return null;
  // Annotated Tag peels to `target.target`; lightweight tag points directly to Commit
  const peeled = target.target && typeof target.target === 'object' ? target.target : target;
  const oid = peeled?.oid || target?.oid || null;
  if (!oid || !/^[0-9a-f]{40}$/i.test(String(oid))) return null;
  const committedDate = peeled?.committedDate || target?.committedDate || null;
  return {
    name: refNode.name,
    commitSha: String(oid).toLowerCase(),
    committedDate,
  };
}

function normalizeReleaseNode(relNode, tagsByName = new Map()) {
  if (!relNode || typeof relNode.tagName !== 'string') return null;
  const tagName = relNode.tagName.trim();
  if (!tagName) return null;
  const rawOid = relNode.tagCommit?.oid || tagsByName.get(tagName)?.commitSha || null;
  const commitSha = rawOid && /^[0-9a-f]{40}$/i.test(String(rawOid)) ? String(rawOid).toLowerCase() : null;
  const rawAssets = Array.isArray(relNode.releaseAssets?.nodes) ? relNode.releaseAssets.nodes : [];
  const assets = rawAssets
    .filter((a) => a && typeof a.name === 'string' && typeof a.downloadUrl === 'string')
    .map((a) => ({
      name: a.name,
      browser_download_url: a.downloadUrl,
      downloadUrl: a.downloadUrl,
      size: Number(a.size || 0),
    }));
  return {
    tagName,
    isDraft: Boolean(relNode.isDraft),
    isPrerelease: Boolean(relNode.isPrerelease),
    publishedAt: relNode.publishedAt || relNode.tagCommit?.committedDate || tagsByName.get(tagName)?.committedDate || null,
    commitSha,
    assets,
  };
}

function normalizeBaseRepoNode(node, fallbackSpec) {
  const fullName = String(node.nameWithOwner || fallbackSpec.fullName);
  const parts = fullName.split('/');
  const ownerLogin = String(node.owner?.login || parts[0] || fallbackSpec.owner);
  const name = String(node.name || parts[1] || fallbackSpec.repo);
  const defaultBranch = node.defaultBranchRef?.name ? String(node.defaultBranchRef.name) : null;
  const rawOid = node.defaultBranchRef?.target?.oid || null;
  const headSha = rawOid && /^[0-9a-f]{40}$/i.test(String(rawOid)) ? String(rawOid).toLowerCase() : null;
  const isEmpty = !node.defaultBranchRef || !headSha;

  return {
    status: isEmpty ? 'empty' : 'ok',
    errorCode: isEmpty ? 'ERR_EMPTY_REPO' : null,
    key: fullName.toLowerCase(),
    requestedKey: fallbackSpec.key,
    nodeId: typeof node.id === 'string' ? node.id : null,
    repositoryId: Number(node.databaseId || 0),
    ownerId: extractOwnerId(node.owner),
    ownerLogin,
    name,
    fullName,
    url: String(node.url || `https://github.com/${fullName}`),
    description: typeof node.description === 'string' ? node.description : '',
    isArchived: Boolean(node.isArchived),
    isDisabled: Boolean(node.isDisabled),
    isTemplate: Boolean(node.isTemplate),
    isFork: Boolean(node.isFork),
    pushedAt: node.pushedAt || null,
    stars: Number(node.stargazerCount || 0),
    licenseSpdxId: node.licenseInfo?.spdxId || null,
    defaultBranch,
    headSha,
    headCommittedAt: node.defaultBranchRef?.target?.committedDate || node.pushedAt || null,
    parent: normalizeParentNode(node.parent),
  };
}

function parseGraphqlErrorsByAlias(errors) {
  const byAlias = new Map();
  let hasRateLimit = false;
  let hasTimeout = false;
  for (const err of Array.isArray(errors) ? errors : []) {
    if (!err || typeof err !== 'object') continue;
    const type = String(err.type || '');
    const msg = String(err.message || '');
    if (type === 'RATE_LIMITED' || /rate\s*limit/i.test(msg)) {
      hasRateLimit = true;
    }
    if (type === 'TIMEOUT' || /timed?\s*out|something went wrong/i.test(msg)) {
      hasTimeout = true;
    }
    if (Array.isArray(err.path) && err.path.length > 0) {
      const alias = String(err.path[0]);
      if (!byAlias.has(alias)) {
        byAlias.set(alias, { type, message: msg });
      }
    }
  }
  return { byAlias, hasRateLimit, hasTimeout };
}

function isRetryableGatewayStatus(status) {
  return status === 502 || status === 503 || status === 504;
}

/**
 * Sends a single GraphQL POST request with timeout & JSON parsing.
 */
async function postGraphql(query, variables, { token, endpoint, fetchImpl, timeoutMs, userAgent }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(endpoint, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
        'User-Agent': userAgent,
      },
      body: JSON.stringify({ query, variables }),
      signal: controller.signal,
    });
    const status = res.status;
    const resetHeader = res.headers?.get?.('x-ratelimit-reset');
    const retryAfterHeader = res.headers?.get?.('retry-after');
    const text = await res.text().catch(() => '');

    if (isRetryableGatewayStatus(status)) {
      return { ok: false, status, gatewayTimeout: true, rateLimited: false, payload: null, text };
    }
    if (status === 401) {
      return { ok: false, status, gatewayTimeout: false, rateLimited: false, authFailed: true, payload: null, text };
    }
    if (status === 429 || (status === 403 && /rate\s*limit|secondary/i.test(text))) {
      return {
        ok: false,
        status,
        gatewayTimeout: false,
        rateLimited: true,
        resetAtMs: resetHeader ? Number(resetHeader) * 1000 : retryAfterHeader ? Date.now() + Number(retryAfterHeader) * 1000 : null,
        payload: null,
        text,
      };
    }
    if (!res.ok) {
      return { ok: false, status, gatewayTimeout: false, rateLimited: false, payload: null, text };
    }

    let payload = null;
    try {
      payload = JSON.parse(text);
    } catch {
      return { ok: false, status, gatewayTimeout: true, rateLimited: false, payload: null, text };
    }
    return { ok: true, status, gatewayTimeout: false, rateLimited: false, payload, text };
  } catch (err) {
    const isAbort = err?.name === 'AbortError' || /abort|timeout|ETIMEDOUT/i.test(String(err?.message || err));
    return {
      ok: false,
      status: 0,
      gatewayTimeout: isAbort,
      rateLimited: false,
      networkError: !isAbort,
      payload: null,
      text: String(err?.message || err),
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Core adaptive batch executor with automatic batch halving on HTTP 502/504 or GraphQL timeout.
 */
async function executeAdaptiveGraphqlBatches(
  items,
  {
    batchSize,
    minBatchSize = 10,
    token = process.env.GITHUB_TOKEN || '',
    endpoint = GITHUB_GRAPHQL_ENDPOINT,
    fetchImpl = fetch,
    timeoutMs = 20_000,
    userAgent = DEFAULT_GRAPHQL_USER_AGENT,
    buildPayload,
    onChunkData,
    onChunkFailed,
  },
) {
  const stats = {
    requestsMade: 0,
    totalCost: 0,
    rateLimit: null,
    rateLimited: false,
    authFailed: false,
    batchHalvings: 0,
    errors: [],
  };

  if (!token) {
    stats.errors.push({ code: 'ERR_GRAPHQL_NO_TOKEN', message: 'GraphQL token is required' });
    return stats;
  }
  if (!Array.isArray(items) || items.length === 0) {
    return stats;
  }

  // Queue of pending chunks (LIFO so halved sub-chunks execute immediately in order)
  const queue = [];
  const initSize = Math.max(1, Math.floor(batchSize));
  for (let i = 0; i < items.length; i += initSize) {
    queue.push(items.slice(i, i + initSize));
  }
  queue.reverse();

  while (queue.length > 0) {
    if (stats.rateLimited || stats.authFailed) break;
    const chunk = queue.pop();
    const { query, variables } = buildPayload(chunk);
    stats.requestsMade += 1;
    const resp = await postGraphql(query, variables, { token, endpoint, fetchImpl, timeoutMs, userAgent });

    if (resp.authFailed) {
      stats.authFailed = true;
      stats.errors.push({ code: 'ERR_GRAPHQL_AUTH', status: resp.status, message: resp.text.slice(0, 200) });
      onChunkFailed(chunk, 'ERR_GRAPHQL_AUTH');
      break;
    }

    if (resp.rateLimited) {
      stats.rateLimited = true;
      stats.errors.push({ code: 'ERR_GRAPHQL_RATE_LIMITED', status: resp.status, resetAtMs: resp.resetAtMs || null });
      onChunkFailed(chunk, 'ERR_GRAPHQL_RATE_LIMITED');
      break;
    }

    const parsedErrs = resp.payload ? parseGraphqlErrorsByAlias(resp.payload.errors) : { byAlias: new Map(), hasRateLimit: false, hasTimeout: false };
    const noUsableData = !resp.payload || !resp.payload.data || Object.keys(resp.payload.data).length === 0;
    const shouldHalve =
      (resp.gatewayTimeout || (parsedErrs.hasTimeout && noUsableData)) &&
      chunk.length > Math.max(1, minBatchSize);

    if (shouldHalve) {
      stats.batchHalvings += 1;
      const half = Math.max(1, Math.floor(chunk.length / 2));
      const right = chunk.slice(half);
      const left = chunk.slice(0, half);
      // Push right first so left pops first (preserves original ordering)
      if (right.length > 0) queue.push(right);
      if (left.length > 0) queue.push(left);
      continue;
    }

    if (!resp.ok || !resp.payload) {
      const code = resp.gatewayTimeout ? 'ERR_GRAPHQL_TIMEOUT' : 'ERR_TRANSIENT_HTTP';
      stats.errors.push({ code, status: resp.status, count: chunk.length });
      onChunkFailed(chunk, code);
      continue;
    }

    const rl = resp.payload.data?.rateLimit || null;
    if (rl && typeof rl === 'object') {
      stats.totalCost += Number(rl.cost || 1);
      stats.rateLimit = {
        cost: Number(rl.cost || 1),
        remaining: Number(rl.remaining ?? 0),
        resetAt: rl.resetAt || null,
      };
      if (rl.remaining === 0) {
        stats.rateLimited = true;
      }
    } else {
      stats.totalCost += 1;
    }

    if (parsedErrs.hasRateLimit) {
      stats.rateLimited = true;
    }

    onChunkData(chunk, resp.payload.data || {}, parsedErrs.byAlias);
  }

  return stats;
}

function dedupeRepoSpecs(repos) {
  const unique = [];
  const seen = new Set();
  for (const raw of Array.isArray(repos) ? repos : []) {
    const parsed = parseOwnerRepoSpec(raw);
    if (!parsed || seen.has(parsed.key)) continue;
    seen.add(parsed.key);
    unique.push(parsed);
  }
  return unique;
}

function buildHeartbeatQuery(chunk) {
  const varDecls = [];
  const variables = {};
  const fields = [];
  for (let i = 0; i < chunk.length; i++) {
    const spec = chunk[i];
    varDecls.push(`$o${i}: String!`, `$n${i}: String!`);
    variables[`o${i}`] = spec.owner;
    variables[`n${i}`] = spec.repo;
    fields.push(`
      r${i}: repository(owner: $o${i}, name: $n${i}) {
        id
        databaseId
        name
        nameWithOwner
        url
        isArchived
        isDisabled
        isTemplate
        isFork
        pushedAt
        stargazerCount
        owner {
          login
          ... on User { databaseId }
          ... on Organization { databaseId }
        }
        parent {
          nameWithOwner
          pushedAt
          isArchived
          defaultBranchRef {
            name
            target { oid }
          }
        }
        defaultBranchRef {
          name
          target {
            oid
            ... on Commit { committedDate }
          }
        }
      }`);
  }
  const query = `query Stage2AHeartbeat(${varDecls.join(', ')}) {\n${fields.join('\n')}\n  rateLimit { cost remaining resetAt }\n}`;
  return { query, variables };
}

/**
 * Stage 2A-Heartbeat: ultra-cheap cached repo liveness & `HEAD` OID check (`B=50`, NO `rootTree`, ~1 pt / 50 repos).
 */
export async function batchHeartbeatStage2A(
  repos,
  {
    batchSize = 50,
    minBatchSize = 10,
    token = process.env.GITHUB_TOKEN || '',
    endpoint = GITHUB_GRAPHQL_ENDPOINT,
    fetchImpl = fetch,
    timeoutMs = 20_000,
    userAgent = DEFAULT_GRAPHQL_USER_AGENT,
  } = {},
) {
  const specs = dedupeRepoSpecs(repos);
  const results = new Map();
  const notFound = new Set();
  const failed = new Map();

  const stats = await executeAdaptiveGraphqlBatches(specs, {
    batchSize,
    minBatchSize,
    token,
    endpoint,
    fetchImpl,
    timeoutMs,
    userAgent,
    buildPayload: buildHeartbeatQuery,
    onChunkData: (chunk, data, errorsByAlias) => {
      for (let i = 0; i < chunk.length; i++) {
        const spec = chunk[i];
        const alias = `r${i}`;
        const node = data[alias];
        const aliasErr = errorsByAlias.get(alias);
        if (!node) {
          if (aliasErr?.type === 'NOT_FOUND') {
            notFound.add(spec.key);
            results.set(spec.key, {
              status: 'not_found',
              errorCode: 'ERR_REPO_NOT_FOUND',
              key: spec.key,
              requestedKey: spec.key,
              fullName: spec.fullName,
            });
          } else {
            const code = aliasErr?.type === 'RATE_LIMITED' ? 'ERR_GRAPHQL_RATE_LIMITED' : 'ERR_GRAPHQL_PARTIAL';
            failed.set(spec.key, code);
            results.set(spec.key, {
              status: 'error',
              errorCode: code,
              key: spec.key,
              requestedKey: spec.key,
              fullName: spec.fullName,
            });
          }
          continue;
        }
        const normalized = normalizeBaseRepoNode(node, spec);
        results.set(spec.key, normalized);
        if (normalized.key !== spec.key) {
          results.set(normalized.key, normalized);
        }
      }
    },
    onChunkFailed: (chunk, code) => {
      for (const spec of chunk) {
        failed.set(spec.key, code);
        results.set(spec.key, {
          status: 'error',
          errorCode: code,
          key: spec.key,
          requestedKey: spec.key,
          fullName: spec.fullName,
        });
      }
    },
  });

  return {
    ok: !stats.authFailed && stats.errors.every((e) => e.code !== 'ERR_GRAPHQL_NO_TOKEN'),
    results,
    notFound,
    failed,
    ...stats,
  };
}

function buildNovelStage2AQuery(chunk) {
  const varDecls = [];
  const variables = {};
  const fields = [];
  for (let i = 0; i < chunk.length; i++) {
    const spec = chunk[i];
    varDecls.push(`$o${i}: String!`, `$n${i}: String!`);
    variables[`o${i}`] = spec.owner;
    variables[`n${i}`] = spec.repo;
    fields.push(`
      r${i}: repository(owner: $o${i}, name: $n${i}) {
        id
        databaseId
        name
        nameWithOwner
        url
        description
        isArchived
        isDisabled
        isTemplate
        isFork
        pushedAt
        stargazerCount
        owner {
          login
          ... on User { databaseId }
          ... on Organization { databaseId }
        }
        parent {
          nameWithOwner
          pushedAt
          isArchived
          defaultBranchRef {
            name
            target { oid }
          }
        }
        defaultBranchRef {
          name
          target {
            oid
            ... on Commit { committedDate }
          }
        }
        rootManifest: object(expression: "HEAD:plugin.json") {
          ... on Blob { byteSize }
        }
        dotManifest: object(expression: "HEAD:.antigravity-plugin/plugin.json") {
          ... on Blob { byteSize }
        }
        companion: object(expression: "HEAD:agy-market.json") {
          ... on Blob { byteSize }
        }
        rootTree: object(expression: "HEAD:") {
          ... on Tree {
            entries {
              name
              type
              object {
                ... on Tree {
                  entries {
                    name
                    type
                  }
                }
              }
            }
          }
        }
      }`);
  }
  const query = `query Stage2ANovel(${varDecls.join(', ')}) {\n${fields.join('\n')}\n  rateLimit { cost remaining resetAt }\n}`;
  return { query, variables };
}

function normalizeDepth2TreeEntries(rootTree) {
  const rawEntries = Array.isArray(rootTree?.entries) ? rootTree.entries : [];
  return rawEntries
    .filter((e) => e && typeof e.name === 'string')
    .map((e) => {
      const childRaw = Array.isArray(e.object?.entries) ? e.object.entries : [];
      return {
        name: e.name,
        type: String(e.type || ''),
        entries: childRaw
          .filter((c) => c && typeof c.name === 'string')
          .map((c) => ({ name: c.name, type: String(c.type || '') })),
      };
    });
}

/**
 * Stage 2A-Novel: batch structural triage for unseen repositories (`B=20`, depth-2 `Tree`, 0 connection cost = ~1 pt / 20 repos).
 */
export async function batchNovelStage2A(
  repos,
  {
    batchSize = 20,
    minBatchSize = 5,
    token = process.env.GITHUB_TOKEN || '',
    endpoint = GITHUB_GRAPHQL_ENDPOINT,
    fetchImpl = fetch,
    timeoutMs = 20_000,
    userAgent = DEFAULT_GRAPHQL_USER_AGENT,
  } = {},
) {
  const specs = dedupeRepoSpecs(repos);
  const results = new Map();
  const notFound = new Set();
  const failed = new Map();

  const stats = await executeAdaptiveGraphqlBatches(specs, {
    batchSize,
    minBatchSize,
    token,
    endpoint,
    fetchImpl,
    timeoutMs,
    userAgent,
    buildPayload: buildNovelStage2AQuery,
    onChunkData: (chunk, data, errorsByAlias) => {
      for (let i = 0; i < chunk.length; i++) {
        const spec = chunk[i];
        const alias = `r${i}`;
        const node = data[alias];
        const aliasErr = errorsByAlias.get(alias);
        if (!node) {
          if (aliasErr?.type === 'NOT_FOUND') {
            notFound.add(spec.key);
            results.set(spec.key, {
              status: 'not_found',
              errorCode: 'ERR_REPO_NOT_FOUND',
              key: spec.key,
              requestedKey: spec.key,
              fullName: spec.fullName,
            });
          } else {
            const code = aliasErr?.type === 'RATE_LIMITED' ? 'ERR_GRAPHQL_RATE_LIMITED' : 'ERR_GRAPHQL_PARTIAL';
            failed.set(spec.key, code);
            results.set(spec.key, {
              status: 'error',
              errorCode: code,
              key: spec.key,
              requestedKey: spec.key,
              fullName: spec.fullName,
            });
          }
          continue;
        }
        const base = normalizeBaseRepoNode(node, spec);
        const enriched = {
          ...base,
          hasRootManifest: Boolean(node.rootManifest && Number(node.rootManifest.byteSize || 0) > 0),
          hasDotManifest: Boolean(node.dotManifest && Number(node.dotManifest.byteSize || 0) > 0),
          hasCompanion: Boolean(node.companion && Number(node.companion.byteSize || 0) > 0),
          rootTreeEntries: normalizeDepth2TreeEntries(node.rootTree),
        };
        results.set(spec.key, enriched);
        if (enriched.key !== spec.key) {
          results.set(enriched.key, enriched);
        }
      }
    },
    onChunkFailed: (chunk, code) => {
      for (const spec of chunk) {
        failed.set(spec.key, code);
        results.set(spec.key, {
          status: 'error',
          errorCode: code,
          key: spec.key,
          requestedKey: spec.key,
          fullName: spec.fullName,
        });
      }
    },
  });

  return {
    ok: !stats.authFailed && stats.errors.every((e) => e.code !== 'ERR_GRAPHQL_NO_TOKEN'),
    results,
    notFound,
    failed,
    ...stats,
  };
}

/**
 * Pure Stage 2A-Novel triage gate with verified 99.1% recall on non-root Antigravity plugin repos.
 * Passes when ANY of:
 *   (a) Root `plugin.json`, `.antigravity-plugin/plugin.json`, or `agy-market.json` exists
 *   (b) Depth-2 tree detects `<d1>/plugin.json` or `<d1>/.antigravity-plugin` (100% of depth-1 subdirs)
 *   (c) Any non-excluded `<d1>` or `<d1>/<d2>` matches `NOVEL_STAGE2A_SUBDIR_WHITELIST` or `repoName`
 *   (d) Bypass: `explicitSubpaths.length > 0`, AGY repo name (`/(?:antigravity|^agy-)/i`), or `topic:antigravity-plugin(s)`
 */
export function passesNovelStage2ATriage(
  node,
  { explicitSubpaths = [], repoName = '', topics = [] } = {},
) {
  if (!node || node.status === 'not_found') {
    return { pass: false, reason: 'ERR_REPO_NOT_FOUND', matchedPaths: [] };
  }
  if (node.status === 'error') {
    return { pass: false, reason: node.errorCode || 'ERR_GRAPHQL_PARTIAL', matchedPaths: [] };
  }
  if (node.status === 'empty' || !node.headSha) {
    return { pass: false, reason: 'ERR_EMPTY_REPO', matchedPaths: [] };
  }
  if (node.isArchived || node.isDisabled || node.isTemplate) {
    return { pass: false, reason: 'ERR_REPO_INELIGIBLE', matchedPaths: [] };
  }
  const ownerLower = String(node.ownerLogin || '').toLowerCase();
  const parentOwnerLower = String(node.parent?.fullName || '').split('/')[0]?.toLowerCase() || '';
  if (EXTENDED_FIRST_PARTY_OWNERS.has(ownerLower) || EXTENDED_FIRST_PARTY_OWNERS.has(parentOwnerLower)) {
    return { pass: false, reason: 'ERR_REPO_INELIGIBLE', matchedPaths: [] };
  }

  // (a) Root manifest or companion
  if (node.hasRootManifest || node.hasDotManifest || node.hasCompanion) {
    return { pass: true, reason: 'root_manifest', matchedPaths: ['.'] };
  }

  const effectiveRepoName = String(repoName || node.name || '').trim();
  const repoLower = effectiveRepoName.toLowerCase();
  const treeEntries = Array.isArray(node.rootTreeEntries) ? node.rootTreeEntries : [];

  const depth2Manifests = [];
  const whitelistedDirs = [];

  for (const d1 of treeEntries) {
    if (!d1 || d1.type !== 'tree' || !d1.name) continue;
    const d1Lower = d1.name.toLowerCase();
    if (NOVEL_STAGE2A_EXCLUDED_DIRS.has(d1Lower)) continue;

    // Check depth-2 children for direct plugin.json / .antigravity-plugin or whitelisted depth-2 dir
    const children = Array.isArray(d1.entries) ? d1.entries : [];
    for (const d2 of children) {
      if (!d2 || !d2.name) continue;
      const d2Lower = d2.name.toLowerCase();
      if (
        (d2Lower === 'plugin.json' && d2.type === 'blob') ||
        (d2Lower === '.antigravity-plugin' && d2.type === 'tree') ||
        (d2Lower === 'agy-market.json' && d2.type === 'blob')
      ) {
        depth2Manifests.push(normalizeRelPosix(d1.name));
      } else if (d2.type === 'tree' && !NOVEL_STAGE2A_EXCLUDED_DIRS.has(d2Lower)) {
        if (NOVEL_STAGE2A_SUBDIR_WHITELIST.has(d2Lower) || (repoLower && d2Lower === repoLower)) {
          whitelistedDirs.push(normalizeRelPosix(`${d1.name}/${d2.name}`));
        }
      }
    }

    if (NOVEL_STAGE2A_SUBDIR_WHITELIST.has(d1Lower) || (repoLower && d1Lower === repoLower)) {
      whitelistedDirs.push(normalizeRelPosix(d1.name));
    }
  }

  // (b) Depth-2 exact manifest hit
  if (depth2Manifests.length > 0) {
    return { pass: true, reason: 'depth2_manifest', matchedPaths: [...new Set(depth2Manifests)].sort() };
  }

  // (c) Expanded subdir whitelist match at depth 1 or 2
  if (whitelistedDirs.length > 0) {
    return { pass: true, reason: 'whitelisted_subdir', matchedPaths: [...new Set(whitelistedDirs)].sort() };
  }

  // (d) Explicit subpaths / AGY repo name / AGY plugin topic bypass
  const cleanExplicit = (Array.isArray(explicitSubpaths) ? explicitSubpaths : [])
    .map((p) => normalizeRelPosix(p))
    .filter(Boolean);
  if (cleanExplicit.length > 0) {
    return { pass: true, reason: 'explicit_subpaths', matchedPaths: [...new Set(cleanExplicit)].sort() };
  }

  if (effectiveRepoName && AGY_NAME_RE.test(effectiveRepoName)) {
    return { pass: true, reason: 'agy_repo_name', matchedPaths: [] };
  }

  const topicList = Array.isArray(topics) ? topics : [];
  if (topicList.some((t) => AGY_PLUGIN_TOPIC_RE.test(String(t || '').trim()))) {
    return { pass: true, reason: 'agy_plugin_topic', matchedPaths: [] };
  }

  return { pass: false, reason: 'ERR_MISSING_PLUGIN_JSON', matchedPaths: [] };
}

function buildInspectStage2BQuery(chunk) {
  const varDecls = [];
  const variables = {};
  const fields = [];
  for (let i = 0; i < chunk.length; i++) {
    const spec = chunk[i];
    varDecls.push(`$o${i}: String!`, `$n${i}: String!`);
    variables[`o${i}`] = spec.owner;
    variables[`n${i}`] = spec.repo;
    fields.push(`
      r${i}: repository(owner: $o${i}, name: $n${i}) {
        id
        databaseId
        name
        nameWithOwner
        url
        description
        isArchived
        isDisabled
        isTemplate
        isFork
        pushedAt
        stargazerCount
        licenseInfo { spdxId }
        owner {
          login
          ... on User { databaseId }
          ... on Organization { databaseId }
        }
        parent {
          nameWithOwner
          pushedAt
          isArchived
          defaultBranchRef {
            name
            target { oid }
          }
        }
        repositoryTopics(first: 10) {
          nodes { topic { name } }
        }
        releases(first: 5, orderBy: { field: CREATED_AT, direction: DESC }) {
          nodes {
            tagName
            isDraft
            isPrerelease
            publishedAt
            tagCommit {
              oid
              committedDate
            }
            releaseAssets(first: 10) {
              nodes {
                name
                downloadUrl
                size
              }
            }
          }
        }
        refs(refPrefix: "refs/tags/", first: 10, orderBy: { field: TAG_COMMIT_DATE, direction: DESC }) {
          nodes {
            name
            target {
              oid
              ... on Commit { committedDate }
              ... on Tag {
                target {
                  oid
                  ... on Commit { committedDate }
                }
              }
            }
          }
        }
        defaultBranchRef {
          name
          target {
            oid
            ... on Commit { committedDate }
          }
        }
        rootManifest: object(expression: "HEAD:plugin.json") {
          ... on Blob { byteSize text isBinary }
        }
        dotManifest: object(expression: "HEAD:.antigravity-plugin/plugin.json") {
          ... on Blob { byteSize text isBinary }
        }
        companion: object(expression: "HEAD:agy-market.json") {
          ... on Blob { byteSize text isBinary }
        }
      }`);
  }
  const query = `query Stage2BInspect(${varDecls.join(', ')}) {\n${fields.join('\n')}\n  rateLimit { cost remaining resetAt }\n}`;
  return { query, variables };
}

function extractBlobText(blobObj, maxBytes = 256 * 1024) {
  if (!blobObj || typeof blobObj !== 'object') return null;
  if (blobObj.isBinary) return null;
  if (Number(blobObj.byteSize || 0) > maxBytes) return null;
  return typeof blobObj.text === 'string' ? blobObj.text : null;
}

/**
 * Stage 2B-Inspect: full snapshot metadata, releases(first:5) w/ assets & tagCommit,
 * tags(first:10, TAG_COMMIT_DATE) w/ peeled committedDate, topics, and pre-tarball manifest blobs (`B=20`).
 */
export async function batchInspectStage2B(
  repos,
  {
    batchSize = 20,
    minBatchSize = 5,
    token = process.env.GITHUB_TOKEN || '',
    endpoint = GITHUB_GRAPHQL_ENDPOINT,
    fetchImpl = fetch,
    timeoutMs = 25_000,
    userAgent = DEFAULT_GRAPHQL_USER_AGENT,
  } = {},
) {
  const specs = dedupeRepoSpecs(repos);
  const results = new Map();
  const notFound = new Set();
  const failed = new Map();

  const stats = await executeAdaptiveGraphqlBatches(specs, {
    batchSize,
    minBatchSize,
    token,
    endpoint,
    fetchImpl,
    timeoutMs,
    userAgent,
    buildPayload: buildInspectStage2BQuery,
    onChunkData: (chunk, data, errorsByAlias) => {
      for (let i = 0; i < chunk.length; i++) {
        const spec = chunk[i];
        const alias = `r${i}`;
        const node = data[alias];
        const aliasErr = errorsByAlias.get(alias);
        if (!node) {
          if (aliasErr?.type === 'NOT_FOUND') {
            notFound.add(spec.key);
            results.set(spec.key, {
              status: 'not_found',
              errorCode: 'ERR_REPO_NOT_FOUND',
              key: spec.key,
              requestedKey: spec.key,
              fullName: spec.fullName,
            });
          } else {
            const code = aliasErr?.type === 'RATE_LIMITED' ? 'ERR_GRAPHQL_RATE_LIMITED' : 'ERR_GRAPHQL_PARTIAL';
            failed.set(spec.key, code);
            results.set(spec.key, {
              status: 'error',
              errorCode: code,
              key: spec.key,
              requestedKey: spec.key,
              fullName: spec.fullName,
            });
          }
          continue;
        }

        const base = normalizeBaseRepoNode(node, spec);
        const topics = (Array.isArray(node.repositoryTopics?.nodes) ? node.repositoryTopics.nodes : [])
          .map((n) => n?.topic?.name)
          .filter((t) => typeof t === 'string' && t.trim())
          .map((t) => t.trim().toLowerCase());

        const tags = (Array.isArray(node.refs?.nodes) ? node.refs.nodes : [])
          .map(normalizeTagNode)
          .filter(Boolean);
        const tagsByName = new Map(tags.map((t) => [t.name, t]));

        const releases = (Array.isArray(node.releases?.nodes) ? node.releases.nodes : [])
          .map((r) => normalizeReleaseNode(r, tagsByName))
          .filter(Boolean);

        const enriched = {
          ...base,
          topics,
          releases,
          tags,
          rootManifestText: extractBlobText(node.rootManifest),
          dotManifestText: extractBlobText(node.dotManifest),
          companionText: extractBlobText(node.companion),
        };

        results.set(spec.key, enriched);
        if (enriched.key !== spec.key) {
          results.set(enriched.key, enriched);
        }
      }
    },
    onChunkFailed: (chunk, code) => {
      for (const spec of chunk) {
        failed.set(spec.key, code);
        results.set(spec.key, {
          status: 'error',
          errorCode: code,
          key: spec.key,
          requestedKey: spec.key,
          fullName: spec.fullName,
        });
      }
    },
  });

  return {
    ok: !stats.authFailed && stats.errors.every((e) => e.code !== 'ERR_GRAPHQL_NO_TOKEN'),
    results,
    notFound,
    failed,
    ...stats,
  };
}

/**
 * Resolves the canonical 3-tier snapshot (Release -> Stable SemVer Tag -> Default-branch Commit SHA)
 * directly from a Stage 2B GraphQL node, matching `crawl-topics.mjs` snapshot semantics with 0 REST calls.
 */
export function resolveSnapshotFromStage2BNode(node, { isMonorepo = false, nowIso = new Date().toISOString() } = {}) {
  if (!node || node.status !== 'ok') return null;
  const fullName = node.fullName;

  // Tier 1: Newest non-draft, non-prerelease GitHub Release
  const stableRelease = (Array.isArray(node.releases) ? node.releases : []).find((rel) => {
    if (!rel || rel.isDraft || rel.isPrerelease || !rel.commitSha) return false;
    if (isMonorepo) {
      const sem = parseSemver(rel.tagName);
      return Boolean(sem && sem.prerelease.length === 0);
    }
    return true;
  });

  if (stableRelease) {
    const asset = isMonorepo ? null : selectReleaseTarballAsset(stableRelease.assets);
    const tarballUrl = asset
      ? asset.browser_download_url
      : buildSourceArchiveUrl(fullName, stableRelease.commitSha, stableRelease.tagName);
    return {
      fullName,
      defaultBranch: node.defaultBranch,
      tier: 'release',
      tagName: stableRelease.tagName,
      commitSha: stableRelease.commitSha,
      tarballUrl,
      publishedAt: stableRelease.publishedAt || node.headCommittedAt || nowIso,
      requireSelfContained: !asset,
    };
  }

  // Tier 2: Highest stable SemVer Git Tag (preserving peeled Tag -> Commit `committedDate`)
  const tags = Array.isArray(node.tags) ? node.tags : [];
  const bestTagName = pickHighestStableSemverTag(tags.map((t) => t.name));
  if (bestTagName) {
    const tagObj = tags.find((t) => t.name === bestTagName);
    if (tagObj?.commitSha) {
      return {
        fullName,
        defaultBranch: node.defaultBranch,
        tier: 'tag',
        tagName: bestTagName,
        commitSha: tagObj.commitSha,
        tarballUrl: buildSourceArchiveUrl(fullName, tagObj.commitSha, bestTagName),
        publishedAt: tagObj.committedDate || node.headCommittedAt || nowIso,
        requireSelfContained: true,
      };
    }
  }

  // Tier 3: Default branch 40-hex Commit SHA
  if (!node.headSha) return null;
  return {
    fullName,
    defaultBranch: node.defaultBranch,
    tier: 'commit',
    tagName: null,
    commitSha: node.headSha,
    tarballUrl: `https://github.com/${fullName}/archive/${node.headSha}.tar.gz`,
    publishedAt: node.headCommittedAt || node.pushedAt || nowIso,
    requireSelfContained: true,
  };
}

/**
 * Converts a GraphQL Stage 2A/2B/Track-1 node into the REST-shaped `repoMeta` object
 * expected by `buildTrack2PluginRecord`, `evaluateRepoSyncUpdate`, and `crawl-topics.mjs`.
 */
export function toRestCompatRepoMeta(node) {
  if (!node || node.status === 'not_found' || node.status === 'error') return null;
  const parentParts = node.parent?.fullName ? node.parent.fullName.split('/') : null;
  return {
    id: Number(node.repositoryId || 0),
    node_id: node.nodeId || undefined,
    name: node.name || '',
    full_name: node.fullName || '',
    html_url: node.url || `https://github.com/${node.fullName}`,
    description: node.description || '',
    archived: Boolean(node.isArchived),
    disabled: Boolean(node.isDisabled),
    is_template: Boolean(node.isTemplate),
    fork: Boolean(node.isFork),
    pushed_at: node.pushedAt || null,
    stargazers_count: Number(node.stars || 0),
    default_branch: node.defaultBranch || 'main',
    license: node.licenseSpdxId ? { spdx_id: node.licenseSpdxId } : null,
    owner: {
      id: Number(node.ownerId || 0),
      login: node.ownerLogin || 'community',
    },
    topics: Array.isArray(node.topics) ? node.topics : [],
    ...(parentParts && parentParts.length === 2
      ? {
          parent: {
            full_name: node.parent.fullName,
            pushed_at: node.parent.pushedAt || null,
            archived: Boolean(node.parent.isArchived),
            owner: { login: parentParts[0] },
          },
        }
      : {}),
  };
}

function buildAuthorExpansionQuery(chunk, reposPerOwner) {
  const varDecls = ['$perOwner: Int!'];
  const variables = { perOwner: reposPerOwner };
  const fields = [];
  for (let i = 0; i < chunk.length; i++) {
    const login = chunk[i];
    varDecls.push(`$u${i}: String!`);
    variables[`u${i}`] = login;
    fields.push(`
      u${i}: repositoryOwner(login: $u${i}) {
        login
        ... on User { databaseId }
        ... on Organization { databaseId }
        repositories(first: $perOwner, ownerAffiliations: [OWNER], isFork: false, privacy: PUBLIC, orderBy: { field: PUSHED_AT, direction: DESC }) {
          nodes {
            id
            databaseId
            name
            nameWithOwner
            url
            description
            isArchived
            isDisabled
            isTemplate
            pushedAt
            stargazerCount
            defaultBranchRef {
              name
              target { oid }
            }
            rootManifest: object(expression: "HEAD:plugin.json") {
              ... on Blob { byteSize }
            }
            dotManifest: object(expression: "HEAD:.antigravity-plugin/plugin.json") {
              ... on Blob { byteSize }
            }
            companion: object(expression: "HEAD:agy-market.json") {
              ... on Blob { byteSize }
            }
          }
        }
      }`);
  }
  const query = `query AuthorSnowballExpansion(${varDecls.join(', ')}) {\n${fields.join('\n')}\n  rateLimit { cost remaining resetAt }\n}`;
  return { query, variables };
}

/**
 * Selects which known plugin authors to expand in the current run slot:
 *   - Prolific authors (`repoCount >= prolificMinRepos`) expand every run (6h)
 *   - Single-plugin authors rotate deterministically across `warmModulus` runs (default 8 -> every 48h)
 */
export function selectAuthorsForExpansion(
  ownerRepoCounts,
  { runSlot = 0, warmModulus = 8, prolificMinRepos = 2 } = {},
) {
  const entries = ownerRepoCounts instanceof Map ? [...ownerRepoCounts.entries()] : Object.entries(ownerRepoCounts || {});
  const selected = [];
  const slot = Math.abs(Math.floor(runSlot)) % Math.max(1, warmModulus);

  for (const [rawLogin, rawCount] of entries) {
    const login = String(rawLogin || '').trim();
    const lower = login.toLowerCase();
    if (!login || !GITHUB_OWNER_RE.test(login) || EXTENDED_FIRST_PARTY_OWNERS.has(lower)) continue;
    const count = Number(rawCount || 0);
    if (count >= prolificMinRepos || deterministicHash32(lower) % Math.max(1, warmModulus) === slot) {
      selected.push({ login, repoCount: count, prolific: count >= prolificMinRepos });
    }
  }

  selected.sort((a, b) => Number(b.prolific) - Number(a.prolific) || b.repoCount - a.repoCount || a.login.localeCompare(b.login));
  return selected.map((s) => s.login);
}

/**
 * Author-Centric Snowball Expansion (`B=20` owners/query, `first:20` public non-fork owned repos, ~1 pt / 20 owners).
 */
export async function batchAuthorExpansion(
  owners,
  {
    batchSize = 20,
    minBatchSize = 5,
    reposPerOwner = 20,
    knownRepoKeys = null,
    token = process.env.GITHUB_TOKEN || '',
    endpoint = GITHUB_GRAPHQL_ENDPOINT,
    fetchImpl = fetch,
    timeoutMs = 20_000,
    userAgent = DEFAULT_GRAPHQL_USER_AGENT,
  } = {},
) {
  const cleanOwners = [];
  const seenOwners = new Set();
  for (const raw of Array.isArray(owners) ? owners : []) {
    const login = String(raw || '').trim();
    const lower = login.toLowerCase();
    if (!login || seenOwners.has(lower) || !GITHUB_OWNER_RE.test(login) || EXTENDED_FIRST_PARTY_OWNERS.has(lower)) {
      continue;
    }
    seenOwners.add(lower);
    cleanOwners.push(login);
  }

  const candidates = new Map();
  const notFoundOwners = new Set();
  const ownersChecked = [];

  const stats = await executeAdaptiveGraphqlBatches(cleanOwners, {
    batchSize,
    minBatchSize,
    token,
    endpoint,
    fetchImpl,
    timeoutMs,
    userAgent,
    buildPayload: (chunk) => buildAuthorExpansionQuery(chunk, Math.min(50, Math.max(1, reposPerOwner))),
    onChunkData: (chunk, data, errorsByAlias) => {
      for (let i = 0; i < chunk.length; i++) {
        const login = chunk[i];
        const alias = `u${i}`;
        const ownerNode = data[alias];
        const aliasErr = errorsByAlias.get(alias);
        if (!ownerNode) {
          if (aliasErr?.type === 'NOT_FOUND') {
            notFoundOwners.add(login.toLowerCase());
          }
          continue;
        }
        ownersChecked.push(ownerNode.login || login);
        const ownerId = extractOwnerId(ownerNode);
        const repoNodes = Array.isArray(ownerNode.repositories?.nodes) ? ownerNode.repositories.nodes : [];
        for (const r of repoNodes) {
          if (!r || !r.nameWithOwner || r.isArchived || r.isDisabled || r.isTemplate) continue;
          const oid = r.defaultBranchRef?.target?.oid || null;
          if (!oid) continue;
          const key = String(r.nameWithOwner).toLowerCase();
          if (knownRepoKeys && knownRepoKeys.has(key)) continue;

          const hasDirectManifest = Boolean(
            (r.rootManifest && Number(r.rootManifest.byteSize || 0) > 0) ||
              (r.dotManifest && Number(r.dotManifest.byteSize || 0) > 0) ||
              (r.companion && Number(r.companion.byteSize || 0) > 0),
          );
          const agyNamed = AGY_NAME_RE.test(String(r.name || ''));
          if (!hasDirectManifest && !agyNamed) continue;

          if (!candidates.has(key)) {
            candidates.set(key, {
              key,
              fullName: String(r.nameWithOwner),
              ownerLogin: String(ownerNode.login || login),
              ownerId,
              repositoryId: Number(r.databaseId || 0),
              nodeId: typeof r.id === 'string' ? r.id : null,
              name: String(r.name || ''),
              url: String(r.url || `https://github.com/${r.nameWithOwner}`),
              description: typeof r.description === 'string' ? r.description : '',
              pushedAt: r.pushedAt || null,
              stars: Number(r.stargazerCount || 0),
              defaultBranch: r.defaultBranchRef?.name || 'main',
              headSha: String(oid).toLowerCase(),
              hasDirectManifest,
              agyNamed,
            });
          }
        }
      }
    },
    onChunkFailed: () => {},
  });

  return {
    ok: !stats.authFailed && stats.errors.every((e) => e.code !== 'ERR_GRAPHQL_NO_TOKEN'),
    candidates: [...candidates.values()].sort((a, b) => Number(b.hasDirectManifest) - Number(a.hasDirectManifest) || a.key.localeCompare(b.key)),
    ownersChecked,
    notFoundOwners,
    ...stats,
  };
}

const TRACK1_REPO_FRAGMENT = `
  fragment Track1RepoFields on Repository {
    id
    databaseId
    name
    nameWithOwner
    url
    description
    isArchived
    isDisabled
    isTemplate
    pushedAt
    stargazerCount
    owner {
      login
      ... on User { databaseId }
      ... on Organization { databaseId }
    }
    defaultBranchRef {
      name
      target {
        oid
        ... on Commit { committedDate }
      }
    }
    releases(first: 10, orderBy: { field: CREATED_AT, direction: DESC }) {
      nodes {
        tagName
        isDraft
        isPrerelease
        publishedAt
        tagCommit {
          oid
          committedDate
        }
        releaseAssets(first: 10) {
          nodes {
            name
            downloadUrl
            size
          }
        }
      }
    }
    refs(refPrefix: "refs/tags/", first: 10, orderBy: { field: TAG_COMMIT_DATE, direction: DESC }) {
      nodes {
        name
        target {
          oid
          ... on Commit { committedDate }
          ... on Tag {
            target {
              oid
              ... on Commit { committedDate }
            }
          }
        }
      }
    }
  }
`;

function buildTrack1DualLookupQuery(chunk) {
  const varDecls = [];
  const variables = {};
  const fields = [];
  const nodeIds = [];

  for (let i = 0; i < chunk.length; i++) {
    const item = chunk[i];
    if (typeof item.nodeId === 'string' && item.nodeId.trim()) {
      nodeIds.push(item.nodeId.trim());
    }
    if (item.spec) {
      varDecls.push(`$o${i}: String!`, `$n${i}: String!`);
      variables[`o${i}`] = item.spec.owner;
      variables[`n${i}`] = item.spec.repo;
      fields.push(`slug_${i}: repository(owner: $o${i}, name: $n${i}) { ...Track1RepoFields }`);
    }
  }

  if (nodeIds.length > 0) {
    varDecls.push('$nodeIds: [ID!]!');
    variables.nodeIds = [...new Set(nodeIds)];
    fields.unshift('byIdNodes: nodes(ids: $nodeIds) { ... on Repository { ...Track1RepoFields } }');
  }

  const declBlock = varDecls.length > 0 ? `(${varDecls.join(', ')})` : '';
  const query = `${TRACK1_REPO_FRAGMENT}\nquery Track1DualLookup${declBlock} {\n  ${fields.join('\n  ')}\n  rateLimit { cost remaining resetAt }\n}`;
  return { query, variables };
}

function parseTrack1Node(rawNode, fallbackSpec) {
  if (!rawNode || typeof rawNode !== 'object' || !rawNode.databaseId) return null;
  const spec = fallbackSpec || parseOwnerRepoSpec(rawNode.nameWithOwner || '');
  if (!spec) return null;
  const base = normalizeBaseRepoNode(rawNode, spec);
  const tags = (Array.isArray(rawNode.refs?.nodes) ? rawNode.refs.nodes : [])
    .map(normalizeTagNode)
    .filter(Boolean);
  const tagsByName = new Map(tags.map((t) => [t.name, t]));
  const releases = (Array.isArray(rawNode.releases?.nodes) ? rawNode.releases.nodes : [])
    .map((r) => normalizeReleaseNode(r, tagsByName))
    .filter(Boolean);
  return { ...base, releases, tags };
}

/**
 * Track-1 Dual Lookup for `sync-releases.mjs`:
 * Combines `nodes(ids: [...])` (by stored GraphQL `nodeId`) + aliased `repository(owner, name)` (by slug)
 * + `releases(first: 10)` + `refs(first: 10)` in 1–2 GraphQL points per batch so RepoJacking (Case A),
 * Rename (Case B), Ownership Transfer (Case C), and `TAG_MUTATION_BLOCKED` work without N*5 REST calls.
 */
export async function batchTrack1DualLookup(
  entries,
  {
    batchSize = 25,
    minBatchSize = 5,
    token = process.env.GITHUB_TOKEN || '',
    endpoint = GITHUB_GRAPHQL_ENDPOINT,
    fetchImpl = fetch,
    timeoutMs = 25_000,
    userAgent = DEFAULT_GRAPHQL_USER_AGENT,
  } = {},
) {
  const prepared = [];
  for (const rec of Array.isArray(entries) ? entries : []) {
    if (!rec || typeof rec !== 'object') continue;
    const spec = parseOwnerRepoSpec(rec.repoFullName || '');
    const nodeId = typeof rec.nodeId === 'string' && rec.nodeId.trim() ? rec.nodeId.trim() : null;
    if (!spec && !nodeId) continue;
    prepared.push({
      entrySlug: String(rec.entrySlug || rec.canonicalName || spec?.key || ''),
      canonicalName: String(rec.canonicalName || ''),
      repositoryId: Number(rec.repositoryId || 0),
      ownerId: Number(rec.ownerId || 0),
      repoFullName: String(rec.repoFullName || spec?.fullName || ''),
      nodeId,
      spec,
    });
  }

  const results = new Map();
  const failed = new Map();

  const stats = await executeAdaptiveGraphqlBatches(prepared, {
    batchSize,
    minBatchSize,
    token,
    endpoint,
    fetchImpl,
    timeoutMs,
    userAgent,
    buildPayload: buildTrack1DualLookupQuery,
    onChunkData: (chunk, data, errorsByAlias) => {
      const nodesByNodeId = new Map();
      const nodesByDatabaseId = new Map();
      for (const raw of Array.isArray(data.byIdNodes) ? data.byIdNodes : []) {
        if (!raw || !raw.databaseId) continue;
        const parsed = parseTrack1Node(raw, null);
        if (!parsed) continue;
        if (parsed.nodeId) nodesByNodeId.set(parsed.nodeId, parsed);
        if (parsed.repositoryId > 0) nodesByDatabaseId.set(parsed.repositoryId, parsed);
      }

      for (let i = 0; i < chunk.length; i++) {
        const item = chunk[i];
        const slugAlias = `slug_${i}`;
        const rawSlug = data[slugAlias] || null;
        const slugErr = errorsByAlias.get(slugAlias);
        const slugParsed = rawSlug ? parseTrack1Node(rawSlug, item.spec) : null;

        let byIdParsed =
          (item.nodeId && nodesByNodeId.get(item.nodeId)) ||
          (item.repositoryId > 0 && nodesByDatabaseId.get(item.repositoryId)) ||
          null;

        // First-run nodeId backfill: if ledger had no nodeId yet and slug lookup returned the EXACT expected repositoryId
        if (!byIdParsed && slugParsed && item.repositoryId > 0 && slugParsed.repositoryId === item.repositoryId) {
          byIdParsed = slugParsed;
        }

        const slugNotFound = !slugParsed && slugErr?.type === 'NOT_FOUND';
        const slugTransientErr = !slugParsed && Boolean(slugErr) && slugErr.type !== 'NOT_FOUND';
        const needsRestFallbackById = !byIdParsed && !item.nodeId && item.repositoryId > 0 && !slugTransientErr;

        const authoritative = byIdParsed || null;
        const resolvedNodeId = authoritative?.nodeId || item.nodeId || null;

        results.set(item.entrySlug, {
          status: slugTransientErr && !byIdParsed ? 'error' : 'ok',
          errorCode: slugTransientErr && !byIdParsed ? 'ERR_GRAPHQL_PARTIAL' : null,
          entrySlug: item.entrySlug,
          canonicalName: item.canonicalName,
          nodeId: resolvedNodeId,
          repoByNumericId: authoritative ? toRestCompatRepoMeta(authoritative) : null,
          repoAtOldSlug: slugParsed ? toRestCompatRepoMeta(slugParsed) : null,
          slugNotFound,
          needsRestFallbackById,
          releases: authoritative?.releases || [],
          tags: authoritative?.tags || [],
          authoritativeNode: authoritative,
          slugNode: slugParsed,
        });
      }
    },
    onChunkFailed: (chunk, code) => {
      for (const item of chunk) {
        failed.set(item.entrySlug, code);
        results.set(item.entrySlug, {
          status: 'error',
          errorCode: code,
          entrySlug: item.entrySlug,
          canonicalName: item.canonicalName,
          nodeId: item.nodeId,
          repoByNumericId: null,
          repoAtOldSlug: null,
          slugNotFound: false,
          needsRestFallbackById: false,
          releases: [],
          tags: [],
          authoritativeNode: null,
          slugNode: null,
        });
      }
    },
  });

  return {
    ok: !stats.authFailed && stats.errors.every((e) => e.code !== 'ERR_GRAPHQL_NO_TOKEN'),
    results,
    failed,
    ...stats,
  };
}
