import assert from 'node:assert/strict';
import test from 'node:test';

import {
  AdaptiveRangeSlicer,
  buildCodeSearchQueryWithExclusions,
  classifyNegCacheReason,
  classifyPositiveRecrawlTier,
  CodeSearchPacer,
  computeActivityMultiplier,
  computeNextNegCacheProbe,
  createDefaultDiscoveryState,
  CURRENT_VALIDATOR_VERSION,
  discoverFromNpmSearch,
  DiscountedUcb1Cost,
  mineCooccurringTopics,
  mineReadmeFrontier,
  pruneNegativeCacheEntries,
  shouldSkipNegativeCache,
  updateNegativeCacheEntry,
  validateCodeSearchQuery,
  VALIDATED_CODE_SEARCH_QUERIES,
} from '../scripts/lib/adaptive-discovery.mjs';
import {
  batchAuthorExpansion,
  batchHeartbeatStage2A,
  batchInspectStage2B,
  batchNovelStage2A,
  batchTrack1DualLookup,
  parseOwnerRepoSpec,
  passesNovelStage2ATriage,
  resolveSnapshotFromStage2BNode,
  selectAuthorsForExpansion,
  toRestCompatRepoMeta,
} from '../scripts/lib/graphql-batch.mjs';

const SHA_A = '1111111111111111111111111111111111111111';
const SHA_B = '2222222222222222222222222222222222222222';
const SHA_C = '3333333333333333333333333333333333333333';

function makeJsonResponse(status, body, headersObj = {}) {
  const headers = new Headers(headersObj);
  const raw = typeof body === 'string' ? body : JSON.stringify(body);
  return {
    ok: status >= 200 && status < 300,
    status,
    headers,
    async text() {
      return raw;
    },
    async json() {
      return JSON.parse(raw);
    },
  };
}

// ============================================================================
// GraphQL Batch Tests (`scripts/lib/graphql-batch.mjs`)
// ============================================================================

test('batchHeartbeatStage2A: omits rootTree, tolerates partial NOT_FOUND & empty repo, and halves batch on 502', async () => {
  const repos = Array.from({ length: 50 }, (_, i) => `owner${i}/repo-${i}`);
  const seenChunkSizes = [];
  const seenQueries = [];

  const fetchImpl = async (_url, init) => {
    const { query, variables } = JSON.parse(init.body);
    seenQueries.push(query);
    const count = Object.keys(variables).length / 2;
    seenChunkSizes.push(count);

    // Force HTTP 502 gateway timeout whenever batch > 15 to verify adaptive halving (50 -> 25 -> 12/13)
    if (count > 15) {
      return makeJsonResponse(502, 'Bad Gateway');
    }

    const data = { rateLimit: { cost: 1, remaining: 4990, resetAt: '2026-11-25T20:00:00Z' } };
    const errors = [];
    for (let i = 0; i < count; i++) {
      const o = variables[`o${i}`];
      const n = variables[`n${i}`];
      if (o === 'owner1') {
        data[`r${i}`] = null;
        errors.push({ type: 'NOT_FOUND', path: [`r${i}`], message: 'Could not resolve to a Repository' });
      } else if (o === 'owner2') {
        data[`r${i}`] = {
          id: 'R_empty',
          databaseId: 1002,
          name: n,
          nameWithOwner: `${o}/${n}`,
          url: `https://github.com/${o}/${n}`,
          isArchived: false,
          isDisabled: false,
          isTemplate: false,
          isFork: false,
          pushedAt: null,
          stargazerCount: 0,
          owner: { login: o, databaseId: 202 },
          parent: null,
          defaultBranchRef: null,
        };
      } else {
        data[`r${i}`] = {
          id: `R_${o}`,
          databaseId: 1000 + Number(o.slice(5)),
          name: n,
          nameWithOwner: `${o}/${n}`,
          url: `https://github.com/${o}/${n}`,
          isArchived: false,
          isDisabled: false,
          isTemplate: false,
          isFork: o === 'owner3',
          pushedAt: '2026-11-24T10:00:00Z',
          stargazerCount: 12,
          owner: { login: o, databaseId: 200 + Number(o.slice(5)) },
          parent:
            o === 'owner3'
              ? {
                  nameWithOwner: 'upstream/orig',
                  pushedAt: '2026-10-01T00:00:00Z',
                  isArchived: false,
                  defaultBranchRef: { name: 'main', target: { oid: SHA_B } },
                }
              : null,
          defaultBranchRef: { name: 'main', target: { oid: SHA_A, committedDate: '2026-11-24T09:55:00Z' } },
        };
      }
    }
    return makeJsonResponse(200, { data, ...(errors.length > 0 ? { errors } : {}) });
  };

  const out = await batchHeartbeatStage2A(repos, { token: 'test-token', fetchImpl });
  assert.equal(out.ok, true);
  assert.ok(out.batchHalvings >= 3, `expected >= 3 batch halvings (50->25+25->12+13+12+13), got ${out.batchHalvings}`);
  assert.equal(seenChunkSizes[0], 50);
  assert.ok(seenQueries.every((q) => !q.includes('rootTree')), 'Stage 2A-Heartbeat must NOT query rootTree');
  assert.ok(seenQueries.every((q) => q.includes('... on User { databaseId }') && q.includes('... on Organization { databaseId }')));

  assert.equal(out.results.get('owner0/repo-0').status, 'ok');
  assert.equal(out.results.get('owner0/repo-0').headSha, SHA_A);
  assert.equal(out.results.get('owner1/repo-1').status, 'not_found');
  assert.equal(out.results.get('owner1/repo-1').errorCode, 'ERR_REPO_NOT_FOUND');
  assert.equal(out.notFound.has('owner1/repo-1'), true);
  assert.equal(out.results.get('owner2/repo-2').status, 'empty');
  assert.equal(out.results.get('owner2/repo-2').errorCode, 'ERR_EMPTY_REPO');
  assert.equal(out.results.get('owner3/repo-3').parent.fullName, 'upstream/orig');
  assert.equal(out.results.get('owner49/repo-49').status, 'ok');
});

test('batchNovelStage2A & passesNovelStage2ATriage: depth-2 Tree + expanded whitelist + bypasses match #10 spec', async () => {
  const fetchImpl = async (_url, init) => {
    const { query, variables } = JSON.parse(init.body);
    assert.ok(query.includes('rootTree: object(expression: "HEAD:")'));
    assert.ok(query.includes('object {\n                ... on Tree {\n                  entries'));
    const count = Object.keys(variables).length / 2;
    const data = { rateLimit: { cost: 1, remaining: 4999, resetAt: '2026-11-25T20:00:00Z' } };
    for (let i = 0; i < count; i++) {
      const o = variables[`o${i}`];
      const n = variables[`n${i}`];
      const key = `${o}/${n}`.toLowerCase();
      let rootManifest = null;
      let rootTree = { entries: [] };
      if (key === 'oil-oil/agy-fast-io') {
        rootTree = { entries: [{ name: 'plugin', type: 'tree', object: { entries: [{ name: 'plugin.json', type: 'blob' }] } }] };
      } else if (key === 'automattic/wordpress-antigravity-plugin') {
        rootTree = { entries: [{ name: 'wordpress', type: 'tree', object: { entries: [{ name: 'plugin.json', type: 'blob' }] } }] };
      } else if (key === 'yashjitpal/bettergravity') {
        rootTree = { entries: [{ name: 'community', type: 'tree', object: { entries: [{ name: 'plugins', type: 'tree' }] } }] };
      } else if (key === 'alice/root-plugin') {
        rootManifest = { byteSize: 320 };
      } else if (key === 'eric-sabe/noise-claude') {
        rootTree = { entries: [{ name: '.claude-plugin', type: 'tree', object: { entries: [{ name: 'plugin.json', type: 'blob' }] } }] };
      } else if (key === 'bob/random-docs-repo') {
        rootTree = { entries: [{ name: 'src', type: 'tree', object: { entries: [{ name: 'index.ts', type: 'blob' }] } }] };
      }
      data[`r${i}`] = {
        id: `R_${i}`,
        databaseId: 500 + i,
        name: n,
        nameWithOwner: `${o}/${n}`,
        url: `https://github.com/${o}/${n}`,
        description: 'test',
        isArchived: false,
        isDisabled: false,
        isTemplate: false,
        isFork: false,
        pushedAt: '2026-11-25T00:00:00Z',
        stargazerCount: 10,
        owner: { login: o, databaseId: 900 + i },
        parent: null,
        defaultBranchRef: { name: 'main', target: { oid: SHA_A, committedDate: '2026-11-25T00:00:00Z' } },
        rootManifest,
        dotManifest: null,
        companion: null,
        rootTree,
      };
    }
    return makeJsonResponse(200, { data });
  };

  const out = await batchNovelStage2A(
    [
      'oil-oil/agy-fast-io',
      'automattic/wordpress-antigravity-plugin',
      'yashjitpal/bettergravity',
      'alice/root-plugin',
      'eric-sabe/noise-claude',
      'bob/random-docs-repo',
      'google-labs-code/stitch-skills',
    ],
    { token: 'tok', fetchImpl },
  );

  assert.equal(passesNovelStage2ATriage(out.results.get('alice/root-plugin')).reason, 'root_manifest');
  assert.equal(passesNovelStage2ATriage(out.results.get('oil-oil/agy-fast-io')).reason, 'depth2_manifest');
  assert.equal(passesNovelStage2ATriage(out.results.get('automattic/wordpress-antigravity-plugin')).reason, 'depth2_manifest');
  assert.equal(passesNovelStage2ATriage(out.results.get('yashjitpal/bettergravity')).reason, 'whitelisted_subdir');
  // Foreign `.claude-plugin` dir is excluded and must fail triage!
  assert.equal(passesNovelStage2ATriage(out.results.get('eric-sabe/noise-claude')).pass, false);
  // Random non-AGY repo fails without bypass, but passes if topic or explicitSubpaths supplied
  assert.equal(passesNovelStage2ATriage(out.results.get('bob/random-docs-repo')).pass, false);
  assert.equal(
    passesNovelStage2ATriage(out.results.get('bob/random-docs-repo'), { topics: ['antigravity-plugin'] }).reason,
    'agy_plugin_topic',
  );
  assert.equal(
    passesNovelStage2ATriage(out.results.get('bob/random-docs-repo'), { explicitSubpaths: ['custom/sub'] }).reason,
    'explicit_subpaths',
  );
  // Google 1st-party org excluded
  assert.equal(passesNovelStage2ATriage(out.results.get('google-labs-code/stitch-skills')).pass, false);
});

test('batchInspectStage2B & resolveSnapshotFromStage2BNode: skips prerelease/platform binary and preserves peeled tag committedDate', async () => {
  const fetchImpl = async (_url, init) => {
    const { query } = JSON.parse(init.body);
    assert.ok(query.includes('releases(first: 5, orderBy: { field: CREATED_AT, direction: DESC })'));
    assert.ok(query.includes('refs(refPrefix: "refs/tags/", first: 10, orderBy: { field: TAG_COMMIT_DATE, direction: DESC })'));
    assert.ok(query.includes('committedDate'));

    return makeJsonResponse(200, {
      data: {
        rateLimit: { cost: 2, remaining: 4998, resetAt: '2026-11-25T20:00:00Z' },
        r0: {
          id: 'R_rel',
          databaseId: 701,
          name: 'agy-demo',
          nameWithOwner: 'alice/agy-demo',
          url: 'https://github.com/alice/agy-demo',
          description: 'Demo plugin',
          isArchived: false,
          isDisabled: false,
          isTemplate: false,
          isFork: false,
          pushedAt: '2026-11-25T05:00:00Z',
          stargazerCount: 42,
          licenseInfo: { spdxId: 'MIT' },
          owner: { login: 'alice', databaseId: 11 },
          parent: null,
          repositoryTopics: { nodes: [{ topic: { name: 'antigravity-plugin' } }] },
          releases: {
            nodes: [
              {
                tagName: 'v2.0.0-beta.1',
                isDraft: false,
                isPrerelease: true,
                publishedAt: '2026-11-25T04:00:00Z',
                tagCommit: { oid: SHA_C, committedDate: '2026-11-25T03:59:00Z' },
                releaseAssets: { nodes: [] },
              },
              {
                tagName: 'v1.2.0',
                isDraft: false,
                isPrerelease: false,
                publishedAt: '2026-11-20T12:00:00Z',
                tagCommit: { oid: SHA_B, committedDate: '2026-11-20T11:55:00Z' },
                releaseAssets: {
                  nodes: [
                    { name: 'agy-demo-darwin-arm64.tar.gz', downloadUrl: 'https://github.com/alice/agy-demo/releases/download/v1.2.0/agy-demo-darwin-arm64.tar.gz', size: 1000 },
                    { name: 'agy-demo.tar.gz', downloadUrl: 'https://github.com/alice/agy-demo/releases/download/v1.2.0/agy-demo.tar.gz', size: 2000 },
                  ],
                },
              },
            ],
          },
          refs: { nodes: [] },
          defaultBranchRef: { name: 'main', target: { oid: SHA_A, committedDate: '2026-11-25T05:00:00Z' } },
          rootManifest: { byteSize: 90, text: '{"name":"agy-demo","version":"1.2.0"}', isBinary: false },
          dotManifest: null,
          companion: null,
        },
        r1: {
          id: 'R_tag',
          databaseId: 702,
          name: 'tag-only-plugin',
          nameWithOwner: 'bob/tag-only-plugin',
          url: 'https://github.com/bob/tag-only-plugin',
          description: 'Tag only',
          isArchived: false,
          isDisabled: false,
          isTemplate: false,
          isFork: false,
          pushedAt: '2026-11-10T00:00:00Z',
          stargazerCount: 5,
          licenseInfo: null,
          owner: { login: 'bob', databaseId: 22 },
          parent: null,
          repositoryTopics: { nodes: [] },
          releases: { nodes: [] },
          refs: {
            nodes: [
              {
                name: 'v1.4.0',
                target: {
                  oid: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                  target: { oid: SHA_C, committedDate: '2026-11-09T18:30:00Z' },
                },
              },
              {
                name: 'v1.3.0',
                target: { oid: SHA_B, committedDate: '2026-10-01T00:00:00Z' },
              },
            ],
          },
          defaultBranchRef: { name: 'main', target: { oid: SHA_A, committedDate: '2026-11-10T00:00:00Z' } },
          rootManifest: null,
          dotManifest: { byteSize: 80, text: '{"name":"tag-only"}', isBinary: false },
          companion: null,
        },
      },
    });
  };

  const out = await batchInspectStage2B(['alice/agy-demo', 'bob/tag-only-plugin'], { token: 'tok', fetchImpl });
  const n0 = out.results.get('alice/agy-demo');
  const snap0 = resolveSnapshotFromStage2BNode(n0);
  assert.equal(snap0.tier, 'release');
  assert.equal(snap0.tagName, 'v1.2.0');
  assert.equal(snap0.commitSha, SHA_B);
  assert.equal(snap0.tarballUrl, 'https://github.com/alice/agy-demo/releases/download/v1.2.0/agy-demo.tar.gz');
  assert.equal(snap0.requireSelfContained, false);

  const restMeta = toRestCompatRepoMeta(n0);
  assert.equal(restMeta.id, 701);
  assert.equal(restMeta.owner.id, 11);
  assert.deepEqual(restMeta.topics, ['antigravity-plugin']);

  const n1 = out.results.get('bob/tag-only-plugin');
  const snap1 = resolveSnapshotFromStage2BNode(n1);
  assert.equal(snap1.tier, 'tag');
  assert.equal(snap1.tagName, 'v1.4.0');
  assert.equal(snap1.commitSha, SHA_C);
  assert.equal(snap1.publishedAt, '2026-11-09T18:30:00Z');
  assert.equal(snap1.requireSelfContained, true);
});

test('batchAuthorExpansion & selectAuthorsForExpansion: shards 1-repo authors and discovers untagged manifests', async () => {
  const counts = {
    'prolific-dev': 5,
    'google-labs-code': 10,
    'single-a': 1,
    'single-b': 1,
    'single-c': 1,
  };
  const seenSingles = new Set();
  for (let slot = 0; slot < 8; slot++) {
    const selected = selectAuthorsForExpansion(counts, { runSlot: slot, warmModulus: 8 });
    assert.ok(selected.includes('prolific-dev'), 'prolific author must appear in every slot');
    assert.ok(!selected.includes('google-labs-code'), 'Google 1st-party org must be excluded');
    for (const login of selected) {
      if (login.startsWith('single-')) seenSingles.add(login);
    }
  }
  assert.deepEqual([...seenSingles].sort(), ['single-a', 'single-b', 'single-c']);

  const fetchImpl = async (_url, init) => {
    const { query } = JSON.parse(init.body);
    assert.ok(query.includes('ownerAffiliations: [OWNER]'));
    return makeJsonResponse(200, {
      data: {
        rateLimit: { cost: 1, remaining: 4995, resetAt: '2026-11-25T20:00:00Z' },
        u0: {
          login: 'prolific-dev',
          databaseId: 300,
          repositories: {
            nodes: [
              {
                id: 'R1',
                databaseId: 3001,
                name: 'untagged-cool-tool',
                nameWithOwner: 'prolific-dev/untagged-cool-tool',
                url: 'https://github.com/prolific-dev/untagged-cool-tool',
                description: 'New plugin with generic name',
                isArchived: false,
                isDisabled: false,
                isTemplate: false,
                pushedAt: '2026-11-25T01:00:00Z',
                stargazerCount: 0,
                defaultBranchRef: { name: 'main', target: { oid: SHA_A } },
                rootManifest: { byteSize: 210 },
                dotManifest: null,
                companion: null,
              },
              {
                id: 'R2',
                databaseId: 3002,
                name: 'already-known',
                nameWithOwner: 'prolific-dev/already-known',
                url: 'https://github.com/prolific-dev/already-known',
                description: '',
                isArchived: false,
                isDisabled: false,
                isTemplate: false,
                pushedAt: '2026-11-25T01:00:00Z',
                stargazerCount: 0,
                defaultBranchRef: { name: 'main', target: { oid: SHA_B } },
                rootManifest: { byteSize: 210 },
                dotManifest: null,
                companion: null,
              },
              {
                id: 'R3',
                databaseId: 3003,
                name: 'random-notes',
                nameWithOwner: 'prolific-dev/random-notes',
                url: 'https://github.com/prolific-dev/random-notes',
                description: 'Not a plugin',
                isArchived: false,
                isDisabled: false,
                isTemplate: false,
                pushedAt: '2026-11-25T01:00:00Z',
                stargazerCount: 0,
                defaultBranchRef: { name: 'main', target: { oid: SHA_C } },
                rootManifest: null,
                dotManifest: null,
                companion: null,
              },
            ],
          },
        },
      },
    });
  };

  const out = await batchAuthorExpansion(['prolific-dev'], {
    knownRepoKeys: new Set(['prolific-dev/already-known']),
    token: 'tok',
    fetchImpl,
  });
  assert.equal(out.candidates.length, 1);
  assert.equal(out.candidates[0].fullName, 'prolific-dev/untagged-cool-tool');
  assert.equal(out.candidates[0].hasDirectManifest, true);
});

test('batchTrack1DualLookup: detects RepoJacking (Case A), seamless rename (Case B), and nodeId backfill', async () => {
  const fetchImpl = async (_url, init) => {
    const { query, variables } = JSON.parse(init.body);
    assert.ok(query.includes('byIdNodes: nodes(ids: $nodeIds)'));
    assert.ok(query.includes('releases(first: 10'));
    assert.deepEqual(variables.nodeIds, ['R_orig_hijack', 'R_orig_renamed']);

    return makeJsonResponse(200, {
      data: {
        rateLimit: { cost: 2, remaining: 4990, resetAt: '2026-11-25T20:00:00Z' },
        byIdNodes: [
          {
            id: 'R_orig_hijack',
            databaseId: 100,
            name: 'plugin-a',
            nameWithOwner: 'alice-archived/plugin-a',
            url: 'https://github.com/alice-archived/plugin-a',
            description: 'Original',
            isArchived: false,
            isDisabled: false,
            isTemplate: false,
            pushedAt: '2026-11-20T00:00:00Z',
            stargazerCount: 50,
            owner: { login: 'alice-archived', databaseId: 10 },
            defaultBranchRef: { name: 'main', target: { oid: SHA_A, committedDate: '2026-11-20T00:00:00Z' } },
            releases: { nodes: [] },
            refs: { nodes: [] },
          },
          {
            id: 'R_orig_renamed',
            databaseId: 200,
            name: 'plugin-b-v2',
            nameWithOwner: 'bob/plugin-b-v2',
            url: 'https://github.com/bob/plugin-b-v2',
            description: 'Renamed',
            isArchived: false,
            isDisabled: false,
            isTemplate: false,
            pushedAt: '2026-11-24T00:00:00Z',
            stargazerCount: 80,
            owner: { login: 'bob', databaseId: 20 },
            defaultBranchRef: { name: 'main', target: { oid: SHA_B, committedDate: '2026-11-24T00:00:00Z' } },
            releases: { nodes: [] },
            refs: { nodes: [] },
          },
        ],
        // Case A: Impostor repo sits on old slug `alice/plugin-a` with DIFFERENT databaseId=999
        slug_0: {
          id: 'R_impostor',
          databaseId: 999,
          name: 'plugin-a',
          nameWithOwner: 'alice/plugin-a',
          url: 'https://github.com/alice/plugin-a',
          description: 'Impostor!',
          isArchived: false,
          isDisabled: false,
          isTemplate: false,
          pushedAt: '2026-11-25T00:00:00Z',
          stargazerCount: 0,
          owner: { login: 'alice', databaseId: 9999 },
          defaultBranchRef: { name: 'main', target: { oid: SHA_C, committedDate: '2026-11-25T00:00:00Z' } },
          releases: { nodes: [] },
          refs: { nodes: [] },
        },
        // Case B: Old slug `bob/plugin-b` returns NOT_FOUND
        slug_1: null,
        // Case C (first-run backfill): no nodeId stored yet, slug matches repositoryId=300
        slug_2: {
          id: 'R_backfilled_300',
          databaseId: 300,
          name: 'plugin-c',
          nameWithOwner: 'carol/plugin-c',
          url: 'https://github.com/carol/plugin-c',
          description: 'Backfill',
          isArchived: false,
          isDisabled: false,
          isTemplate: false,
          pushedAt: '2026-11-25T00:00:00Z',
          stargazerCount: 15,
          owner: { login: 'carol', databaseId: 30 },
          defaultBranchRef: { name: 'main', target: { oid: SHA_A, committedDate: '2026-11-25T00:00:00Z' } },
          releases: { nodes: [] },
          refs: { nodes: [] },
        },
      },
      errors: [{ type: 'NOT_FOUND', path: ['slug_1'], message: 'Not found' }],
    });
  };

  const out = await batchTrack1DualLookup(
    [
      { entrySlug: 'alice__plugin-a', canonicalName: 'plugin-a', repositoryId: 100, ownerId: 10, repoFullName: 'alice/plugin-a', nodeId: 'R_orig_hijack' },
      { entrySlug: 'bob__plugin-b', canonicalName: 'plugin-b', repositoryId: 200, ownerId: 20, repoFullName: 'bob/plugin-b', nodeId: 'R_orig_renamed' },
      { entrySlug: 'carol__plugin-c', canonicalName: 'plugin-c', repositoryId: 300, ownerId: 30, repoFullName: 'carol/plugin-c', nodeId: null },
    ],
    { token: 'tok', fetchImpl },
  );

  const a = out.results.get('alice__plugin-a');
  assert.equal(a.repoByNumericId.id, 100);
  assert.equal(a.repoAtOldSlug.id, 999);

  const b = out.results.get('bob__plugin-b');
  assert.equal(b.repoByNumericId.full_name, 'bob/plugin-b-v2');
  assert.equal(b.repoAtOldSlug, null);
  assert.equal(b.slugNotFound, true);
  assert.equal(b.needsRestFallbackById, false);

  const c = out.results.get('carol__plugin-c');
  assert.equal(c.nodeId, 'R_backfilled_300');
  assert.equal(c.repoByNumericId.id, 300);
  assert.equal(c.needsRestFallbackById, false);
});

test('parseOwnerRepoSpec validates safe owner/repo inputs', () => {
  assert.deepEqual(parseOwnerRepoSpec('Alice/My-Repo.git'), {
    owner: 'Alice',
    repo: 'My-Repo',
    fullName: 'Alice/My-Repo',
    key: 'alice/my-repo',
  });
  assert.equal(parseOwnerRepoSpec('bad owner/repo'), null);
  assert.equal(parseOwnerRepoSpec('owner/"injection'), null);
});

// ============================================================================
// Adaptive Discovery Tests (`scripts/lib/adaptive-discovery.mjs`)
// ============================================================================

test('AdaptiveRangeSlicer: bisects pushed -> stars -> separate sizeClause with ZERO infinite loop and resumes startPage cleanly', async () => {
  const slicer = new AdaptiveRangeSlicer({ nSafe: 900, minSpanMs: 3_600_000, stopAfterEmptyPages: 0 });

  // Part A: Stress-test hot 30-minute window (>900 results even after stars + size split -> MUST terminate, zero duplicate sizeClause!)
  const stateA = createDefaultDiscoveryState();
  const baseLo = Date.parse('2026-11-25T10:00:00Z');
  const baseHi = Date.parse('2026-11-25T10:30:00Z');
  stateA.pendingIntervals.hot = [{ loMs: baseLo, hiMs: baseHi, starClause: '', sizeClause: '', startPage: 1, isIncremental: true }];
  const seenHotQueries = [];

  const resA = await slicer.runQuery({
    queryId: 'hot',
    baseQuery: 'topic:antigravity-plugin archived:false',
    discoveryState: stateA,
    pageBudget: 15,
    nowMs: baseHi,
    fetchPageFn: async (q, page) => {
      seenHotQueries.push({ q, page });
      // Verify no duplicate `size:` clause ever appears!
      const sizeMatches = q.match(/\bsize:/g) || [];
      assert.ok(sizeMatches.length <= 1, `Duplicate size: clause detected in query: ${q}`);
      return {
        ok: true,
        totalCount: 1500, // always > 900 to force full stars -> size subdivision -> pagination termination
        items: [{ full_name: `u/r-${seenHotQueries.length}` }],
      };
    },
  });

  assert.equal(resA.pagesUsed, 15);
  assert.ok(seenHotQueries.some((x) => x.q.includes('stars:>10') && !x.q.includes('size:')));
  assert.ok(seenHotQueries.some((x) => x.q.includes('stars:>10') && x.q.includes('size:>1000')));
  // Once stars + size are BOTH set, it falls through to page 2 (terminating subdivision!)
  assert.ok(seenHotQueries.some((x) => x.q.includes('size:>1000') && x.page === 2));

  // Part B: Resumable `startPage` when pageBudget cuts off mid-segment (450 items = 5 pages, budget = 2 per run)
  const stateB = createDefaultDiscoveryState();
  const t0 = Date.parse('2026-11-24T00:00:00Z');
  const t1 = Date.parse('2026-11-25T00:00:00Z');
  const fetchedPages = [];

  const mockPagedFetch = async (_q, page, perPage) => {
    fetchedPages.push(page);
    const count = page < 5 ? perPage : 50;
    return {
      ok: true,
      totalCount: 450,
      items: Array.from({ length: count }, (_, idx) => ({ full_name: `p${page}/r${idx}` })),
    };
  };

  // Run 1: budget 2 -> pages 1, 2; stack retains startPage: 3
  const run1 = await slicer.runQuery({
    queryId: 'paged',
    baseQuery: 'topic:antigravity-plugin archived:false',
    discoveryState: stateB,
    pageBudget: 2,
    nowMs: t1,
    epochMs: t0,
    fetchPageFn: mockPagedFetch,
  });
  assert.deepEqual(fetchedPages, [1, 2]);
  assert.equal(run1.items.length, 200);
  assert.equal(stateB.pendingIntervals.paged[0].startPage, 3);
  assert.equal(stateB.watermarks.paged, undefined, 'Watermark must NOT advance until incremental segment completes');

  // Run 2: budget 2 -> pages 3, 4; stack retains startPage: 5
  const run2 = await slicer.runQuery({
    queryId: 'paged',
    baseQuery: 'topic:antigravity-plugin archived:false',
    discoveryState: stateB,
    pageBudget: 2,
    nowMs: t1,
    epochMs: t0,
    fetchPageFn: mockPagedFetch,
  });
  assert.deepEqual(fetchedPages, [1, 2, 3, 4]);
  assert.equal(run2.items.length, 200);
  assert.equal(stateB.pendingIntervals.paged[0].startPage, 5);

  // Run 3: finishes page 5 and advances watermark!
  const run3 = await slicer.runQuery({
    queryId: 'paged',
    baseQuery: 'topic:antigravity-plugin archived:false',
    discoveryState: stateB,
    pageBudget: 2,
    nowMs: t1,
    epochMs: t0,
    fetchPageFn: mockPagedFetch,
  });
  assert.deepEqual(fetchedPages, [1, 2, 3, 4, 5]);
  assert.equal(run3.items.length, 50);
  assert.equal(stateB.pendingIntervals.paged.length, 0);
  assert.equal(stateB.watermarks.paged, '2026-11-25T00:00:00Z');
});

test('DiscountedUcb1Cost: enforces 15% recall floor, favors high-yield arms, discounts by gamma=0.92, and attributes 1/k(r)', () => {
  const bandit = new DiscountedUcb1Cost({ gamma: 0.92, floorRatio: 0.15, maxStaleRuns: 4, defaultMaxUnitsPerArm: 5 });
  const arms = [
    { id: 'arm-hot', maxUnits: 5 },
    { id: 'arm-cold', maxUnits: 5 },
    { id: 'arm-stale', maxUnits: 5 },
  ];
  const state = {
    gamma: 0.92,
    arms: {
      'arm-hot': { discountedReward: 20, discountedCost: 4, discountedPulls: 4, totalPulls: 10, runsSinceLastPull: 0 },
      'arm-cold': { discountedReward: 0.2, discountedCost: 4, discountedPulls: 4, totalPulls: 10, runsSinceLastPull: 0 },
      'arm-stale': { discountedReward: 0.1, discountedCost: 4, discountedPulls: 4, totalPulls: 10, runsSinceLastPull: 5 },
    },
  };

  const alloc = bandit.allocateBudget(arms, 10, state);
  assert.equal(alloc.get('arm-stale') >= 1, true, 'Stale arm (>=4 runs) must receive recall-floor unit');
  assert.ok((alloc.get('arm-hot') || 0) > (alloc.get('arm-cold') || 0), 'High-yield arm must out-allocate cold arm');

  // Verify fractional attribution 1/k(r)
  const rewards = bandit.computeFractionalAttribution(
    {
      'arm-hot': ['a/shared-new', 'a/only-hot', 'a/existing-updated', 'a/existing-unchanged'],
      'arm-cold': ['a/shared-new', 'a/existing-updated'],
    },
    {
      knownValidRepoKeys: new Set(['a/existing-updated', 'a/existing-unchanged']),
      updatedRepoKeys: new Set(['a/existing-updated']),
      updateWeight: 0.25,
    },
  );
  // a/shared-new -> 0.5 each; a/only-hot -> 1.0 to hot; a/existing-updated -> 0.125 each
  assert.equal(rewards.get('arm-hot'), 1.625);
  assert.equal(rewards.get('arm-cold'), 0.625);

  // Verify exponential discounting & staleness increment
  const next = bandit.updateState(
    state,
    { 'arm-hot': { reward: 3, cost: 2, pulls: 2 } },
    { allArmIds: ['arm-hot', 'arm-cold', 'arm-stale'], nowIso: '2026-11-25T12:00:00Z' },
  );
  assert.equal(next.arms['arm-hot'].runsSinceLastPull, 0);
  assert.ok(Math.abs(next.arms['arm-hot'].discountedReward - (20 * 0.92 + 3)) < 1e-4);
  assert.equal(next.arms['arm-cold'].runsSinceLastPull, 1);
  assert.equal(next.arms['arm-stale'].runsSinceLastPull, 6);
});

test('Code Search validation, -repo: 250-char cap, and CodeSearchPacer rate-limit resilience', async () => {
  // All validated fingerprint queries MUST pass strict 422 checks
  for (const spec of VALIDATED_CODE_SEARCH_QUERIES) {
    const check = validateCodeSearchQuery(spec.query);
    assert.equal(check.valid, true, `Query ${spec.id} failed validation: ${check.issues.join('; ')}`);
  }

  // Known broken legacy queries from #10 MUST be caught
  assert.equal(validateCodeSearchQuery('path:.antigravity-plugin/plugin.json').valid, false);
  assert.equal(validateCodeSearchQuery('path:.agents/plugins/ filename:plugin.json').valid, false);

  // `-repo:` exclusion strictly obeys `<= 250` char cap
  const baseQ = 'filename:plugin.json "antigravity"';
  const longRepos = Array.from({ length: 10 }, (_, i) => `very-long-monorepo-owner-name-${i}/antigravity-mega-plugins-pack-${i}`);
  const excludedQ = buildCodeSearchQueryWithExclusions(baseQ, longRepos, { maxLength: 250, maxExclusions: 5 });
  assert.ok(excludedQ.length <= 250, `Expected <=250 chars, got ${excludedQ.length}`);
  assert.ok(excludedQ.includes('-repo:'));
  assert.equal(validateCodeSearchQuery(excludedQ).valid, true);

  // CodeSearchPacer: sleeps on 429 & remaining===0 WITHOUT disabling; disables ONLY on 401 or non-RL 403
  let fakeNow = 1_700_000_000_000;
  const sleeps = [];
  const pacer = new CodeSearchPacer({
    minIntervalMs: 6800,
    resetPadMs: 1500,
    sleepImpl: async (ms) => {
      sleeps.push(ms);
      fakeNow += ms;
    },
    nowFn: () => fakeNow,
  });

  let callNum = 0;
  const fetch429Then200 = async () => {
    callNum += 1;
    if (callNum === 1) {
      return makeJsonResponse(429, 'rate limit exceeded', { 'retry-after': '10' });
    }
    return makeJsonResponse(200, { total_count: 1, items: [{ path: 'plugin.json' }] }, { 'x-ratelimit-remaining': '9' });
  };
  const r1 = await pacer.fetchPage('https://api.github.com/search/code?q=test', { fetchImpl: fetch429Then200 });
  assert.equal(r1.ok, true);
  assert.equal(pacer.disabled, false);
  assert.equal(sleeps[0], 11_500);

  // HTTP 422 must NOT disable pacer
  const r422 = await pacer.fetchPage('https://api.github.com/search/code?q=bad', {
    fetchImpl: async () => makeJsonResponse(422, 'Validation Failed'),
  });
  assert.equal(r422.invalidQuery, true);
  assert.equal(pacer.disabled, false);

  // Non-rate-limit 403 (default GITHUB_TOKEN) MUST disable pacer cleanly
  const r403 = await pacer.fetchPage('https://api.github.com/search/code?q=scope', {
    fetchImpl: async () => makeJsonResponse(403, 'Must be authenticated to access code search'),
  });
  assert.equal(r403.disabled, true);
  assert.equal(pacer.disabled, true);
  assert.equal(pacer.disabledReason, 'HTTP_403_FORBIDDEN');
});

test('1-hop README frontier + auto-aggregator promotion (>=8), npm Search bridge, and Topic Co-occurrence miner', async () => {
  const knownValid = new Set(Array.from({ length: 9 }, (_, i) => `dev${i}/valid-plugin-${i}`));
  const negCache = new Set(['bad/neg-plugin']);

  const awesomeMd = [
    ...Array.from({ length: 8 }, (_, i) => `- https://github.com/dev${i}/valid-plugin-${i}`),
    '- https://github.com/alice/agy-new-tool',
    '- https://github.com/shared/popular-tool',
    '- https://github.com/random/single-link-noise',
    '- https://github.com/google-labs-code/stitch-skills',
  ].join('\n');

  const secondMd = '- Check out https://github.com/shared/popular-tool and https://github.com/bad/neg-plugin';

  const frontier = mineReadmeFrontier(
    {
      'curator/awesome-agy': awesomeMd,
      'dev0/valid-plugin-0': secondMd,
    },
    { knownValidRepoKeys: knownValid, negCacheRepoKeys: negCache, autoAggregatorThreshold: 8 },
  );

  assert.equal(frontier.promotedAggregators.length, 1);
  assert.equal(frontier.promotedAggregators[0].repo, 'curator/awesome-agy');
  assert.equal(frontier.promotedAggregators[0].validLinkCount, 8);

  const candKeys = frontier.candidates.map((c) => c.key);
  assert.ok(candKeys.includes('alice/agy-new-tool'), 'AGY slug should qualify with indegree 1');
  assert.ok(candKeys.includes('shared/popular-tool'), 'Non-AGY slug should qualify with indegree >= 2');
  assert.ok(!candKeys.includes('random/single-link-noise'), 'Single-mention non-AGY noise must be excluded');
  assert.ok(!candKeys.includes('bad/neg-plugin'), 'Neg-cached repo must be skipped');
  assert.ok(!candKeys.includes('google-labs-code/stitch-skills'), 'Google 1st-party org must be skipped');

  // npm Search bridge
  const npmRes = await discoverFromNpmSearch({
    queries: ['keywords:antigravity-plugin'],
    fetchImpl: async () =>
      makeJsonResponse(200, {
        objects: [
          { package: { name: '@alice/agy-foo', links: { repository: 'git+https://github.com/alice/agy-foo.git' } } },
          { package: { name: '@google/ignore', links: { repository: 'https://github.com/google-labs-code/ignore' } } },
        ],
      }),
  });
  assert.equal(npmRes.candidates.length, 1);
  assert.equal(npmRes.candidates[0].fullName, 'alice/agy-foo');

  // Topic Co-occurrence auto-arm miner (`p_hat = c_V / (c_V + c_N + 5) >= 0.40 && c_V >= 3`)
  const autoTopics = mineCooccurringTopics({
    validReposTopics: [
      ['antigravity-plugin', 'antigravity-sidecar', 'ai'],
      ['antigravity-sidecar', 'agy-mcp'],
      ['antigravity-sidecar', 'agy-mcp'],
      ['antigravity-sidecar', 'agy-mcp'],
      ['antigravity-sidecar'],
      ['rare-topic'],
      ['rare-topic'],
    ],
    negReposTopics: [
      ['agy-mcp'],
      ['agy-mcp'],
      ['agy-mcp'],
    ],
  });
  // antigravity-sidecar: 5 / (5 + 0 + 5) = 0.50 >= 0.40 -> promoted
  // agy-mcp: 3 / (3 + 3 + 5) = 0.2727 < 0.40 -> rejected
  // ai -> generic noise excluded; antigravity-plugin -> seed excluded; rare-topic -> c_V < 3
  assert.equal(autoTopics.length, 1);
  assert.equal(autoTopics[0].topic, 'antigravity-sidecar');
  assert.equal(autoTopics[0].smoothedPrecision, 0.5);
  assert.equal(autoTopics[0].query, 'topic:antigravity-sidecar archived:false');
});

test('Neg-Cache v2 backoff, activity multiplier phi(a), wake-up gates, and tiered positive recrawl', () => {
  const now = Date.parse('2026-11-25T12:00:00Z');
  const dayMs = 86_400_000;

  assert.equal(classifyNegCacheReason('ERR_MISSING_PLUGIN_JSON'), 'missing_manifest');
  assert.equal(classifyNegCacheReason('ERR_TAR_SYMLINK_FORBIDDEN'), 'fixable_packaging');
  assert.equal(classifyNegCacheReason('ERR_NOT_ANTIGRAVITY_PLUGIN'), 'foreign_ecosystem');
  assert.equal(classifyNegCacheReason('ERR_REPO_NOT_FOUND'), 'terminal');

  assert.equal(computeActivityMultiplier(new Date(now - 2 * dayMs).toISOString(), now), 0.5);
  assert.equal(computeActivityMultiplier(new Date(now - 15 * dayMs).toISOString(), now), 1.0);
  assert.equal(computeActivityMultiplier(new Date(now - 60 * dayMs).toISOString(), now), 2.0);
  assert.equal(computeActivityMultiplier(new Date(now - 120 * dayMs).toISOString(), now), 4.0);

  // Active fixable repo (age < 7d, k=1): 24h * 0.5 = 12h
  const pActive = computeNextNegCacheProbe({
    reason: 'ERR_TAR_SYMLINK_FORBIDDEN',
    failureCount: 1,
    pushedAt: new Date(now - 1 * dayMs).toISOString(),
    nowMs: now,
  });
  assert.equal(pActive.intervalMs, 12 * 3_600_000);

  // Dormant foreign repo (age > 90d, k=3): 14d * 2.5^2 * 4 = 350d -> clamped to T_max = 120d
  const pForeign = computeNextNegCacheProbe({
    reason: 'ERR_NOT_ANTIGRAVITY_PLUGIN',
    failureCount: 3,
    pushedAt: new Date(now - 150 * dayMs).toISOString(),
    nowMs: now,
  });
  assert.equal(pForeign.intervalMs, 120 * dayMs);

  // Update & gate checks
  const entry = updateNegativeCacheEntry(null, {
    repositoryId: 42,
    headSha: SHA_A,
    pushedAt: new Date(now - 2 * dayMs).toISOString(),
    reason: 'ERR_MISSING_PLUGIN_JSON',
    nowMs: now,
    validatorVersion: CURRENT_VALIDATOR_VERSION,
  });
  assert.equal(entry.retryAfter, entry.nextProbeAt);
  assert.equal(shouldSkipNegativeCache(entry, { nowMs: now + 3_600_000 }).skip, true);
  // SHA changed -> wakes immediately
  assert.equal(shouldSkipNegativeCache(entry, { nowMs: now + 3_600_000, observedHeadSha: SHA_B }).wakeReason, 'head_sha_changed');
  // Validator upgraded -> wakes non-terminal entry immediately
  assert.equal(
    shouldSkipNegativeCache(entry, { nowMs: now + 3_600_000, validatorVersion: CURRENT_VALIDATOR_VERSION + 1 }).wakeReason,
    'validator_upgraded',
  );
  // Post-probe unchanged SHA -> still skips tarball download even after backoff elapsed!
  assert.equal(
    shouldSkipNegativeCache(entry, { nowMs: now + 10 * dayMs, observedHeadSha: SHA_A, phase: 'post-probe' }).reason,
    'head_sha_unchanged',
  );

  // Pruning stale entries past gcAfterMs
  const pruned = pruneNegativeCacheEntries(
    {
      'old/dead': { reason: 'ERR_MISSING_PLUGIN_JSON', nextProbeAt: new Date(now - 100 * dayMs).toISOString() },
      'fresh/neg': entry,
    },
    now,
  );
  assert.equal(Boolean(pruned['old/dead']), false);
  assert.equal(Boolean(pruned['fresh/neg']), true);

  // Positive recrawl tiers: hot every run, warm 1/4, cold 1/12
  assert.equal(classifyPositiveRecrawlTier({ repositoryId: 10, pushedAt: new Date(now - 3 * dayMs).toISOString(), stars: 0 }, { nowMs: now, runSlot: 3 }).due, true);
  assert.equal(classifyPositiveRecrawlTier({ repositoryId: 10, pushedAt: new Date(now - 100 * dayMs).toISOString(), stars: 25 }, { nowMs: now, runSlot: 3 }).tier, 'hot');

  let warmHits = 0;
  let coldHits = 0;
  for (let slot = 0; slot < 12; slot++) {
    if (classifyPositiveRecrawlTier({ repositoryId: 77, pushedAt: new Date(now - 40 * dayMs).toISOString(), stars: 2 }, { nowMs: now, runSlot: slot }).due) warmHits++;
    if (classifyPositiveRecrawlTier({ repositoryId: 77, pushedAt: new Date(now - 120 * dayMs).toISOString(), stars: 2 }, { nowMs: now, runSlot: slot }).due) coldHits++;
  }
  assert.equal(warmHits, 3);
  assert.equal(coldHits, 1);
});
