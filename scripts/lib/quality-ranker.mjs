// Composite Quality/Trust Ranking & Capability Privilege-Escalation Diff (`scripts/lib/quality-ranker.mjs`).
//
// Zero external dependencies; deterministic pure Node.js.
// Calibrated against live 852-plugin backtest:
//   - Strict [0, 100] clamp with additive +8 Track-1 verified bonus
//   - Multiplicative (0.5 + 0.5 * R_native) authenticity gate
//   - Monorepo star deflation s_eff + star-spam anomaly cap + alpha=0.5 (S_cap=500)
//   - Freshness decay (0.60 + 0.40 * hasSemver) / (1 + dt / H)^1.3
//   - Permissive host-enhancement policy: CDP & app.asar are NEVER penalized.

import { GENERIC_MCP_SERVER_NAMES, parseSemver } from './constants.mjs';

export const QUALITY_RANKER_VERSION = 1;

const ALPHA_PRIOR = 0.5;
const STARS_CAP = 500;
const FRESHNESS_GRAVITY = 1.3;
const HALF_LIFE_DEFAULT_DAYS = 120;
const HALF_LIFE_STABLE_DECL_DAYS = 240;
const TRACK1_ADDITIVE_BONUS = 8;

const NON_RUNTIME_TEST_RE = /(?:^|\/)(?:test|tests|__tests__|fixtures|mocks)\/|\.(?:test|spec)\.[a-z0-9]+$/i;
const SCRIPT_EXT_RE = /\.(?:mjs|cjs|js|ts|py|sh|ps1|cmd|bat)$/i;

const HIGH_RISK_SHELL_PATTERNS = [
  { id: 'curl_pipe_shell', re: /\b(?:curl|wget)\b[^\r\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/i },
  {
    id: 'powershell_encoded_or_iex',
    re: /\bpowershell(?:\.exe)?\b[^\r\n]*(?:-enc(?:odedcommand)?\b|Invoke-Expression\b|\biex\b)/i,
  },
  { id: 'eval_base64_decode', re: /\beval\s*\(\s*(?:atob\s*\(|Buffer\.from\s*\([^)]*['"]base64['"])/i },
  {
    id: 'function_ctor_base64',
    re: /\bnew\s+Function\s*\([^)]*Buffer\.from\s*\([^)]*['"]base64['"]/i,
  },
];

const CRITICAL_PATCH_BADGES = new Set(['lifecycle-hooks', 'mcp-stdio']);

function clamp(v, lo, hi) {
  return Math.max(lo, Math.min(hi, v));
}

function round2(v) {
  return Math.round(v * 100) / 100;
}

function round4(v) {
  return Math.round(v * 10000) / 10000;
}

function hasStableSemverVersion(plugin) {
  if (plugin?.gitTag) return true;
  const v = String(plugin?.version || '').trim();
  if (!v || /-git\./i.test(v)) return false;
  return Boolean(parseSemver(v));
}

function stripLightComments(src, relPath) {
  if (/\.(?:py|sh|ps1)$/i.test(relPath)) {
    return src.replace(/^\s*#.*$/gm, '');
  }
  return src.replace(/^\s*\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
}

/**
 * Computes calibrated composite quality/trust score Q(p) in [0, 100].
 *
 * Returns `{ score, compatTier, breakdown }`.
 */
export function computeQualityScore(
  plugin = {},
  {
    track = null,
    repoPluginCount = 1,
    nowMs = Date.now(),
    authenticityScore = null,
    compatTier = null,
    metadata = null,
    status = 'active',
  } = {},
) {
  const effectiveTrack =
    track ||
    plugin?._track ||
    plugin?.track ||
    (plugin?.forceScopedInstall === false ? 'verified' : 'unverified');
  const isTrack1 = effectiveTrack === 'verified';
  const meta = metadata || {};

  // 1. Popularity R_pop (monorepo-deflated + anti-star-spam + alpha=0.5, S_cap=500)
  const k = Math.max(1, Number(repoPluginCount || 1));
  const rawStars = Math.max(0, Number(plugin?.repository?.stars || 0));
  let sEff = k === 1 ? rawStars : rawStars / (1 + 0.75 * Math.pow(k - 1, 0.85));

  const forks = meta.forks !== undefined ? Number(meta.forks) : null;
  const repoAgeDays = meta.repoAgeDays !== undefined ? Number(meta.repoAgeDays) : null;
  const distinctCommits = meta.distinctCommits !== undefined ? Number(meta.distinctCommits) : null;
  if (
    rawStars > 50 &&
    forks === 0 &&
    repoAgeDays !== null &&
    repoAgeDays < 14 &&
    distinctCommits !== null &&
    distinctCommits < 5
  ) {
    sEff = Math.min(sEff, 10);
  }
  const rPop = clamp(Math.log(1 + sEff + ALPHA_PRIOR) / Math.log(1 + STARS_CAP + ALPHA_PRIOR), 0, 1);

  // 2. Freshness R_fresh ((0.60 + 0.40 * hasSemver) / (1 + dt / H)^1.3)
  const badges = Array.isArray(plugin?.capabilities?.badges) ? plugin.capabilities.badges : [];
  const hasSemver =
    typeof meta.hasSemverTag === 'boolean' ? meta.hasSemverTag : hasStableSemverVersion(plugin);
  const parsedVer = parseSemver(plugin?.version || '');
  const isStableDeclarative =
    badges.includes('declarative-only') && hasSemver && parsedVer !== null && parsedVer.major >= 1;
  const halfLife = isStableDeclarative ? HALF_LIFE_STABLE_DECL_DAYS : HALF_LIFE_DEFAULT_DAYS;

  const updatedTs = Date.parse(plugin?.updatedAt || plugin?.repository?.pushedAt || '');
  const dtDays = Number.isFinite(updatedTs) ? Math.max(0, (nowMs - updatedTs) / 86_400_000) : 180;
  const rFresh = clamp((0.6 + 0.4 * (hasSemver ? 1 : 0)) / Math.pow(1 + dtDays / halfLife, FRESHNESS_GRAVITY), 0, 1);

  // 3. Structural Completeness R_struct (observable-normalized so Track 1 & Track 2 compare fairly)
  let structEarned = 0;
  let structMax = 0;

  // Icon (+0.15)
  structMax += 0.15;
  if (plugin?.media?.iconUrl) structEarned += 0.15;

  // Distribution release hygiene (+0.18 release asset / +0.10 semver tag)
  structMax += 0.18;
  const tarballUrl = String(plugin?.distribution?.tarballUrl || '');
  const hasReleaseAsset =
    typeof meta.hasReleaseAsset === 'boolean'
      ? meta.hasReleaseAsset
      : tarballUrl.includes('/releases/download/');
  if (hasReleaseAsset) {
    structEarned += 0.18;
  } else if (hasSemver) {
    structEarned += 0.1;
  }

  // Structured runtime/frontmatter component vs bare rules-only (+0.06)
  structMax += 0.06;
  const hasStructuredComponent =
    typeof meta.hasStructuredComponent === 'boolean'
      ? meta.hasStructuredComponent
      : badges.some(
          (b) =>
            b === 'sidecar-ui' ||
            b === 'mcp-stdio' ||
            b === 'mcp-remote' ||
            b === 'declarative-only' ||
            b === 'lifecycle-hooks',
        );
  if (hasStructuredComponent) structEarned += 0.06;

  // Optional observable README richness (+0.12 substantive, +0.08 bilingual)
  if (typeof meta.readmeLength === 'number') {
    structMax += 0.12;
    if (meta.readmeLength >= 400) structEarned += 0.12;
    else if (meta.readmeLength >= 100) structEarned += 0.06;
  }
  if (typeof meta.isBilingualReadme === 'boolean') {
    structMax += 0.08;
    if (meta.isBilingualReadme) structEarned += 0.08;
  }

  // Optional extended crawl-time booleans (included symmetrically when observed)
  if (typeof meta.strictManifest === 'boolean') {
    structMax += 0.15;
    if (meta.strictManifest) structEarned += 0.15;
  }
  if (typeof meta.hasLicense === 'boolean') {
    structMax += 0.1;
    if (meta.hasLicense) structEarned += 0.1;
  }
  if (typeof meta.hasCompanion === 'boolean' || typeof meta.hasSuggestedPrompts === 'boolean') {
    structMax += 0.08;
    if (meta.hasCompanion || meta.hasSuggestedPrompts) structEarned += 0.08;
  }
  if (typeof meta.hasCiTests === 'boolean') {
    structMax += 0.08;
    if (meta.hasCiTests) structEarned += 0.08;
  }

  const rStruct = structMax > 0 ? clamp(structEarned / structMax, 0, 1) : 0.5;

  // 4. Native Antigravity Authenticity R_native + multiplicative gate (0.5 + 0.5 * R_native)
  const rawNative =
    typeof authenticityScore === 'number' && Number.isFinite(authenticityScore)
      ? authenticityScore
      : typeof plugin?.authenticity?.score === 'number' && Number.isFinite(plugin.authenticity.score)
        ? plugin.authenticity.score
        : isTrack1
          ? 1.0
          : 0.85;
  const rNative = clamp(rawNative, 0, 1);
  const nativeGate = 0.5 + 0.5 * rNative;

  const resolvedCompatTier =
    compatTier ||
    plugin?.authenticity?.compatTier ||
    plugin?.ranking?.compatTier ||
    (isTrack1 || rNative >= 0.88 ? 'native' : rNative >= 0.72 ? 'compatible' : null);

  // 5. Security & Hygiene R_hygiene (NOTE: `host-enhancement` CDP/app.asar is NEVER penalized!)
  let rHygiene = 1.0;

  const genericMcpCount = Array.isArray(meta.genericMcpViolations)
    ? meta.genericMcpViolations.length
    : Number(meta.genericMcpViolations || 0) ||
      (Array.isArray(plugin?.capabilities?.mcpServers)
        ? plugin.capabilities.mcpServers.filter((s) => {
            const rawKey = String(s || '').split('_').pop()?.toLowerCase() || '';
            return GENERIC_MCP_SERVER_NAMES.has(rawKey);
          }).length
        : 0);
  if (genericMcpCount > 0) rHygiene -= 0.2;

  const rulesTokens = Number(plugin?.capabilities?.rulesEstimatedTokens || 0);
  if (rulesTokens > 2500) {
    rHygiene -= 0.15 * Math.min(1, (rulesTokens - 2500) / 3500);
  }

  const sizeBytes = Number(plugin?.distribution?.sizeBytes || 0);
  if (sizeBytes > 25 * 1024 * 1024) {
    rHygiene -= 0.15;
  }

  if (meta.hasSkillOrAgentCollision) {
    rHygiene -= 0.25;
  }
  if (meta.hasUnreviewedEscalation) {
    rHygiene -= 0.35;
  }
  if (!Number(plugin?.repository?.repositoryId || 0)) {
    rHygiene -= 0.1;
  }
  rHygiene = clamp(rHygiene, 0, 1);

  // 6. Combine with additive +8 Track-1 bonus, multiplicative native gate, status penalty, and [0, 100] clamp
  const weightedBase =
    100 * (0.25 * rPop + 0.22 * rFresh + 0.25 * rStruct + 0.18 * rNative + 0.1 * rHygiene);
  const trackBonus = isTrack1 ? TRACK1_ADDITIVE_BONUS : 0;

  const normStatus = String(status || plugin?.status || 'active').toUpperCase();
  let penaltyMultiplier = 1.0;
  if (
    normStatus === 'QUARANTINED' ||
    normStatus === 'REPOJACKING_BLOCKED' ||
    normStatus === 'TAG_MUTATION_BLOCKED' ||
    normStatus === 'DEPRECATED_GONE'
  ) {
    penaltyMultiplier = 0.0;
  } else if (normStatus === 'ARCHIVED') {
    penaltyMultiplier = 0.4;
  } else if (normStatus === 'STALE_WARNING') {
    penaltyMultiplier = 0.5;
  } else if (normStatus === 'PRIVILEGE_REVIEW' || normStatus === 'OWNERSHIP_TRANSFER_REVIEW') {
    penaltyMultiplier = 0.7;
  }

  const score = round2(clamp((weightedBase * nativeGate + trackBonus) * penaltyMultiplier, 0, 100));

  return {
    score,
    compatTier: resolvedCompatTier,
    breakdown: {
      popularity: round4(rPop),
      freshness: round4(rFresh),
      completeness: round4(rStruct),
      native: round4(rNative),
      hygiene: round4(rHygiene),
      nativeGate: round4(nativeGate),
      trackBonus,
      penaltyMultiplier,
      effectiveStars: round2(sEff),
    },
  };
}

/**
 * Applies viewport monorepo slot dampening: for entries sharing the same repository,
 * multiplies the k-th entry's display sort score by `1 / (1 + 0.15 * (k - 1))`.
 */
export function applyMonorepoSlotDampening(plugins = []) {
  const sorted = [...plugins].sort(
    (a, b) =>
      Number(b?.ranking?.score ?? 0) - Number(a?.ranking?.score ?? 0) ||
      Number(b?.repository?.stars ?? 0) - Number(a?.repository?.stars ?? 0) ||
      String(a?.id || '').localeCompare(String(b?.id || '')),
  );

  const repoRankCount = new Map();
  const dampened = sorted.map((p) => {
    const rid = Number(p?.repository?.repositoryId || 0);
    const repoKey = rid > 0 ? `id:${rid}` : String(p?.repository?.url || p?.id || '').toLowerCase();
    const k = (repoRankCount.get(repoKey) || 0) + 1;
    repoRankCount.set(repoKey, k);
    const baseScore = Number(p?.ranking?.score ?? 0);
    const displayScore = round2(baseScore / (1 + 0.15 * (k - 1)));
    return { plugin: p, slotIndex: k, displayScore };
  });

  dampened.sort(
    (a, b) =>
      b.displayScore - a.displayScore ||
      Number(b.plugin?.repository?.stars ?? 0) - Number(a.plugin?.repository?.stars ?? 0) ||
      String(a.plugin?.id || '').localeCompare(String(b.plugin?.id || '')),
  );
  return dampened.map((d) => d.plugin);
}

function scanScopedFilesForHighRiskShell(scopedFiles) {
  if (!scopedFiles) return [];
  const entries = typeof scopedFiles.entries === 'function' ? [...scopedFiles.entries()] : Object.entries(scopedFiles);
  const findings = [];
  for (const [relPath, rawBuf] of entries) {
    const norm = String(relPath || '').replace(/\\/g, '/');
    if (!SCRIPT_EXT_RE.test(norm) || NON_RUNTIME_TEST_RE.test(norm)) continue;
    const rawText = Buffer.isBuffer(rawBuf) ? rawBuf.toString('utf8') : String(rawBuf || '');
    const stripped = stripLightComments(rawText.slice(0, 256_000), norm);
    for (const pat of HIGH_RISK_SHELL_PATTERNS) {
      if (pat.re.test(stripped)) {
        findings.push({ file: norm, pattern: pat.id });
      }
    }
  }
  return findings;
}

/**
 * Computes security-relevant capability deltas between two plugin versions.
 * Runs unconditionally on EVERY Track-1 and Track-2 update (not only when `ownerChanged`).
 *
 * Returns `{ severity: 'NONE'|'MODERATE'|'CRITICAL', action: 'ALLOW'|'ESCALATION_MODAL'|'PRIVILEGE_REVIEW', hasExpansion, reasons, escalation }`.
 */
export function computeCapabilityDiff(
  prevCaps = null,
  nextCaps = null,
  { ownerChanged = false, prevVersion = '', nextVersion = '', scopedFiles = null } = {},
) {
  const prev = prevCaps || {};
  const next = nextCaps || {};

  const prevBadges = new Set(prev.badges || []);
  const addedBadges = [...new Set(next.badges || [])].filter((b) => b !== 'declarative-only' && !prevBadges.has(b));

  const prevDomains = new Set((prev.mcpRemoteDomains || []).map((d) => String(d).toLowerCase()));
  const addedRemoteDomains = [...new Set((next.mcpRemoteDomains || []).map((d) => String(d).toLowerCase()))].filter(
    (d) => !prevDomains.has(d),
  );

  const prevHooks = new Set(prev.hookEvents || []);
  const addedHookEvents = [...new Set(next.hookEvents || [])].filter((e) => !prevHooks.has(e));

  const prevHostKinds = new Set(prev.hostEnhancementKind || []);
  const addedHostEnhancementKinds = [...new Set(next.hostEnhancementKind || [])].filter((k) => !prevHostKinds.has(k));

  const prevServers = new Set(prev.mcpServers || []);
  const addedMcpServers = [...new Set(next.mcpServers || [])].filter((s) => !prevServers.has(s));

  const prevTokens = Number(prev.rulesEstimatedTokens || 0);
  const nextTokens = Number(next.rulesEstimatedTokens || 0);
  const rulesTokenDelta = nextTokens - prevTokens;
  const rulesTokenRatio = prevTokens > 0 ? nextTokens / prevTokens : nextTokens > 0 ? Infinity : 1;

  const suspiciousShellFindings = scanScopedFilesForHighRiskShell(scopedFiles);

  const pSem = parseSemver(prevVersion);
  const nSem = parseSemver(nextVersion);
  const isPatchBump = Boolean(
    pSem && nSem && pSem.major === nSem.major && pSem.minor === nSem.minor && nSem.patch > pSem.patch,
  );

  const reasons = [];
  let severity = 'NONE';

  if (addedRemoteDomains.length > 0) {
    severity = 'CRITICAL';
    reasons.push(`NEW_MCP_REMOTE_DOMAINS:${addedRemoteDomains.join(',')}`);
  }
  if (ownerChanged && (addedBadges.length > 0 || addedHookEvents.length > 0 || addedMcpServers.length > 0)) {
    severity = 'CRITICAL';
    reasons.push('OWNER_TRANSFER_CAPABILITY_EXPANSION');
  }
  if (
    isPatchBump &&
    (addedBadges.some((b) => CRITICAL_PATCH_BADGES.has(b)) || addedHostEnhancementKinds.includes('app-asar'))
  ) {
    severity = 'CRITICAL';
    reasons.push('PATCH_BUMP_HIGH_PRIVILEGE_ADDITION');
  }
  if (rulesTokenDelta > 1500 && rulesTokenRatio > 2.0) {
    severity = 'CRITICAL';
    reasons.push(`RULES_TOKEN_SPIKE:+${rulesTokenDelta}`);
  }
  if (suspiciousShellFindings.length > 0) {
    severity = 'CRITICAL';
    reasons.push(`HIGH_RISK_SHELL_PATTERN:${suspiciousShellFindings.map((f) => f.pattern).join(',')}`);
  }

  const hasModerateDelta =
    addedBadges.length > 0 ||
    addedHookEvents.length > 0 ||
    addedMcpServers.length > 0 ||
    addedHostEnhancementKinds.length > 0;

  if (severity === 'NONE' && hasModerateDelta) {
    severity = 'MODERATE';
    if (addedBadges.length > 0) reasons.push(`ADDED_BADGES:${addedBadges.join(',')}`);
    if (addedHookEvents.length > 0) reasons.push(`ADDED_HOOKS:${addedHookEvents.join(',')}`);
    if (addedMcpServers.length > 0) reasons.push(`ADDED_MCP:${addedMcpServers.join(',')}`);
  }

  const action =
    severity === 'CRITICAL' ? 'PRIVILEGE_REVIEW' : severity === 'MODERATE' ? 'ESCALATION_MODAL' : 'ALLOW';

  return {
    severity,
    action,
    hasExpansion: severity !== 'NONE',
    reasons,
    escalation: {
      addedBadges: addedBadges.sort(),
      addedRemoteDomains: addedRemoteDomains.sort(),
      addedHookEvents: addedHookEvents.sort(),
      addedHostEnhancementKinds: addedHostEnhancementKinds.sort(),
      addedMcpServers: addedMcpServers.sort(),
      rulesTokenDelta,
      suspiciousShellFindings,
    },
  };
}
