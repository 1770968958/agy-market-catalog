// Streaming Tarball & Antigravity 10-Field `plugin.json` + `agy-market.json` Validator (`scripts/validate-plugin-tarball.mjs`).

import {
  AGY_MARKET_JSON_ALLOWED_KEYS,
  ALLOWED_CATEGORIES,
  CANONICAL_NAME_RE,
  normalizeRelPosix,
  parseJsonc,
  parseSemver,
  PLUGIN_JSON_ALLOWED_KEYS,
  SCOPED_NAME_RE,
} from './lib/constants.mjs';
import { inspectTarGzBuffer } from './lib/tar-stream.mjs';
import { normalizeIconBuffer } from './sanitize-icon.mjs';
import { scanPluginCapabilities } from './scan-capabilities.mjs';

export function extractPluginRootFiles(allFilesMap, pluginRoot = '.') {
  const normRoot = normalizeRelPosix(pluginRoot);
  if (normRoot === '.') {
    return new Map(allFilesMap);
  }
  const prefix = `${normRoot}/`;
  const scoped = new Map();
  for (const [p, buf] of allFilesMap.entries()) {
    if (p.startsWith(prefix)) {
      scoped.set(p.slice(prefix.length), buf);
    }
  }
  return scoped;
}

export function validatePluginManifestObject(manifest, { allowScopedName = false } = {}) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new Error('ERR_PLUGIN_JSON_NOT_OBJECT: plugin.json root must be an object');
  }

  for (const key of Object.keys(manifest)) {
    if (!PLUGIN_JSON_ALLOWED_KEYS.has(key)) {
      throw new Error(
        `ERR_PLUGIN_JSON_UNKNOWN_KEY: "${key}" is outside Antigravity's 10-field plugin.json allowlist`,
      );
    }
  }

  if (typeof manifest.name !== 'string' || !manifest.name.trim()) {
    throw new Error('ERR_PLUGIN_JSON_NAME: "name" is required in plugin.json');
  }
  const nameValid = allowScopedName
    ? CANONICAL_NAME_RE.test(manifest.name) || SCOPED_NAME_RE.test(manifest.name)
    : CANONICAL_NAME_RE.test(manifest.name);
  if (!nameValid) {
    throw new Error(
      `ERR_PLUGIN_JSON_NAME_FORMAT: "${manifest.name}" must be lowercase kebab-case${allowScopedName ? '' : ' (single hyphens only; "--" is reserved for scoped installs)'}`,
    );
  }

  if (typeof manifest.description !== 'string' || !manifest.description.trim()) {
    throw new Error('ERR_PLUGIN_JSON_DESCRIPTION: "description" is required in plugin.json');
  }

  if (manifest.version !== undefined && !parseSemver(manifest.version)) {
    throw new Error(`ERR_PLUGIN_JSON_VERSION: "${manifest.version}" is not a valid SemVer string`);
  }

  if (manifest.logo !== undefined) {
    if (typeof manifest.logo !== 'string' || !manifest.logo.trim()) {
      throw new Error('ERR_PLUGIN_JSON_LOGO: "logo" must be a non-empty relative path');
    }
    if (/^https?:\/\//i.test(manifest.logo) || manifest.logo.startsWith('/') || manifest.logo.includes('..')) {
      throw new Error(
        `ERR_PLUGIN_JSON_LOGO_PATH: "${manifest.logo}" must be a relative path inside pluginRoot (never https:// or ..)`,
      );
    }
  }

  if (manifest.suggestedPrompts !== undefined) {
    if (
      !Array.isArray(manifest.suggestedPrompts) ||
      manifest.suggestedPrompts.length > 3 ||
      manifest.suggestedPrompts.some((s) => typeof s !== 'string' || !s.trim())
    ) {
      throw new Error('ERR_PLUGIN_JSON_PROMPTS: "suggestedPrompts" must be an array of 1..3 non-empty strings');
    }
  }

  return manifest;
}

export function validateMarketCompanionManifest(rawCompanion) {
  if (!rawCompanion || typeof rawCompanion !== 'object' || Array.isArray(rawCompanion)) {
    throw new Error('ERR_AGY_MARKET_JSON: agy-market.json must be a JSON object');
  }
  for (const key of Object.keys(rawCompanion)) {
    if (!AGY_MARKET_JSON_ALLOWED_KEYS.has(key)) {
      throw new Error(`ERR_AGY_MARKET_JSON_KEY: Unknown key "${key}" in agy-market.json`);
    }
  }
  if (rawCompanion.schemaVersion !== undefined && rawCompanion.schemaVersion !== 1) {
    throw new Error(`ERR_AGY_MARKET_SCHEMA_VERSION: Unsupported schemaVersion "${rawCompanion.schemaVersion}"`);
  }
  if (rawCompanion.categories !== undefined) {
    if (
      !Array.isArray(rawCompanion.categories) ||
      rawCompanion.categories.some((c) => typeof c !== 'string' || !ALLOWED_CATEGORIES.has(c))
    ) {
      throw new Error('ERR_AGY_MARKET_CATEGORIES: Invalid categories list in agy-market.json');
    }
  }
  if (rawCompanion.platforms !== undefined) {
    const validPlatforms = new Set(['win32', 'darwin', 'linux']);
    if (!Array.isArray(rawCompanion.platforms) || rawCompanion.platforms.some((p) => !validPlatforms.has(p))) {
      throw new Error('ERR_AGY_MARKET_PLATFORMS: platforms must be a subset of ["win32", "darwin", "linux"]');
    }
  }
  if (rawCompanion.preservePaths !== undefined) {
    if (
      !Array.isArray(rawCompanion.preservePaths) ||
      rawCompanion.preservePaths.some(
        (p) => typeof p !== 'string' || !p.trim() || p.includes('..') || p.startsWith('/') || /^[A-Za-z]:/.test(p),
      )
    ) {
      throw new Error('ERR_AGY_MARKET_PRESERVE_PATHS: preservePaths must be safe relative globs');
    }
  }
  return rawCompanion;
}

export function verifySelfContainedPrebuiltFiles(scopedFiles, packageJson = null) {
  for (const [relPath, buf] of scopedFiles.entries()) {
    const m = /^sidecars\/([^/]+)\/sidecar\.json$/.exec(relPath);
    if (!m) continue;
    const sidecarId = m[1];
    const parsed = parseJsonc(buf.toString('utf8'));
    const views = Array.isArray(parsed?.ui_config?.views) ? parsed.ui_config.views : [];
    for (const view of views) {
      if (!view || typeof view.path !== 'string') continue;
      const cleanView = view.path.split('?')[0].split('#')[0].replace(/^\/+/, '');
      const candidates = cleanView
        ? [`sidecars/${sidecarId}/${cleanView}`, `sidecars/${sidecarId}/${cleanView.replace(/\/+$/, '')}/index.html`]
        : [`sidecars/${sidecarId}/index.html`];
      if (!candidates.some((c) => scopedFiles.has(c))) {
        throw new Error(
          `ERR_UNBUILT_SOURCE_ARCHIVE: Missing prebuilt sidecar UI entrypoint "${candidates[0]}" in archive`,
        );
      }
    }
  }

  const deps = packageJson?.dependencies && typeof packageJson.dependencies === 'object' ? Object.keys(packageJson.dependencies) : [];
  if (deps.length > 0) {
    let hasBundledNodeModules = false;
    for (const k of scopedFiles.keys()) {
      if (k.startsWith('node_modules/')) {
        hasBundledNodeModules = true;
        break;
      }
    }
    if (!hasBundledNodeModules) {
      throw new Error(
        `ERR_UNBUNDLED_NPM_DEPS: Archive declares runtime dependencies (${deps.join(', ')}) without prebuilt bundle`,
      );
    }
  }
}

export function validatePluginTarball(
  compressedBuf,
  { pluginRoot = '.', allowScopedName = false, fallbackVersion = '', requireSelfContained = false } = {},
) {
  const tarInfo = inspectTarGzBuffer(compressedBuf);
  const scopedFiles = extractPluginRootFiles(tarInfo.files, pluginRoot);

  if (!scopedFiles.has('plugin.json')) {
    throw new Error(`ERR_MISSING_PLUGIN_JSON: No plugin.json found at pluginRoot "${pluginRoot}"`);
  }

  let manifest;
  try {
    manifest = parseJsonc(scopedFiles.get('plugin.json').toString('utf8'));
  } catch (err) {
    throw new Error(`ERR_INVALID_PLUGIN_JSON: Failed to parse plugin.json (${err?.message || String(err)})`);
  }
  validatePluginManifestObject(manifest, { allowScopedName });

  // Optional companion agy-market.json (in pluginRoot or archive root)
  let companion = null;
  const companionBuf = scopedFiles.get('agy-market.json') || tarInfo.files.get('agy-market.json') || null;
  if (companionBuf) {
    companion = validateMarketCompanionManifest(parseJsonc(companionBuf.toString('utf8')));
  }

  // Logo verification & sanitization
  let iconArtifact = null;
  if (manifest.logo) {
    const logoRel = normalizeRelPosix(manifest.logo);
    const logoBuf = scopedFiles.get(logoRel);
    if (!logoBuf) {
      throw new Error(`ERR_MISSING_LOGO_FILE: plugin.json.logo "${manifest.logo}" does not exist in tarball`);
    }
    iconArtifact = normalizeIconBuffer(logoBuf, logoRel);
  }

  // 4-Layer static capability & safety scan
  const { capabilities, components } = scanPluginCapabilities(scopedFiles, { pluginName: manifest.name });

  const readmeBuf =
    scopedFiles.get('README.md') ||
    scopedFiles.get('readme.md') ||
    tarInfo.files.get('README.md') ||
    null;
  const readmeMarkdown = readmeBuf ? readmeBuf.toString('utf8').slice(0, 64_000) : '';

  const parsedSemver = parseSemver(manifest.version || fallbackVersion || '0.1.0');
  if (!parsedSemver) {
    throw new Error('ERR_VERSION_MISSING: Neither plugin.json.version nor release tag provides a valid SemVer');
  }

  let packageJson = null;
  if (scopedFiles.has('package.json')) {
    try {
      packageJson = JSON.parse(scopedFiles.get('package.json').toString('utf8'));
    } catch {
      packageJson = null;
    }
  }

  if (requireSelfContained) {
    verifySelfContainedPrebuiltFiles(scopedFiles, packageJson);
  }

  return {
    sha256: tarInfo.sha256,
    sizeBytes: tarInfo.compressedBytes,
    manifest,
    companion,
    version: parsedSemver.version,
    iconArtifact,
    readmeMarkdown,
    capabilities,
    components,
    packageJson,
  };
}
