#!/usr/bin/env node
// OIDC Provenance Publisher for `@agy-market/catalog` (`scripts/publish-catalog-npm.mjs`).
// Publishes pure-JSON catalog artifacts to npm ONLY when content SHA-256 changes, enabling
// automatic replication across `registry.npmmirror.com` and Tencent Cloud npm mirrors.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { computeCatalogVersion } from './build-catalog.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');

export function computeCatalogContentHash(distDir) {
  const hash = createHash('sha256');
  for (const name of ['index.json', 'unverified-index.json', 'readmes.json']) {
    const p = join(distDir, name);
    if (!existsSync(p)) {
      throw new Error(`Missing built artifact ${p}; run scripts/build-catalog.mjs first`);
    }
    // Strip volatile `generatedAt` / `catalogVersion` so identical plugin payloads yield identical hash
    const parsed = JSON.parse(readFileSync(p, 'utf8'));
    const canonical = { ...parsed };
    delete canonical.generatedAt;
    delete canonical.catalogVersion;
    hash.update(name);
    hash.update(JSON.stringify(canonical));
  }
  return hash.digest('hex');
}

export function prepareNpmCatalogRelease({ repoRoot = REPO_ROOT, runNumber = 1, dryRun = true } = {}) {
  const distDir = join(repoRoot, 'dist');
  const hashFile = join(repoRoot, 'state', 'last-npm-hash.txt');
  const pkgPath = join(repoRoot, 'package.json');

  const nextHash = computeCatalogContentHash(distDir);
  const prevHash = existsSync(hashFile) ? readFileSync(hashFile, 'utf8').trim() : '';

  if (nextHash === prevHash) {
    return { changed: false, contentHash: nextHash, version: null };
  }

  const nextVersion = computeCatalogVersion(new Date(), runNumber);
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
  pkg.version = nextVersion;

  if (!dryRun) {
    writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`, 'utf8');
    const cleanEnv = { ...process.env };
    delete cleanEnv.ELECTRON_RUN_AS_NODE;
    execFileSync('npm', ['publish', '--provenance', '--access', 'public'], {
      cwd: repoRoot,
      env: cleanEnv,
      stdio: 'inherit',
    });
    writeFileSync(hashFile, `${nextHash}\n`, 'utf8');
  }

  return { changed: true, contentHash: nextHash, version: nextVersion };
}

if (import.meta.url === pathToFileURL(resolve(process.argv[1] || '')).href) {
  const dryRun = process.argv.includes('--dry-run') || !process.env.NPM_CONFIG_PROVENANCE;
  const runNum = Number(process.env.GITHUB_RUN_NUMBER || 1);
  const res = prepareNpmCatalogRelease({ runNumber: runNum, dryRun });
  console.log(`[publish-catalog-npm] changed=${res.changed} hash=${res.contentHash.slice(0, 12)} version=${res.version} dryRun=${dryRun}`);
}
