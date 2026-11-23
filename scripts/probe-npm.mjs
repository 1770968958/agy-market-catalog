// Bidirectional npm Mirror Anti-Squatting Verifier (`scripts/probe-npm.mjs`).
// Only populates `distribution.npmMirrorPkg` when a plugin bundle contains a `package.json`
// AND `registry.npmjs.org/<pkg>/latest` proves repository ownership back to the exact `owner/repo`.

export function normalizeGithubRepoSlug(rawRepoField) {
  const urlStr =
    typeof rawRepoField === 'string'
      ? rawRepoField
      : rawRepoField && typeof rawRepoField.url === 'string'
        ? rawRepoField.url
        : '';
  if (!urlStr) return null;
  const m = /github\.com[/:]([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+?)(?:\.git|\/)?$/i.exec(urlStr.trim());
  if (!m) return null;
  return `${m[1].toLowerCase()}/${m[2].toLowerCase()}`;
}

export function verifyBidirectionalNpmOwnership({ packageJson, npmLatestDoc, expectedRepoFullName }) {
  const pkgName = packageJson?.name;
  if (typeof pkgName !== 'string' || !pkgName.trim()) return null;
  if (!npmLatestDoc || typeof npmLatestDoc !== 'object') return null;
  if (npmLatestDoc.name !== pkgName) return null;

  const expectedLower = String(expectedRepoFullName || '').toLowerCase();
  const npmRepoSlug = normalizeGithubRepoSlug(npmLatestDoc.repository);
  if (!npmRepoSlug || npmRepoSlug !== expectedLower) {
    return null;
  }
  return pkgName;
}

export async function probeNpmMirrorPackage(packageJson, expectedRepoFullName, { fetchImpl = fetch } = {}) {
  const pkgName = packageJson?.name;
  if (typeof pkgName !== 'string' || !pkgName.trim()) return null;
  try {
    const encoded = pkgName.startsWith('@') ? `@${encodeURIComponent(pkgName.slice(1))}` : encodeURIComponent(pkgName);
    const res = await fetchImpl(`https://registry.npmjs.org/${encoded}/latest`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) return null;
    const doc = await res.json();
    return verifyBidirectionalNpmOwnership({ packageJson, npmLatestDoc: doc, expectedRepoFullName });
  } catch {
    return null;
  }
}
