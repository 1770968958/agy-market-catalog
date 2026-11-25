#!/usr/bin/env node
// Pure parser & CLI for Tier-0 Community Plugin Nomination GitHub Issue Forms (`scripts/parse-nomination.mjs`).
// Parses GitHub Issue Form sections (`### Repository` / `### Plugin Root`) and validates via `parseSafeGitHubCandidateUrl`.

import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { normalizeRelPosix } from './lib/constants.mjs';
import { parseSafeGitHubCandidateUrl } from './lib/discovery-sources.mjs';
import { validateSafeArchivePath } from './lib/tar-stream.mjs';

const OWNER_REPO_SHORTHAND_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9._-]+$/;

function extractFormSections(body) {
  const sections = new Map();
  const lines = String(body || '').split(/\r?\n/);
  let currentHeading = null;
  let buffer = [];

  const flush = () => {
    if (!currentHeading) return;
    const raw = buffer.join('\n').trim();
    sections.set(currentHeading.toLowerCase(), raw === '_No response_' ? '' : raw);
  };

  for (const line of lines) {
    const m = /^###\s+(.+?)\s*$/.exec(line);
    if (m) {
      flush();
      currentHeading = m[1].trim();
      buffer = [];
    } else if (currentHeading !== null) {
      buffer.push(line);
    }
  }
  flush();
  return sections;
}

/**
 * Parses and validates a community-discovery nomination issue body.
 * Returns `{ ok: true, owner, repo, fullName, pluginRoot, targetArg }` or `{ ok: false, errorCode, message }`.
 */
export function parseNominationIssueBody(body) {
  const text = String(body || '').trim();
  if (!text) {
    return { ok: false, errorCode: 'ERR_EMPTY_NOMINATION', message: 'Issue body is empty' };
  }

  const sections = extractFormSections(text);
  let rawRepo = '';
  let rawPluginRoot = '';

  for (const [heading, val] of sections.entries()) {
    if (!rawRepo && /\b(?:repository|repo|github)\b/i.test(heading)) {
      rawRepo = val.split(/\r?\n/)[0]?.trim() || '';
    }
    if (!rawPluginRoot && /\b(?:plugin[\s_-]?root|subpath|directory)\b/i.test(heading)) {
      rawPluginRoot = val.split(/\r?\n/)[0]?.trim() || '';
    }
  }

  // Fallback for plain issue bodies containing a GitHub URL or `owner/repo`
  if (!rawRepo) {
    const urlMatch = /https:\/\/github\.com\/[^\s<>()"'`[\]]+/i.exec(text);
    if (urlMatch) {
      rawRepo = urlMatch[0];
    } else {
      const firstLine = text.split(/\r?\n/).map((l) => l.trim()).find(Boolean) || '';
      if (OWNER_REPO_SHORTHAND_RE.test(firstLine)) {
        rawRepo = firstLine;
      }
    }
  }

  if (!rawRepo) {
    return {
      ok: false,
      errorCode: 'ERR_INVALID_REPO_URL',
      message: 'Could not find a valid public GitHub repository (`owner/repo` or `https://github.com/owner/repo`).',
    };
  }

  const candidateUrl = rawRepo.startsWith('https://')
    ? rawRepo
    : OWNER_REPO_SHORTHAND_RE.test(rawRepo)
      ? `https://github.com/${rawRepo}`
      : rawRepo;

  const parsed = parseSafeGitHubCandidateUrl(candidateUrl);
  if (!parsed) {
    return {
      ok: false,
      errorCode: 'ERR_INVALID_REPO_URL',
      message: `Repository "${rawRepo}" failed safe GitHub URL allowlist validation (must be a public non-first-party https://github.com/<owner>/<repo>).`,
    };
  }

  let pluginRoot = parsed.explicitSubpath || '.';
  if (rawPluginRoot && rawPluginRoot !== '.') {
    const cleaned = rawPluginRoot.replace(/^[`"'<]+|[`"'>]+$/g, '').trim();
    if (cleaned && cleaned !== '.') {
      try {
        const safe = validateSafeArchivePath(cleaned);
        pluginRoot = normalizeRelPosix(safe || '.');
      } catch (err) {
        return {
          ok: false,
          errorCode: 'ERR_UNSAFE_PLUGIN_ROOT',
          message: `Invalid plugin_root "${rawPluginRoot}": ${err?.message || err}`,
        };
      }
    }
  }

  const targetArg =
    pluginRoot && pluginRoot !== '.'
      ? `https://github.com/${parsed.fullName}/tree/HEAD/${pluginRoot}`
      : parsed.fullName;

  return {
    ok: true,
    owner: parsed.owner,
    repo: parsed.repo,
    fullName: parsed.fullName,
    pluginRoot,
    targetArg,
  };
}

if (import.meta.url === pathToFileURL(resolve(process.argv[1] || '')).href) {
  const body = process.env.ISSUE_BODY || '';
  const result = parseNominationIssueBody(body);
  console.log(JSON.stringify(result));
  if (!result.ok) {
    process.exitCode = 1;
  }
}
