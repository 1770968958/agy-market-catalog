// 4-Layer Static Capability & Safety Scanner (`scripts/scan-capabilities.mjs`).
//
// Security Philosophy:
//   - HARD-BLOCK genuine supply-chain / exfiltration attacks:
//       1. `rules/*.md` `@[label](path)` local-file exfiltration (`..`, `~/`, `$ENV`, absolute paths) & >24KB ceiling
//       2. Invisible prompt-injection smuggling (Unicode Tag block U+E0000..U+E007F & bidi overrides)
//   - PERMISSIVELY PROFILE legitimate Antigravity capabilities (including CDP & `app.asar` host enhancements ->
//     gentle `host-enhancement` badge `💡 宿主界面增强`, NEVER blocked or penalized).

import { GENERIC_MCP_SERVER_NAMES, MAX_RULE_FILE_BYTES, parseJsonc } from './lib/constants.mjs';

const INVISIBLE_SMUGGLING_RE = /[\u{E0000}-\u{E007F}\u202A-\u202E\u2066-\u2069]/u;

const CDP_DETECTION_RE =
  /--remote-debugging-port|webSocketDebuggerUrl|DevToolsActivePort|Runtime\.evaluate|Page\.addScriptToEvaluateOnNewDocument/;

const ASAR_DETECTION_RE = /\bapp\.asar\b|asar\.extractAll|asar\.createPackage/;

const NON_RUNTIME_TEST_PATH_RE = /(?:^|\/)(?:test|tests|__tests__)\/|\.(?:test|spec)\.[a-z0-9]+$/i;

const HOOK_META_KEYS = new Set(['$schema', 'version', 'description', 'enabled']);

function stripMarkdownCodeExamples(mdText) {
  // Strip fenced code blocks (```...``` or ~~~...~~~) and single-line inline code spans (`...`)
  // so documentation tables/examples do not falsely trip @[label](path) include checks.
  return mdText
    .replace(/^ {0,3}(`{3,}|~{3,})[^\r\n]*\r?\n[\s\S]*?^ {0,3}\1[ \t]*$/gm, '')
    .replace(/`[^`\r\n]+`/g, '');
}

function stripSourceComments(src, relPath) {
  if (/\.(?:py|sh|ps1)$/i.test(relPath)) {
    return src.replace(/^\s*#.*$/gm, '');
  }
  if (/\.(?:cmd|bat)$/i.test(relPath)) {
    return src.replace(/^\s*(?:rem\b|::).*$/gim, '');
  }
  let out = '';
  let inSingle = false;
  let inDouble = false;
  let inTemplate = false;
  let inLineComment = false;
  let inBlockComment = false;
  let escaped = false;

  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    const next = src[i + 1];

    if (inLineComment) {
      if (ch === '\n') {
        inLineComment = false;
        out += ch;
      }
      continue;
    }
    if (inBlockComment) {
      if (ch === '*' && next === '/') {
        inBlockComment = false;
        out += ' ';
        i++;
      } else if (ch === '\n') {
        out += '\n';
      }
      continue;
    }
    if (inSingle) {
      out += ch;
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === "'" || ch === '\n') inSingle = false;
      continue;
    }
    if (inDouble) {
      out += ch;
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"' || ch === '\n') inDouble = false;
      continue;
    }
    if (inTemplate) {
      out += ch;
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '`') inTemplate = false;
      continue;
    }

    if (ch === '/' && next === '/') {
      inLineComment = true;
      i++;
      continue;
    }
    if (ch === '/' && next === '*') {
      inBlockComment = true;
      i++;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      out += ch;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      out += ch;
      continue;
    }
    if (ch === '`') {
      inTemplate = true;
      out += ch;
      continue;
    }
    out += ch;
  }
  return out;
}

function checkRulesExfiltration(relPath, contentText) {
  // Match real `@[label](target)` includes outside fenced/inline code documentation examples
  const proseOnly = stripMarkdownCodeExamples(contentText);
  const atIncludeRe = /@\[[^\]]*\]\(([^)]+)\)/g;
  let match;
  while ((match = atIncludeRe.exec(proseOnly)) !== null) {
    const rawTarget = match[1].trim();
    if (!rawTarget || /^https?:\/\//i.test(rawTarget)) continue;
    if (
      /(?:^|[\\/])\.\.(?:[\\/]|$)/.test(rawTarget) ||
      rawTarget.startsWith('~/') ||
      rawTarget.startsWith('~\\') ||
      rawTarget.startsWith('/') ||
      rawTarget.startsWith('\\') ||
      /^[A-Za-z]:/.test(rawTarget) ||
      /^file:/i.test(rawTarget) ||
      /\$[A-Za-z_{]|%[A-Za-z_]+%/.test(rawTarget)
    ) {
      throw new Error(
        `ERR_RULES_PATH_EXFILTRATION: "${relPath}" references out-of-root path "${rawTarget}" via @[...](...)`,
      );
    }
  }
}

function parseSkillFrontmatterName(mdText) {
  const clean = mdText.replace(/^\uFEFF/, '');
  const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(clean);
  if (!m) return null;
  const nameMatch = /^\s*name\s*:\s*([^\r\n#]+)/m.exec(m[1]);
  if (!nameMatch) return null;
  return nameMatch[1].trim().replace(/^['"]|['"]$/g, '');
}

/**
 * Inspects files inside `<pluginRoot>` (`Map<string, Buffer>`) and produces
 * `{ capabilities, components }` or throws on hard-blocked exfiltration/smuggling.
 */
export function scanPluginCapabilities(pluginFilesMap, { pluginName = '' } = {}) {
  const badges = [];
  let totalRuleBytes = 0;
  let hasRules = false;
  let hasSidecarUi = false;
  let hasMcpStdio = false;
  let hasMcpRemote = false;
  let hasLifecycleHooks = false;
  let hasSkillsOrAgents = false;

  const mcpServers = [];
  const mcpRawKeys = [];
  const mcpRemoteDomains = new Set();
  const hookEvents = new Set();
  const hostEnhancementKinds = new Set();
  const claimedSkills = [];
  const claimedAgents = [];

  for (const [relPath, buf] of pluginFilesMap.entries()) {
    // 1. Rules scan (`rules/*.md`)
    if (/^rules\/[^/]+\.md$/i.test(relPath)) {
      hasRules = true;
      if (buf.length > MAX_RULE_FILE_BYTES) {
        throw new Error(
          `ERR_RULE_SIZE_EXCEEDED: "${relPath}" is ${buf.length} bytes (Antigravity ceiling is ${MAX_RULE_FILE_BYTES} bytes)`,
        );
      }
      totalRuleBytes += buf.length;
      const text = buf.toString('utf8');
      if (INVISIBLE_SMUGGLING_RE.test(text)) {
        throw new Error(
          `ERR_INVISIBLE_PROMPT_INJECTION: Disallowed Unicode Tag or bidi override characters in "${relPath}"`,
        );
      }
      checkRulesExfiltration(relPath, text);
    }

    // 2. Skills scan (`skills/<skill>/SKILL.md`)
    const skillMatch = /^skills\/([^/]+)\/SKILL\.md$/.exec(relPath);
    if (skillMatch) {
      hasSkillsOrAgents = true;
      const skillDir = skillMatch[1];
      const text = buf.toString('utf8');
      if (INVISIBLE_SMUGGLING_RE.test(text)) {
        throw new Error(
          `ERR_INVISIBLE_PROMPT_INJECTION: Disallowed Unicode Tag or bidi override characters in "${relPath}"`,
        );
      }
      const fmName = parseSkillFrontmatterName(text);
      claimedSkills.push({ dir: skillDir, frontmatterName: fmName || skillDir });
    }

    // 3. Agents scan (`agents/<agent>.md`)
    const agentMatch = /^agents\/([^/]+)\.md$/.exec(relPath);
    if (agentMatch) {
      hasSkillsOrAgents = true;
      const agentName = agentMatch[1];
      const text = buf.toString('utf8');
      if (INVISIBLE_SMUGGLING_RE.test(text)) {
        throw new Error(
          `ERR_INVISIBLE_PROMPT_INJECTION: Disallowed Unicode Tag or bidi override characters in "${relPath}"`,
        );
      }
      claimedAgents.push(agentName);
    }

    // 4. Sidecar UI (`sidecars/<id>/sidecar.json`)
    if (/^sidecars\/[^/]+\/sidecar\.json$/.test(relPath)) {
      const parsed = parseJsonc(buf.toString('utf8'));
      if (parsed && typeof parsed === 'object') {
        hasSidecarUi = true;
      }
    }

    // 5. MCP Config (`mcp_config.json`)
    if (relPath === 'mcp_config.json') {
      const parsed = parseJsonc(buf.toString('utf8'));
      const serversObj = parsed?.mcpServers && typeof parsed.mcpServers === 'object' ? parsed.mcpServers : {};
      for (const [serverKey, cfg] of Object.entries(serversObj)) {
        mcpRawKeys.push(serverKey);
        const namespaced = pluginName ? `${pluginName}_${serverKey}` : serverKey;
        mcpServers.push(namespaced);
        const remoteUrl = cfg?.serverUrl || cfg?.url || cfg?.httpUrl || '';
        if (typeof remoteUrl === 'string' && /^https?:\/\//i.test(remoteUrl)) {
          hasMcpRemote = true;
          try {
            const u = new URL(remoteUrl);
            mcpRemoteDomains.add(u.hostname.toLowerCase());
          } catch {
            throw new Error(`ERR_MCP_INVALID_URL: Invalid remote URL "${remoteUrl}" in mcp_config.json`);
          }
        }
        if (typeof cfg?.command === 'string' && cfg.command.trim()) {
          hasMcpStdio = true;
        }
      }
    }

    // 6. Lifecycle Hooks (`hooks.json` — supports Antigravity named hook groups, `{ hooks: {...} }`, & flat maps)
    if (relPath === 'hooks.json') {
      hasLifecycleHooks = true;
      const parsed = parseJsonc(buf.toString('utf8'));
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        for (const [topKey, topVal] of Object.entries(parsed)) {
          if (HOOK_META_KEYS.has(topKey)) continue;
          if (Array.isArray(topVal)) {
            hookEvents.add(topKey);
          } else if (topVal && typeof topVal === 'object') {
            if (topVal.enabled === false) continue;
            for (const [eventKey, eventVal] of Object.entries(topVal)) {
              if (HOOK_META_KEYS.has(eventKey)) continue;
              if (Array.isArray(eventVal)) {
                hookEvents.add(eventKey);
              }
            }
          }
        }
      }
    }

    // 7. Permissive Host-Enhancement Profiling (CDP & app.asar — strip comments & skip non-runtime test suites!)
    if (/\.(?:mjs|cjs|js|ts|py|ps1|sh|cmd|bat)$/i.test(relPath) && !NON_RUNTIME_TEST_PATH_RE.test(relPath)) {
      const code = stripSourceComments(buf.toString('utf8'), relPath);
      if (CDP_DETECTION_RE.test(code)) {
        hostEnhancementKinds.add('cdp');
      }
      if (ASAR_DETECTION_RE.test(code)) {
        hostEnhancementKinds.add('app-asar');
      }
    }
  }

  const rulesEstimatedTokens = hasRules ? Math.ceil(totalRuleBytes / 4) : 0;
  const hostEnhancementKind = [...hostEnhancementKinds].sort();

  const isPureDeclarative =
    hasSkillsOrAgents &&
    !hasRules &&
    !hasSidecarUi &&
    !hasMcpStdio &&
    !hasMcpRemote &&
    !hasLifecycleHooks &&
    hostEnhancementKind.length === 0;

  if (isPureDeclarative) badges.push('declarative-only');
  if (hasRules) badges.push('global-rules');
  if (hasSidecarUi) badges.push('sidecar-ui');
  if (hasMcpStdio) badges.push('mcp-stdio');
  if (hasMcpRemote) badges.push('mcp-remote');
  if (hasLifecycleHooks) badges.push('lifecycle-hooks');
  if (hostEnhancementKind.length > 0) badges.push('host-enhancement');

  const genericMcpViolations = mcpRawKeys.filter((k) => GENERIC_MCP_SERVER_NAMES.has(k.toLowerCase()));

  return {
    capabilities: {
      badges,
      rulesEstimatedTokens,
      mcpServers: mcpServers.sort(),
      mcpRemoteDomains: [...mcpRemoteDomains].sort(),
      hookEvents: [...hookEvents].sort(),
      hostEnhancementKind,
    },
    components: {
      claimedSkills,
      claimedAgents: claimedAgents.sort(),
      mcpRawKeys,
      genericMcpViolations,
    },
  };
}
