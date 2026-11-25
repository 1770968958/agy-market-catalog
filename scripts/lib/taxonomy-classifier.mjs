// Curated taxonomy overrides + deterministic multi-signal classifier v2 (`scripts/lib/taxonomy-classifier.mjs`).

import { ALLOWED_CATEGORIES } from './constants.mjs';

export const TAXONOMY_VERSION = 2;

export const CURATED_TAXONOMY_OVERRIDES = Object.freeze({
  'azwosile__agy-market': Object.freeze({
    categories: Object.freeze(['productivity', 'developer-tools']),
    tags: Object.freeze(['marketplace', 'sidebar', 'plugin-manager']),
  }),
  'azwosile__agy-wallpaper-prism': Object.freeze({
    categories: Object.freeze(['ui-themes']),
    tags: Object.freeze(['wallpaper', 'glass-skin', 'theme', 'sidebar']),
  }),
  'yunjuanyunshu114-byte__antigravity-observer': Object.freeze({
    categories: Object.freeze(['monitoring-quota', 'ui-themes']),
    tags: Object.freeze(['telemetry', 'quota', 'companion-widget', 'context']),
  }),
  'zou172866__agy-dart': Object.freeze({
    categories: Object.freeze(['context-cache', 'developer-tools']),
    tags: Object.freeze(['kv-cache', 'context-guard', 'latency', 'mcp']),
  }),
  'a16nights__antigravity-think-zh': Object.freeze({
    categories: Object.freeze(['agents-reasoning']),
    tags: Object.freeze(['thinking', 'zh-cn', 'reasoning', 'hooks']),
  }),
  'carlosduplar__agy-lite-research': Object.freeze({
    categories: Object.freeze(['context-cache', 'agents-reasoning']),
    tags: Object.freeze(['quota-saver', 'subagent', 'flash-lite', 'hooks']),
  }),
  'commit-or-die-studio__agy-git-graph': Object.freeze({
    categories: Object.freeze(['developer-tools']),
    tags: Object.freeze(['git', 'branch-graph', 'diff', 'sidebar']),
  }),
  'eatingdream-antigravity-plugins__chrome-stream-mcp': Object.freeze({
    categories: Object.freeze(['mcp-integrations']),
    tags: Object.freeze(['chrome', 'screencast', 'devtools', 'mcp']),
  }),
  'eatingdream-antigravity-plugins__context-radar-mcp': Object.freeze({
    categories: Object.freeze(['context-cache', 'monitoring-quota']),
    tags: Object.freeze(['context-radar', 'cache', 'compact', 'mcp']),
  }),
  'eatingdream-antigravity-plugins__mac-clamshell-mcp': Object.freeze({
    categories: Object.freeze(['mcp-integrations']),
    tags: Object.freeze(['macos', 'hardware', 'thermal', 'mcp']),
  }),
  'mskasal__sculpting-framework': Object.freeze({
    categories: Object.freeze(['skills-workflows']),
    tags: Object.freeze(['product-engineering', 'framework', 'skills']),
  }),
  'rimenine__antigravity-status-monitor': Object.freeze({
    categories: Object.freeze(['monitoring-quota']),
    tags: Object.freeze(['status-monitor', 'network-probe', 'token', 'sidebar']),
  }),
  'souma-sumire__antigravity-zh-cn': Object.freeze({
    categories: Object.freeze(['ui-themes']),
    tags: Object.freeze(['zh-cn', 'i18n', 'localization', 'sidebar']),
  }),
  'wllzhang__awesome-antigravity-tools': Object.freeze({
    categories: Object.freeze(['skills-workflows', 'productivity']),
    tags: Object.freeze(['advisor', 'directory', 'skills']),
  }),
  'xmt-cn__agy-ctx-ring': Object.freeze({
    categories: Object.freeze(['monitoring-quota']),
    tags: Object.freeze(['context-hud', 'token', 'ttft', 'sidebar']),
  }),
  'ycuwq__agy-ext-swarm': Object.freeze({
    categories: Object.freeze(['agents-reasoning']),
    tags: Object.freeze(['swarm', 'multi-agent', 'worktree', 'mcp']),
  }),
  'yuhuan-dev__antigravity-usage-monitor': Object.freeze({
    categories: Object.freeze(['monitoring-quota']),
    tags: Object.freeze(['usage-monitor', 'speed', 'quota', 'sidebar']),
  }),
});

const CATEGORY_PRIORITY = [...ALLOWED_CATEGORIES];
const CATEGORY_PRIORITY_INDEX = new Map(CATEGORY_PRIORITY.map((c, idx) => [c, idx]));

const IGNORED_TOPIC_TAGS = new Set([
  'antigravity',
  'antigravity-plugin',
  'antigravity-plugins',
  'google-antigravity',
  'google-antigravity-plugin',
  'agy',
  'agy-plugin',
  'agy-plugins',
  'plugin',
  'plugins',
  'experimental',
  'other',
]);

const GENERIC_SUBPATH_SLUGS = new Set([
  '',
  'plugin',
  'plugins',
  'plugin-meta',
  'plugin-src',
  'core',
  'antigravity',
  'antigravity-plugin',
  'agy',
  'agy-plugin',
  'claude-plugin',
  'copilot',
  'dsh',
  'src',
  'name',
  'ja',
  'ko',
  'zh-cn',
  'en',
]);

function stripGenericContainerWords(slug) {
  return String(slug || '')
    .replace(
      /\b(?:antigravity[-_]?plugin[-_]?directory|agent[-_]?plugin[-_]?marketplace|agent[-_]?registry[-_]?marketplace[-_]?workshop|open[-_]?secagent[-_]?marketplace|zen[-_]?computer[-_]?marketplace|google[-_]?antigravity[-_]?plugins|antigravity[-_]?plugins[-_]?hub|antigravity[-_]?plugins|antigravity[-_]?plugin|antigravity[-_]?skills|agent[-_]?skills|agent[-_]?plugins|claude[-_]?plugin)\b/gi,
      ' ',
    )
    .replace(/\s+/g, ' ')
    .trim();
}

export function extractPluginSlugFromId(normId) {
  const raw = String(normId || '').trim().toLowerCase();
  if (!raw) return '';
  const afterOwner = raw.includes('__') ? raw.slice(raw.indexOf('__') + 2) : raw;
  if (!afterOwner.includes('--')) {
    return stripGenericContainerWords(afterOwner);
  }
  const splitIdx = afterOwner.indexOf('--');
  const repoPart = afterOwner.slice(0, splitIdx);
  const subRaw = afterOwner.slice(splitIdx + 2);
  const cleanedSub = subRaw
    .replace(
      /^(?:agents-plugins-|community-plugins-|starter-marketplace-plugins-|starter-|plugins-|plugin-|templates-plugin-plugins-|templates-plugin-|templates-|examples-|skills-|person-|stacks-(?:db|domain|iac|lang|platform|tooling)-|adapters-|host_resources-|locales-)/,
      '',
    )
    .replace(/(?:-claude-plugin|-antigravity-plugin|-plugin)$/, '');
  if (GENERIC_SUBPATH_SLUGS.has(cleanedSub)) {
    return stripGenericContainerWords(repoPart);
  }
  return cleanedSub;
}

export function sanitizeDescriptionNoise(text) {
  return String(text || '')
    .replace(/\b(?:zero|0|no)[-_\s]?tokens?\b/gi, ' ')
    .replace(/(?:零(?:额外)?|不消耗|无需)\s*tokens?/gi, ' ')
    .replace(/\btoken[-_\s]?tax\b/gi, ' ')
    .replace(/\b(?:design|auth|oauth|session|access|refresh|api)[-_\s]?tokens?\b/gi, ' ')
    .replace(/内存令牌/g, ' ')
    .replace(/\bzero[-_\s]?telemetry\b/gi, ' ')
    .replace(/\bTODO\s*:/gi, ' ')
    .replace(/\binvestment\s+themes?\b/gi, ' ')
    .replace(/(?:实时|自动)?跟随(?:宿主|系统|antigravity)?\s*主题/gi, ' ')
    .replace(/安全审查白名单(?:内|中)?/g, ' ')
    .replace(/\b(?:command|safety|safe|review)\s+allowlist\b/gi, ' ')
    .replace(/\b(?:via|with|through)\s+(?:scoped\s+)?oauth(?:\s+(?:mcp|sign[-_\s]?in))?\b/gi, ' ')
    .replace(/\boauth2?\s+(?:or\s+app\s+password|sign[-_\s]?in|login|mcp)\b/gi, ' ')
    .replace(/\b(?:windows|wsl2?|macos|linux)(?:\s*(?:,|\/|&|and)\s*(?:windows|wsl2?|macos|linux))+\b/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

const SIGNAL_RULES = Object.freeze([
  // ── monitoring-quota ──────────────────────────────────────────────────────
  {
    category: 'monitoring-quota',
    weight: 7,
    tag: 'usage-monitor',
    re: /\b(?:usage[-_\s]?monitor|status[-_\s]?monitor|speed[-_\s]?monitor|quota[-_\s]?monitor|quota[-_\s]?meter|quota[-_\s]?dashboard|quota[-_\s]?cockpit|quota[-_\s]?pill|session[-_\s]?monitor|session[-_\s]?stats|session[-_\s]?report|session[-_\s]?inspector|context[-_\s]?monitor|context[-_\s]?viewer|context[-_\s]?meter|context[-_\s]?usage|context[-_\s]?hud|context[-_\s]?dashboard|context[-_\s]?insights|context[-_\s]?inspector|context[-_\s]?lens|context[-_\s]?doctor|desktop[-_\s]?context|token[-_\s]?meter|token[-_\s]?tracker|token[-_\s]?monitor|token[-_\s]?usage|chat[-_\s]?tokens|usage[-_\s]?ledger|usage[-_\s]?meter|model[-_\s]?usage|model[-_\s]?details|sub[-_\s]?meter|agy[-_\s]?lens|agy[-_\s]?pulse|antigravity[-_\s]?pulse|antigravity[-_\s]?dashboard|agy[-_\s]?usage|agy[-_\s]?capsule|agy[-_\s]?hud|agy[-_\s]?statusline|status[-_\s]?capsule|floating[-_\s]?hud|balance[-_\s]?widget|monowatch|magpie[-_\s]?usage|check[-_\s]?usage|usage[-_\s]?dashboard)\b|用量监控|状态监控|额度监控|額度監控|额度面板|额度速览|模型用量|会话监控|会话统计|上下文占用|上下文看板|上下文监控|上下文洞察|额度显示|配额监控|配额与上下文|余额监控|多来源用量|吞吐监控/i,
  },
  {
    category: 'monitoring-quota',
    weight: 6,
    tag: 'telemetry',
    re: /\b(?:telemetry|observer|cockpit|ttft|tok\/s|token\/s|\btps\b|ctx[-_\s]?ring|statusline|status[-_\s]?line|wakatime|langfuse|observability|datadog|sentry|chronova|brbrdb)\b|观察台|观察窗|上下文胶囊|首字延迟|首字延遲|生成速度|生成速率|吞吐率|吞吐量/i,
  },
  {
    category: 'monitoring-quota',
    weight: 5,
    tag: 'quota',
    re: /\b(?:quota(?!\s*saver)|rate[-_\s]?limit|network[-_\s]?probe|5[-_\s]?hour\s+(?:&|and)\s+weekly|usage[-_\s]?limits?|context[-_\s]?window\s+(?:usage|fill|gauge|occupancy|breakdown|estimate)|token[-_\s]?(?:breakdown|speed|consumption|workload|weather))\b|可用额度|可用額度|模型额度|模型配额|历史用量|歷史用量|消耗速度|耗尽预估|5h.*周(?:共享)?额度|上下文窗口(?:占用|水位)/i,
  },
  {
    category: 'monitoring-quota',
    weight: 3,
    tag: 'monitor',
    re: /\b(?:monitor|metrics|hud|capsule|donut|probe|heartbeat[-_\s]?tracking|session[-_\s]?analytics)\b|监控|遥测|用量|探针|仪表盘/i,
  },

  // ── context-cache ─────────────────────────────────────────────────────────
  {
    category: 'context-cache',
    weight: 7,
    tag: 'kv-cache',
    re: /\b(?:kv[-_\s]?cache|cold[-_\s]?cache|cache[-_\s]?guard|cache[-_\s]?warm|cache[-_\s]?radar|cache[-_\s]?optimizer|context[-_\s]?auto[-_\s]?split|context[-_\s]?anchor|context[-_\s]?mode|context[-_\s]?guard|context[-_\s]?radar|context[-_\s]?file[-_\s]?splitter|agy[-_\s]?headroom|agy[-_\s]?hyper|agy[-_\s]?fast|agy[-_\s]?tune|antigravity[-_\s]?booster|agy[-_\s]?booster|token[-_\s]?guard|token[-_\s]?optimizer|token[-_\s]?compression|quota[-_\s]?saver|prefix[-_\s]?safe|slice[-_\s]?distillation|anti[-_\s]?context[-_\s]?bloat|mdp[-_\s]?forgetting|fast[-_\s]?io)\b|缓存保护|缓存加速|上下文守卫|上下文压缩|上下文自动分流|上下文保护|省额度|低延迟加速|防膨胀|子对话自动多开/i,
  },
  {
    category: 'context-cache',
    weight: 5,
    tag: 'context-guard',
    re: /\b(?:prompt[-_\s]?cache\s+(?:hit|efficiency|savings|diagnostics|optimizer)|cache[-_\s]?hit|token[-_\s]?sav(?:er|ing|ings)|token[-_\s]?optimi[zs]|context[-_\s]?optimi[zs]|context[-_\s]?window\s+(?:protection|optimi[zs]|compress)|context[-_\s]?compress|observation[-_\s]?pruning|\brtk\b|latency[-_\s]?reduction|acceleration[-_\s]?engine)\b|缓存命中|前缀缓存|上下文裁剪/i,
  },
  {
    category: 'context-cache',
    weight: 3,
    tag: 'compact',
    re: /\b(?:compact|keepalive|caching|batching|accelerator)\b|缓存/i,
  },

  // ── ui-themes ─────────────────────────────────────────────────────────────
  {
    category: 'ui-themes',
    weight: 7,
    tag: 'wallpaper',
    re: /\b(?:wallpaper|glass[-_\s]?skin|frosted[-_\s]?glass|liquid[-_\s]?glass|glassmorphism|theme[-_\s]?control|theme[-_\s]?examples|obsidian[-_\s]?prism|antigravity[-_\s]?skin|antigravity[-_\s]?background|claude[-_\s]?studio|claude[-_\s]?style|zen[-_\s]?one[-_\s]?tone|ui[-_\s]?tweaks|latex[-_\s]?enhancer|katex)\b|壁纸|毛玻璃|液态玻璃|桌面主题|配色方案|皮肤|界面美化|界面调校|外观增强|界面美学/i,
  },
  {
    category: 'ui-themes',
    weight: 7,
    tag: 'i18n',
    re: /\b(?:zh[-_\s]?cn[-_\s]?(?:ui|pack|localiz\w*|lang\w*)|chinese[-_\s]?ui|antigravity[-_\s]?zh|antigravity[-_\s]?ru|antigravity[-_\s]?jp|arabic[-_\s]?rtl|rtl[-_\s]?fix|bidi|language[-_\s]?packs?|ui[-_\s]?localiz\w*|localizer)\b|汉化|语言包|简体中文\s*ui|简体中文界面|界面本地化|词库|日本語化|русификация/i,
  },
  {
    category: 'ui-themes',
    weight: 7,
    tag: 'companion-widget',
    re: /\b(?:companion[-_\s]?widget|(?:animated\s+)?desktop[-_\s]?companion|desktop[-_\s]?pet|antigravity[-_\s]?pet|gemini[-_\s]?pet|dsh[-_\s]?pet|\bpets\b|agy[-_\s]?piggy|piggy|mascot|antigravity[-_\s]?bee|pixel[-_\s]?mascot)\b|桌面宠物|桌宠|猫娘挂件|桌面挂件|挂件/i,
  },
  {
    category: 'ui-themes',
    weight: 5,
    tag: 'theme',
    re: /\b(?:color[-_\s]?scheme|dark[-_\s]?mode|custom[-_\s]?css|animated[-_\s]?backdrops?|boot[-_\s]?animation|appearance[-_\s]?menu|ui[-_\s]?themes?|desktop[-_\s]?themes?|windows[-_\s]?themes?|crystal[-_\s]?themes?|\bi18n\b|\bl10n\b|localization)\b|深浅主题|中文界面/i,
  },

  // ── agents-reasoning ──────────────────────────────────────────────────────
  {
    category: 'agents-reasoning',
    weight: 7,
    tag: 'swarm',
    re: /\b(?:swarm|multi[-_\s]?agent|multi[-_\s]?cli|multi[-_\s]?model|dual[-_\s]?brain|agent[-_\s]?orchestrat\w*|agent[-_\s]?bridge|codex[-_\s]?bridge|codex[-_\s]?orchestrator|codex[-_\s]?subagent|codex[-_\s]?worker|codex[-_\s]?cli|let[-_\s]?agy[-_\s]?use[-_\s]?codex|codex[-_\s]?dynamic[-_\s]?bridge|agy[-_\s]?handoff|model[-_\s]?router|adaptive[-_\s]?router|chief[-_\s]?router|super[-_\s]?agent|google[-_\s]?jules|\bjules\b|cospan|omnilane|fusion[-_\s]?panel|mumo|mitosis|skizzo|tenchi|ghostty[-_\s]?bus|provider[-_\s]?routing|freellm[-_\s]?manager|gemini[-_\s]?elements|antigravity[-_\s]?elements|use[-_\s]?hydrogen)\b|多代理|多智能体|蜂群|协同对讲室|自动路由|双脑|模型选择器|元素周期表/i,
  },
  {
    category: 'agents-reasoning',
    weight: 7,
    tag: 'reasoning',
    re: /\b(?:think[-_\s]?zh|think[-_\s]?hard|think[-_\s]?tank|deep[-_\s]?reasoning|brain[-_\s]?live|thinking[-_\s]?visualizer|thought[-_\s]?translator|agent[-_\s]?tracer|chronobranch|custom[-_\s]?persona|persona[-_\s]?hub|persona[-_\s]?skills|xiaoke[-_\s]?persona|hajimi[-_\s]?persona|hakimi[-_\s]?hiss|gravitas|math[-_\s]?olympiad|math[-_\s]?proof|attention[-_\s]?guard|hyper[-_\s]?cortex|agi[-_\s]?research|egm[-_\s]?conductor)\b|思考语言|内部思考|推理控制|思维链|中文思考|思考过程|人设|拍档人设|哈基米/i,
  },
  {
    category: 'agents-reasoning',
    weight: 5,
    tag: 'subagent',
    re: /\b(?:sub[-_\s]?agents?|flash[-_\s]?lite|agent[-_\s]?routing|model[-_\s]?routing|chain[-_\s]?of[-_\s]?thought|reasoning[-_\s]?effort|thinking[-_\s]?blocks?|orchestrator|agent[-_\s]?team|agent[-_\s]?fleet|agent[-_\s]?to[-_\s]?agent|openai[-_\s]?codex|codex\s+cli|deliberation|adversarial|generator[-_\s]?critic|reflexion|persona)\b|子代理|对决|对抗审查|编排/i,
  },

  // ── creative-media ────────────────────────────────────────────────────────
  {
    category: 'creative-media',
    weight: 7,
    tag: 'media',
    re: /\b(?:blender|unreal[-_\s]?engine|unreal[-_\s]?studio|openscad|meshy|tripo|snaprender|capcut|kling[-_\s]?ai|phantra|spritecook|autopic|soundiiz|affinity[-_\s]?by[-_\s]?canva|figma|figcraft|canva|kokoro|text[-_\s]?to[-_\s]?speech|\btts\b|voice[-_\s]?reader|antigravity[-_\s]?voice|vocalis|narrator|r2d2[-_\s]?sounds|agy[-_\s]?meme|meme[-_\s]?plugin|meme[-_\s]?stickers?|contenty[-_\s]?studio|youtube[-_\s]?studio|roblox[-_\s]?game|minimo[-_\s]?games|thicken|monozukuri|janction[-_\s]?render|mint[-_\s]?antigravity|revayat[-_\s]?comic|revayat[-_\s]?subtitle|lazydiagram|md[-_\s]?viz|design[-_\s]?system|laws[-_\s]?of[-_\s]?ux|impeccable[-_\s]?design|frontend[-_\s]?design|frontend[-_\s]?taste|stitch[-_\s]?plugin|google[-_\s]?stitch|kombai|vaadin[-_\s]?flow|unslopovich|unsloop|a[-_\s]?mdui|no[-_\s]?slop)\b|表情包|斗图|音视频|视频剪辑|图像生成|多媒体|创意设计|3d\s*模型|3d\s*建模|3dプリント|语音朗读|插画/i,
  },
  {
    category: 'creative-media',
    weight: 5,
    tag: 'design',
    re: /\b(?:ffmpeg|video[-_\s]?edit|image[-_\s]?gen|text[-_\s]?to[-_\s]?3d|image[-_\s]?to[-_\s]?3d|3d[-_\s]?models?|3d[-_\s]?print|parametric[-_\s]?cad|game[-_\s]?art|pixel[-_\s]?art|sprites?|tilesets?|storyboards?|subtitles?|manga|manhwa|comics?|illustration|svg[-_\s]?editor|podcast|playlists?|music[-_\s]?transfer|ui\/ux[-_\s]?design|ux[-_\s]?design|prototyping|carousels?|thumbnails?|voice[-_\s]?to[-_\s]?voice|sound[-_\s]?effects?|reads?\s+out\s+loud|video[-_\s]?directing)\b|动画|剪辑|配音|视觉设计/i,
  },

  // ── writing-knowledge ─────────────────────────────────────────────────────
  {
    category: 'writing-knowledge',
    weight: 7,
    tag: 'knowledge',
    re: /\b(?:lanxi[-_\s]?memory|soul[-_\s]?md|archivist|obsidian|notion|scholarocr|contextstream|teach[-_\s]?skill|mnemon|nowledge[-_\s]?mem|agentic[-_\s]?vault|alexein|memorix|everos|memlin|hindsight|openviking|memory[-_\s]?bank|conductor[-_\s]?memory|cognitive[-_\s]?persistence|local[-_\s]?memory|agent[-_\s]?learning|evolver|coalhearth|knowledge[-_\s]?compiler|affine|rivul|research[-_\s]?literature|epigraphy|humanizer|avoid[-_\s]?ai[-_\s]?writing|ai[-_\s]?writing[-_\s]?patterns?|ai[-_\s]?isms?|less[-_\s]?ai[-_\s]?tone|deslop[-_\s]?copyeditor|copyeditor|well[-_\s]?document|aimake|jotter|meeting[-_\s]?notes|anchor[-_\s]?wheel|aletheia[-_\s]?research|antigravity[-_\s]?tutor|cs[-_\s]?tutor|pick[-_\s]?me|lolcv|wordpress|wp[-_\s]?publisher|writing[-_\s]?and[-_\s]?learning|make[-_\s]?laprak|scientific[-_\s]?writing|promptbase|redpine|factdock|primary[-_\s]?source|current[-_\s]?information[-_\s]?research|chinese[-_\s]?translation|chinese[-_\s]?community[-_\s]?pack|help[-_\s]?agent|agy[-_\s]?help)\b|蓝汐|潮汐认知图谱|苍蓝魂匣|长期记忆|持久化记忆|知识库|知识图谱|认知图谱|记忆管理|去\s*ai\s*味|中文写作|润色|学术论文|文献|笔记|教学|简历|中文翻譯/i,
  },
  {
    category: 'writing-knowledge',
    weight: 5,
    tag: 'writing',
    re: /\b(?:persistent[-_\s]?memory|project[-_\s]?memory|cross[-_\s]?session.*memory|cross[-_\s]?agent.*memory|cognitive[-_\s]?memory|layered[-_\s]?memory|session[-_\s]?handoff|handover[-_\s]?journal|knowledge[-_\s]?base|knowledge[-_\s]?graph|wiki|zettelkasten|markdown[-_\s]?notes|note[-_\s]?taking|quick[-_\s]?note|academic[-_\s]?writing|scholarly|literature[-_\s]?review|\bocr\b|novel|blog|copywriting|resumes?|cover[-_\s]?letters?|bibtex|citations?|proposal[-_\s]?engine|technical[-_\s]?annexes|engineering[-_\s]?docs|document[-_\s]?co[-_\s]?authoring|documentation[-_\s]?skill)\b|写作|文稿|记忆|术语对照/i,
  },

  // ── security ──────────────────────────────────────────────────────────────
  {
    category: 'security',
    weight: 7,
    tag: 'security',
    re: /\b(?:guardrails?|agent[-_\s]?guard|pi[-_\s]?guardrails|workspace[-_\s]?guard|blindfold|verisource|tokensafe|orca[-_\s]?security|snyk|security[-_\s]?guidance|security[-_\s]?audit|security[-_\s]?agent|antigravity[-_\s]?security|claude[-_\s]?security|eigenscope|ztds|systemores|crowdstrike|falcon|ssojet|oauth[-_\s]?scope[-_\s]?minimizer|auto[-_\s]?permissions|alignment[-_\s]?mode|reverse[-_\s]?engineer\w*|reverselab|android[-_\s]?reverse|pc[-_\s]?reverse|ghidra|redteam|red[-_\s]?team|hardening|chaos[-_\s]?audit|verifyum|luaward|anti[-_\s]?hallucination|fact[-_\s]?checking)\b|安全审计|安全审查|防火墙|逆向工程|静态反编译|红队|蓝队|漏洞扫描|权限授权|安全护栏|零信任|隐私脱敏/i,
  },
  {
    category: 'security',
    weight: 5,
    tag: 'audit',
    re: /\b(?:security|secret[-_\s]?scan|vulnerability|\bcve\b|pentest|sast|owasp|rbac|auth0|compliance|firewall|malware|pii[-_\s]?scrub|zero[-_\s]?trust|sanitization|decompilation|frida|binary[-_\s]?exploit\w*|anti[-_\s]?hook|openssf|supply[-_\s]?chain|permission[-_\s]?classifier|credential[-_\s]?masking|enterprise[-_\s]?sso|key[-_\s]?vault|cors[-_\s]?headers|csrf|denycode)\b|合规|密钥扫描|秘钥扫描|防破解|加固|脱壳|漏洞/i,
  },

  // ── cloud-devops ──────────────────────────────────────────────────────────
  {
    category: 'cloud-devops',
    weight: 7,
    tag: 'devops',
    re: /\b(?:docker|kubernetes|\bk8s\b|helm|terraform|opentofu|ansible|better[-_\s]?stack|betterstack|cloudflare|netlify|vercel|shipstatic|taghost|firebase|supabase|azure[-_\s]?bicep|azure[-_\s]?container|azure[-_\s]?blob|azure[-_\s]?postgresql|azure[-_\s]?cache|azure[-_\s]?key[-_\s]?vault|gcp[-_\s]?finops|finops|github[-_\s]?actions|gitlab|ci\/cd|cicd|devops|\bsre\b|infrastructure[-_\s]?as[-_\s]?code|beamfar|termalin|pluglayer|pathtoship|sprites|aws[-_\s]?plugin|engsys[-_\s]?(?:aws|azure|gcp|cloudflare|terraform|bicep|cdk)|linux[-_\s]?server|proxy[-_\s]?helper|namefi|xovris|website[-_\s]?artifacts)\b|云原生|容器|部署|基础设施|运维|服务器监控|代理助手/i,
  },
  {
    category: 'cloud-devops',
    weight: 5,
    tag: 'cloud',
    re: /\b(?:deploy|deployment|hosting|\baws\b|\bgcp\b|\bazure\b|nginx|dockerfile|buildkit|containerization|prometheus|grafana|incident[-_\s]?triage|edge[-_\s]?cloud|serverless|cloud[-_\s]?billing|mcp[-_\s]?tunnels|cloud[-_\s]?clusters?|cloud[-_\s]?vms?)\b/i,
  },

  // ── data-science ──────────────────────────────────────────────────────────
  {
    category: 'data-science',
    weight: 7,
    tag: 'data-science',
    re: /\b(?:adspirer|analytics|ibkr|interactive[-_\s]?brokers|bhm[-_\s]?markets|stockmarketagent|zilliz|milvus|braintrust|bigquery|databricks|parquet|arrow[-_\s]?peek|masthead|quantum[-_\s]?metric|gitlytics|danqing|dnaobs|genomics|bio[-_\s]?structural|scientific[-_\s]?computing|scientific[-_\s]?ideation|sci[-_\s]?fast[-_\s]?io|where[-_\s]?my[-_\s]?hug|hugging[-_\s]?face|\bkame\b|llm[-_\s]?review[-_\s]?triage|datagent|tiller[-_\s]?finance|layerz|finance[-_\s]?workflows|semrush|whyiq|rankspot|rank[-_\s]?in[-_\s]?maps|kissmypost|signalseek|plushcap|multitool[-_\s]?ads|criora|nutrifit|manufacturing)\b|数据分析|科学计算|机器学习|科研|数据集|量化|金融|基因组|向量数据库|丹青/i,
  },
  {
    category: 'data-science',
    weight: 5,
    tag: 'analytics',
    re: /\b(?:jupyter|notebook|pandas|numpy|pytorch|tensorflow|dataset|data[-_\s]?science|machine[-_\s]?learning|sql[-_\s]?analytics|vector[-_\s]?search|bioinformatics|scientific|equity[-_\s]?research|financial[-_\s]?models?|portfolio|marketing[-_\s]?analytics|traffic[-_\s]?analytics|\bseo\b|\bcro\b|audience[-_\s]?research|llm[-_\s]?evaluation|alphafold|nmr|climate[-_\s]?and[-_\s]?disaster|biomarker|ab[-_\s]?bench|sci[-_\s]?eda)\b/i,
  },

  // ── automation ────────────────────────────────────────────────────────────
  {
    category: 'automation',
    weight: 7,
    tag: 'automation',
    re: /\b(?:cron|scheduler|scheduled|notifier|notify|turbo[-_\s]?notify|wakeshift|pushary|agentbus|simpleterm|antigravity[-_\s]?relay|computer[-_\s]?use|cua[-_\s]?driver|cua[-_\s]?computer[-_\s]?use|win[-_\s]?pilot|win[-_\s]?chauffeur|win[-_\s]?janitor|weavetab|antigravity[-_\s]?flow|google[-_\s]?flow|n8n|zapier|webhook|ralph[-_\s]?loop|hookify|prompt[-_\s]?queue|bullmq|celery|feishu[-_\s]?router|wecom|telegram[-_\s]?nexus|agy[-_\s]?hq|execution[-_\s]?guard|anti[-_\s]?freeze|zyntaflow|agy[-_\s]?cmd|antigravity[-_\s]?aistudio)\b|定时任务|守护任务|定时巡检|自动化触发|后台守卫|任务通知|远程推送|桌面自动化|自动续跑|防停机|消息推送/i,
  },
  {
    category: 'automation',
    weight: 5,
    tag: 'daemon',
    re: /\b(?:daemon|watchdog|polling|background[-_\s]?job|desktop[-_\s]?automation|gui[-_\s]?automation|browser[-_\s]?automation|ui[-_\s]?automation|workflow[-_\s]?automation|remote[-_\s]?push|task[-_\s]?queue|queued[-_\s]?tasks?|run[-_\s]?queued|after\s+<task>)\b|自动化|看门狗|守护进程/i,
  },

  // ── developer-tools ───────────────────────────────────────────────────────
  {
    category: 'developer-tools',
    weight: 7,
    tag: 'git',
    re: /\b(?:git[-_\s]?graph|branch[-_\s]?graph|commit[-_\s]?diff|git[-_\s]?diff|source[-_\s]?control|git[-_\s]?github|git[-_\s]?workflow|git[-_\s]?for[-_\s]?me|modern[-_\s]?git|commit[-_\s]?commands|github[-_\s]?worker|time[-_\s]?machine|git[-_\s]?shadow|conventional[-_\s]?commits)\b|分支图|版本控制|源代码管理/i,
  },
  {
    category: 'developer-tools',
    weight: 7,
    tag: 'devtools',
    re: /\b(?:postman|api[-_\s]?tester|biome|unslop[-_\s]?backend|quality[-_\s]?gate|quality[-_\s]?pack|coalmine|code[-_\s]?graph|code[-_\s]?review|pr[-_\s]?review|code[-_\s]?simplifier|code[-_\s]?modernization|code[-_\s]?inspector|serena|causoryn|playwright|endform|leapwork|qa[-_\s]?skill|wiremock|grafana[-_\s]?k6|modern[-_\s]?k6|eslint|language[-_\s]?server|\blsp\b|pyright|gopls|rust[-_\s]?analyzer|clangd|jdtls|intelephense|roslyn|sourcekit|wsl[-_\s]?terminal|sqlite[-_\s]?inspector|adb[-_\s]?toolkit|nestjs|nextjs|next\.js|react[-_\s]?19|\bnuxt\b|django|fastapi|fast[-_\s]?api|spring[-_\s]?boot|laravel|prisma|postgresql|node[-_\s]?pg|nodejs|python[-_\s]?3|python[-_\s]?artisan|rust[-_\s]?systems|dotnet|pnpm|py[-_\s]?uv|mongodb|sql[-_\s]?server|formal[-_\s]?verify|tla\+|lean[-_\s]?4|agent[-_\s]?sdk|plugin[-_\s]?porter|plugin[-_\s]?dev|plugin[-_\s]?factory|plugin[-_\s]?architect|meta[-_\s]?plugin|arma3[-_\s]?sqf|docusign|servicenow|suqo|chunked[-_\s]?write|junction[-_\s]?skill[-_\s]?fix|swift[-_\s]?macos|mobile[-_\s]?native|kotlin[-_\s]?compose|schemasketch|webapp6|saas[-_\s]?defaults|repo[-_\s]?architect|repo[-_\s]?tools|codex[-_\s]?worklog|fabric[-_\s]?code[-_\s]?mode|technical[-_\s]?delivery|pilah|cycle)\b|代码审查|代码图谱|质量门禁|wsl\s*终端|接口调试/i,
  },
  {
    category: 'developer-tools',
    weight: 5,
    tag: 'code',
    re: /\b(?:\bgit\b|worktree|github|pull[-_\s]?requests?|debugger|debug|linter|lint|prettier|\bast\b|refactor\w*|unit[-_\s]?test|\btdd\b|sqlite|fts5|ripgrep|tree[-_\s]?sitter|end[-_\s]?to[-_\s]?end[-_\s]?test|schema[-_\s]?design|migrations?|microservices?|compiler|\bsdk\b|idiomatic|package[-_\s]?management|lockfile|code[-_\s]?quality|rest[-_\s]?api)\b|代码检索|调试|重构|测试工具|构建/i,
  },

  // ── productivity ──────────────────────────────────────────────────────────
  {
    category: 'productivity',
    weight: 7,
    tag: 'marketplace',
    re: /\b(?:marketplace|plugin[-_\s]?manager|plugin[-_\s]?market|plugin[-_\s]?installer|plugin[-_\s]?switcher|skills[-_\s]?manager|antigravity[-_\s]?workshop|awesome[-_\s]?list|plugin[-_\s]?directory|tools?[-_\s]?directory|account[-_\s]?switcher|account[-_\s]?manager|agy[-_\s]?profiles)\b|插件市场|插件管理|插件安装|插件开关|创意工坊|账号切换|工具目录/i,
  },
  {
    category: 'productivity',
    weight: 7,
    tag: 'productivity',
    re: /\b(?:file[-_\s]?tree|file[-_\s]?explorer|better[-_\s]?sidebar|sidecar[-_\s]?studio|lite[-_\s]?editor|finder[-_\s]?reveal|doc[-_\s]?preview|doc[-_\s]?viewer|document[-_\s]?preview|agy[-_\s]?preview|image[-_\s]?preview|quick[-_\s]?peek|office[-_\s]?documents|docx[-_\s]?delivery|makespdf|clipboard[-_\s]?file[-_\s]?paste|link[-_\s]?menu|conversation[-_\s]?timeline|sessionlist|session[-_\s]?vault|task[-_\s]?progress|task[-_\s]?monitor|project[-_\s]?radar|progress[-_\s]?updates|agybar|work[-_\s]?plan|statedock|\bhoja\b|any\.?do|asana|linear|monday\.com|\bhive\b|gmail|zoho[-_\s]?books|zoho[-_\s]?desk|ai[-_\s]?executive|todo[-_\s]?for[-_\s]?ai|google[-_\s]?workspace|google[-_\s]?translate|translator|snippets|tab[-_\s]?suggest|next[-_\s]?step|suggest[-_\s]?next[-_\s]?steps|project[-_\s]?artifact|receipts|human[-_\s]?governor|sales[-_\s]?command|supersei[-_\s]?crm|tokenrip|ether|upfirst|tareno|hrizn|panther[-_\s]?hook|consolex|alynki)\b|文件树|文件浏览|文件工作台|访达|文档预览|剪贴板|任务进度|进度播报|对话时间线|模板库|下一步补全|侧边栏工作台/i,
  },
  {
    category: 'productivity',
    weight: 5,
    tag: 'workspace',
    re: /\b(?:preview|docx|pptx|xlsx|kanban|task[-_\s]?manager|task[-_\s]?track\w*|calendar|bookmarks?|launcher|quick[-_\s]?switch|issue[-_\s]?track\w*|project[-_\s]?management|\bcrm\b|invoicing|emails?|playground)\b|效率增强|工作台助手|快捷操作/i,
  },

  // ── mcp-integrations ──────────────────────────────────────────────────────
  {
    category: 'mcp-integrations',
    weight: 7,
    tag: 'chrome',
    re: /\b(?:chrome[-_\s]?stream|chrome[-_\s]?browser[-_\s]?mcp|workbench[-_\s]?browser|in[-_\s]?built[-_\s]?browser|antigravity[-_\s]?browser|devtools[-_\s]?relay|screencast)\b|浏览器控制|侧边栏里的真浏览器/i,
  },
  {
    category: 'mcp-integrations',
    weight: 7,
    tag: 'mcp',
    re: /\b(?:mcp[-_\s]?manager|mcp[-_\s]?server[-_\s]?dev|mac[-_\s]?clamshell|stupidmirror|parallels[-_\s]?desktop|remote[-_\s]?device|cwc[-_\s]?makers|cardputer|\bexa\b|firecrawl|bright[-_\s]?data|decodo|mrscraper|parallel[-_\s]?web|seltz|octen|toolsnap|pomerado|context7|apify|discord|telegram|whatsapp|wabot|wapliss|imessage|fakechat|agentchat|agentschat|\bando\b|aisense|directcase|everlaw|legal[-_\s]?data[-_\s]?hunter|legalquants|leksio|midpage|passim|trellis[-_\s]?law|imzala|iprwise|opencityrecord|stringtheory|global[-_\s]?source|elevenflo|motyv|lawve|glucobeat|hoy[-_\s]?planes|teas[-_\s]?co[-_\s]?uk|compteam|sic[-_\s]?civil|mentionagent|mentionskill|billdog|agent[-_\s]?reach|phinite)\b/i,
  },
  {
    category: 'mcp-integrations',
    weight: 4,
    tag: 'connector',
    re: /\b(?:clamshell|thermal[-_\s]?guard|hardware|firmware|web[-_\s]?scraping|web[-_\s]?search|legal[-_\s]?research|case[-_\s]?law|legislation|slack|mcp[-_\s]?server|mcp[-_\s]?app)\b|硬件|温控|连接器|第三方服务/i,
  },

  // ── skills-workflows ──────────────────────────────────────────────────────
  {
    category: 'skills-workflows',
    weight: 7,
    tag: 'framework',
    re: /\b(?:operating[-_\s]?framework|sculpting[-_\s]?framework|product[-_\s]?engineer|vertical[-_\s]?slices|superpowers|pstack|astack|agystack|hiway[-_\s]?kit|tea[-_\s]?stack|lift[-_\s]?sdlc|specdd|dev[-_\s]?process[-_\s]?kit|contract[-_\s]?first|armature[-_\s]?cdd|godmode|god[-_\s]?prompt|prompt[-_\s]?forge|prompt[-_\s]?engineering|feature[-_\s]?dev|skill[-_\s]?creator|skill[-_\s]?governance|skilltally|web2skill|pattern[-_\s]?harvester|harness|rsi[-_\s]?harness|oh[-_\s]?my[-_\s]?antigravity|frontier[-_\s]?engineer|engsys|dev[-_\s]?team[-_\s]?skills|dev[-_\s]?agents|agentforge|agentry|gurita|neckbeard|blackhole|champion[-_\s]?kit|explanatory[-_\s]?output|learning[-_\s]?output|proactive[-_\s]?mentorship|engineering[-_\s]?sobriety|antigravity[-_\s]?setup|claude[-_\s]?code[-_\s]?setup|setup[-_\s]?audit|agents[-_\s]?md[-_\s]?improver|claude[-_\s]?md[-_\s]?management|rules[-_\s]?management|antigravity[-_\s]?customizer|antigravity[-_\s]?essentials|antigravity[-_\s]?plus|karpathy[-_\s]?skills|mattpocock|fullstack[-_\s]?hq|universal[-_\s]?agent[-_\s]?skills|starter[-_\s]?plugin|example[-_\s]?plugin|sample[-_\s]?agent[-_\s]?plugin|antigravityrules|idea[-_\s]?to[-_\s]?reality|business[-_\s]?blueprint|startupantigravity|airprompter|gravity[-_\s]?boots|u[-_\s]?team|engineering[-_\s]?protocols|conventions[-_\s]?plugin|prompt[-_\s]?patcher|dyy[-_\s]?plugin|gitranks|idd[-_\s]?skills|multiplayer|forge[-_\s]?antigravity|mapek|gta[-_\s]?5)\b|工程方法|方法论|技能包|技能集|工作流框架|行为与语言规范/i,
  },
  {
    category: 'skills-workflows',
    weight: 4,
    tag: 'skills',
    re: /\b(?:framework|methodology|playbook|cookbook|skill[-_\s]?pack|skills[-_\s]?bundle|skills|workflows?|advisor|best[-_\s]?practices|\bsop\b|spec[-_\s]?driven|\bsdlc\b)\b|工作流|最佳实践/i,
  },
]);

function normalizeCategories(list) {
  const out = [];
  const seen = new Set();
  for (const raw of Array.isArray(list) ? list : []) {
    if (typeof raw !== 'string') continue;
    const clean = raw.trim();
    if (!clean || !ALLOWED_CATEGORIES.has(clean) || seen.has(clean)) continue;
    seen.add(clean);
    out.push(clean);
  }
  return out;
}

function normalizeTag(raw) {
  if (typeof raw !== 'string') return '';
  return raw
    .trim()
    .toLowerCase()
    .replace(/[\s_]+/g, '-')
    .replace(/[^a-z0-9\u4e00-\u9fff-]/g, '')
    .replace(/-{2,}/g, '-')
    .replace(/^-+|-+$/g, '');
}

function normalizeTags(list, { stripExperimental = true, maxTags = 8 } = {}) {
  const out = [];
  const seen = new Set();
  for (const raw of Array.isArray(list) ? list : []) {
    const clean = normalizeTag(raw);
    if (!clean || seen.has(clean)) continue;
    if (stripExperimental && clean === 'experimental') continue;
    seen.add(clean);
    out.push(clean);
    if (out.length >= maxTags) break;
  }
  return out;
}

function flattenDescription(description) {
  if (typeof description === 'string') return description;
  if (description && typeof description === 'object') {
    return `${description.zh || ''} ${description.en || ''}`.trim();
  }
  return '';
}

function deriveBadgeTags(badges) {
  const tags = [];
  if (badges.includes('sidecar-ui')) tags.push('sidebar');
  if (badges.includes('mcp-stdio') || badges.includes('mcp-remote')) tags.push('mcp');
  if (badges.includes('lifecycle-hooks')) tags.push('hooks');
  if (badges.includes('declarative-only')) tags.push('skills');
  return tags;
}

function deriveTopicTags(topics) {
  const tags = [];
  for (const raw of Array.isArray(topics) ? topics : []) {
    const clean = normalizeTag(raw);
    if (!clean || IGNORED_TOPIC_TAGS.has(clean) || clean.length < 2 || clean.length > 32) continue;
    tags.push(clean);
  }
  return tags;
}

const VERSION_STUB_DESC_RE = /^[a-z0-9._\s-]+\s+v?\d+\.\d+(?:\.\d+)?$/i;
const CJK_CHAR_RE = /[\u3400-\u4dbf\u4e00-\u9fff]/;

function stripMarkdownToCleanLead(mdText, maxChars = 220) {
  const raw = String(mdText || '').replace(/^\uFEFF/, '');
  if (!raw.trim()) return '';
  // Strip YAML frontmatter and fenced code blocks
  const withoutBlocks = raw
    .replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n?/, '')
    .replace(/^ {0,3}(`{3,}|~{3,})[^\r\n]*\r?\n[\s\S]*?^ {0,3}\1[ \t]*$/gm, '')
    .replace(/<!--[\s\S]*?-->/g, '');

  const paragraphs = withoutBlocks.split(/\r?\n\s*\r?\n/);
  for (const rawPara of paragraphs) {
    const lines = rawPara
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => {
        if (!l) return false;
        if (/^#{1,6}\s/.test(l)) return false;
        if (/^[-*_]{3,}$/.test(l)) return false;
        if (/^<[^>]+>$/.test(l)) return false;
        if (/^\|/.test(l)) return false;
        // Skip badge-only lines and language switcher lines
        if (/^(?:\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)|!\[[^\]]*\]\([^)]*\)|<img\b[^>]*>|\s)+$/i.test(l)) return false;
        if (/^\[(?:简体中文|中文|english|en|日本語|한국어)[^\]]*\]\([^)]+\)/i.test(l)) return false;
        return true;
      });
    if (lines.length === 0) continue;

    const cleaned = lines
      .join(' ')
      .replace(/^>\s*/g, '')
      .replace(/!\[[^\]]*\]\([^)]*\)/g, '')
      .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
      .replace(/<[^>]+>/g, ' ')
      .replace(/`([^`]+)`/g, '$1')
      .replace(/[*_~]{1,3}([^*_~]+)[*_~]{1,3}/g, '$1')
      .replace(/\s+/g, ' ')
      .trim();

    if (cleaned.length >= 16) {
      return cleaned.length > maxChars ? `${cleaned.slice(0, maxChars - 1).trimEnd()}…` : cleaned;
    }
  }
  return '';
}

function isWeakDescription(text) {
  const s = String(text || '').trim();
  if (s.length < 15) return true;
  if (VERSION_STUB_DESC_RE.test(s)) return true;
  return false;
}

/**
 * Extracts clean bilingual `{ zh, en }` summaries from localized READMEs when `description`
 * is missing, too short, version-stub-only, or monolingual.
 */
export function extractBilingualSummaryFromReadmes({
  description = '',
  readmeZh = '',
  readmeEn = '',
  maxZhChars = 180,
  maxEnChars = 240,
} = {}) {
  const rawZh =
    typeof description === 'object' && description !== null
      ? String(description.zh || '').trim()
      : String(description || '').trim();
  const rawEn =
    typeof description === 'object' && description !== null
      ? String(description.en || '').trim()
      : String(description || '').trim();

  const leadZh = stripMarkdownToCleanLead(readmeZh, maxZhChars);
  const leadEn = stripMarkdownToCleanLead(readmeEn, maxEnChars);

  let zh = rawZh;
  let en = rawEn;
  const extractedFromReadme = { zh: false, en: false };

  if (leadZh && (isWeakDescription(zh) || (!CJK_CHAR_RE.test(zh) && CJK_CHAR_RE.test(leadZh)))) {
    zh = leadZh;
    extractedFromReadme.zh = true;
  }
  if (leadEn && (isWeakDescription(en) || (CJK_CHAR_RE.test(en) && !CJK_CHAR_RE.test(leadEn)))) {
    en = leadEn;
    extractedFromReadme.en = true;
  }

  if (!zh && en) zh = en;
  if (!en && zh) en = zh;

  return { zh, en, extractedFromReadme };
}

function sanitizeReadmeForFallback(readmeText, skillDescriptions = []) {
  const skillsJoined = (Array.isArray(skillDescriptions) ? skillDescriptions : [])
    .filter((s) => typeof s === 'string' && s.trim())
    .join(' ');
  const readmeCleaned = String(readmeText || '')
    .replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n?/, '')
    .replace(/^ {0,3}(`{3,}|~{3,})[^\r\n]*\r?\n[\s\S]*?^ {0,3}\1[ \t]*$/gm, ' ')
    .replace(/!\[[^\]]*\]\([^)]*\)/g, ' ')
    .slice(0, 2000);
  return sanitizeDescriptionNoise(`${skillsJoined} ${readmeCleaned}`);
}

/**
 * Deterministic curated-override + multi-signal taxonomy classifier v2 for Track-1 & Track-2 plugins.
 */
export function inferPluginTaxonomy({
  id = '',
  canonicalName = '',
  displayName = '',
  description = '',
  topics = [],
  capabilities = {},
  existingCategories = [],
  existingTags = [],
  yamlCategory = '',
  readmeText = '',
  skillDescriptions = [],
} = {}) {
  const normId = String(id || '').trim().toLowerCase();
  const badges = Array.isArray(capabilities?.badges) ? capabilities.badges : [];
  const cleanExistingCategories = normalizeCategories(existingCategories);
  const explicitExistingCategories = cleanExistingCategories.filter((c) => c !== 'other');
  const cleanExistingTags = normalizeTags(existingTags, { stripExperimental: true });
  const cleanYamlCategory =
    typeof yamlCategory === 'string' && ALLOWED_CATEGORIES.has(yamlCategory.trim()) ? yamlCategory.trim() : '';

  const curated =
    CURATED_TAXONOMY_OVERRIDES[normId] ||
    CURATED_TAXONOMY_OVERRIDES[normId.replace(/--plugin$/, '')] ||
    null;

  // 1. Respect explicit upstream non-`other` companion categories when provided.
  if (explicitExistingCategories.length > 0) {
    const mergedTags = curated
      ? normalizeTags([...cleanExistingTags, ...curated.tags])
      : cleanExistingTags.length > 0
        ? cleanExistingTags
        : normalizeTags([...deriveTopicTags(topics), ...deriveBadgeTags(badges)], { maxTags: 5 });
    return {
      categories: explicitExistingCategories,
      tags: mergedTags,
      taxonomyVersion: TAXONOMY_VERSION,
    };
  }

  // 2. Apply curated override for known catalog plugins.
  if (curated) {
    const categories =
      cleanYamlCategory && cleanYamlCategory !== 'other'
        ? normalizeCategories([cleanYamlCategory, ...curated.categories])
        : normalizeCategories(curated.categories);
    const tags = normalizeTags([...cleanExistingTags, ...curated.tags]);
    return {
      categories: categories.length > 0 ? categories : ['other'],
      tags,
      taxonomyVersion: TAXONOMY_VERSION,
    };
  }

  // 3. Multi-signal deterministic scoring for community plugins.
  const pluginSlug = extractPluginSlugFromId(normId);
  const titleCorpus = [
    pluginSlug,
    String(canonicalName || ''),
    String(displayName || ''),
    ...(Array.isArray(topics) ? topics : []),
  ]
    .join(' ')
    .trim();
  const descCorpus = sanitizeDescriptionNoise(flattenDescription(description));

  const scores = new Map();
  const matchedTags = [];
  const bumpScore = (cat, pts) => {
    if (!ALLOWED_CATEGORIES.has(cat)) return;
    scores.set(cat, (scores.get(cat) || 0) + pts);
  };

  for (const rule of SIGNAL_RULES) {
    const inTitle = titleCorpus ? rule.re.test(titleCorpus) : false;
    const inDesc = descCorpus ? rule.re.test(descCorpus) : false;
    if (inTitle || inDesc) {
      // Name/title matches carry extra authority over incidental mentions in long prose descriptions.
      bumpScore(rule.category, inTitle ? rule.weight + 2 : rule.weight);
      if (rule.tag) matchedTags.push(rule.tag);
    }
  }

  // 3b. Low-weight README + SKILL.md description fallback ONLY when title+desc top score < 4.
  let maxTextScore = 0;
  for (const sc of scores.values()) {
    if (sc > maxTextScore) maxTextScore = sc;
  }
  if (maxTextScore < 4 && (readmeText || (Array.isArray(skillDescriptions) && skillDescriptions.length > 0))) {
    const fallbackCorpus = sanitizeReadmeForFallback(readmeText, skillDescriptions);
    if (fallbackCorpus) {
      for (const rule of SIGNAL_RULES) {
        if (rule.re.test(fallbackCorpus)) {
          const lowWeight = Math.min(4, Math.max(2, Math.ceil(rule.weight * 0.55)));
          bumpScore(rule.category, lowWeight);
          if (rule.tag) matchedTags.push(rule.tag);
        }
      }
      for (const sc of scores.values()) {
        if (sc > maxTextScore) maxTextScore = sc;
      }
    }
  }

  // Capability badge & identifier signals (gentle boosts, never overpowering explicit domain matches)
  const hasMcpBadge = badges.includes('mcp-stdio') || badges.includes('mcp-remote');
  const isDeclarativeOnly = badges.includes('declarative-only');
  const hasHostEnhancement = badges.includes('host-enhancement');
  const hasHooks = badges.includes('lifecycle-hooks');
  const hasSidecar = badges.includes('sidecar-ui');

  if (hasMcpBadge) {
    bumpScore('mcp-integrations', 2);
  }
  if (/(?:^|[-_/])mcp(?:$|[-_/])/i.test(`${pluginSlug} ${canonicalName}`)) {
    bumpScore('mcp-integrations', 2);
  }
  if (isDeclarativeOnly) {
    // Never let declarative-only badge boost (+2) override an already-matched concrete non-workflow domain!
    const topNonWorkflowScore = [...scores.entries()]
      .filter(([cat]) => cat !== 'skills-workflows')
      .reduce((mx, [, sc]) => Math.max(mx, sc), 0);
    if (topNonWorkflowScore < 4) {
      bumpScore('skills-workflows', 2);
    }
  }
  if (hasHostEnhancement && (scores.get('ui-themes') || 0) > 0) {
    bumpScore('ui-themes', 1);
  }

  const ranked = [...scores.entries()]
    .filter(([, score]) => score > 0)
    .sort(
      (a, b) =>
        b[1] - a[1] ||
        (CATEGORY_PRIORITY_INDEX.get(a[0]) ?? 999) - (CATEGORY_PRIORITY_INDEX.get(b[0]) ?? 999),
    );

  let inferredCategories = [];
  if (cleanYamlCategory && cleanYamlCategory !== 'other') {
    inferredCategories = [cleanYamlCategory];
  } else if (ranked.length > 0 && ranked[0][1] >= 4) {
    const [primaryCat, primaryScore] = ranked[0];
    inferredCategories.push(primaryCat);
    if (ranked.length > 1) {
      const [secondaryCat, secondaryScore] = ranked[1];
      if (secondaryScore >= 6 && secondaryScore >= primaryScore * 0.65) {
        inferredCategories.push(secondaryCat);
      }
    }
  } else if (hasMcpBadge) {
    inferredCategories = ['mcp-integrations'];
  } else if (isDeclarativeOnly) {
    inferredCategories = ['skills-workflows'];
  } else if (hasHooks) {
    inferredCategories = ['automation'];
  } else if (hasSidecar) {
    inferredCategories = ['productivity'];
  } else if (ranked.length > 0) {
    inferredCategories = [ranked[0][0]];
  } else {
    inferredCategories = ['other'];
  }

  const finalCategories = normalizeCategories(inferredCategories);
  const finalTags = normalizeTags(
    [...cleanExistingTags, ...matchedTags, ...deriveTopicTags(topics), ...deriveBadgeTags(badges)],
    { stripExperimental: true, maxTags: 5 },
  );
  const nonOtherCats = finalCategories.filter((c) => c !== 'other');
  const fallbackTags =
    nonOtherCats.length > 0
      ? nonOtherCats
      : normalizeTags([canonicalName, pluginSlug, 'community'], { stripExperimental: true, maxTags: 2 });

  return {
    categories: finalCategories.length > 0 ? finalCategories : ['other'],
    tags: finalTags.length > 0 ? finalTags : fallbackTags.length > 0 ? fallbackTags : ['community'],
    taxonomyVersion: TAXONOMY_VERSION,
  };
}
