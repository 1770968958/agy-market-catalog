// SVG XSS Sanitizer & Binary Icon Magic-Byte Validator (`scripts/sanitize-icon.mjs`).

import { extname } from 'node:path';
import { ALLOWED_LOGO_EXTS } from './lib/constants.mjs';

export function sanitizeSvgIcon(rawSvg) {
  const text = Buffer.isBuffer(rawSvg) ? rawSvg.toString('utf8') : String(rawSvg || '');
  const trimmed = text.replace(/^\uFEFF/, '').trim();

  if (!/<svg[\s>]/i.test(trimmed) || !/<\/svg>\s*$/i.test(trimmed)) {
    throw new Error('ERR_ICON_SVG_MALFORMED: File does not contain a valid root <svg>...</svg> element');
  }
  if (/<!ENTITY/i.test(trimmed)) {
    throw new Error('ERR_ICON_SVG_XXE: XML <!ENTITY> declarations are prohibited in SVG icons');
  }

  let cleaned = trimmed;
  const before = cleaned;

  // Strip DOCTYPE, active embedded containers, scripts, event attributes, and dangerous URI schemes
  cleaned = cleaned
    .replace(/<!DOCTYPE[^>]*>/gi, '')
    .replace(/<script\b[\s\S]*?<\/script\s*>/gi, '')
    .replace(/<script\b[^>]*\/\s*>/gi, '')
    .replace(/<foreignObject\b[\s\S]*?<\/foreignObject\s*>/gi, '')
    .replace(/<foreignObject\b[^>]*\/\s*>/gi, '')
    .replace(/<(?:iframe|object|embed|audio|video)\b[\s\S]*?<\/(?:iframe|object|embed|audio|video)\s*>/gi, '')
    .replace(/<(?:iframe|object|embed|audio|video)\b[^>]*\/\s*>/gi, '')
    .replace(/\s+on[a-zA-Z0-9_-]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '')
    .replace(
      /\s+(?:xlink:href|href|src)\s*=\s*(?:"\s*(?:javascript:|vbscript:|data:text\/html)[^"]*"|'\s*(?:javascript:|vbscript:|data:text\/html)[^']*')/gi,
      '',
    )
    .replace(/url\(\s*['"]?\s*(?:javascript:|data:text\/html)[^)]*\)/gi, 'none');

  if (/<script\b|<foreignObject\b|javascript:/i.test(cleaned)) {
    throw new Error('ERR_ICON_SVG_XSS: Active script payload remained after sanitization');
  }

  return {
    sanitizedText: cleaned,
    sanitizedBuffer: Buffer.from(cleaned, 'utf8'),
    modified: cleaned !== before,
    ext: '.svg',
    mime: 'image/svg+xml',
  };
}

export function normalizeIconBuffer(buf, filePath) {
  const ext = extname(String(filePath || '')).toLowerCase();
  if (!ALLOWED_LOGO_EXTS.has(ext)) {
    throw new Error(`ERR_ICON_EXT: Unsupported logo extension "${ext}"`);
  }
  if (!Buffer.isBuffer(buf) || buf.length === 0) {
    throw new Error('ERR_ICON_EMPTY: Logo file is empty');
  }
  if (buf.length > 2 * 1024 * 1024) {
    throw new Error(`ERR_ICON_TOO_LARGE: Logo exceeds 2 MB (${buf.length} bytes)`);
  }

  if (ext === '.svg') {
    return sanitizeSvgIcon(buf);
  }

  if (ext === '.png') {
    const isPng =
      buf.length >= 8 &&
      buf[0] === 0x89 &&
      buf[1] === 0x50 &&
      buf[2] === 0x4e &&
      buf[3] === 0x47 &&
      buf[4] === 0x0d &&
      buf[5] === 0x0a &&
      buf[6] === 0x1a &&
      buf[7] === 0x0a;
    if (!isPng) throw new Error('ERR_ICON_MAGIC_MISMATCH: File with .png extension does not have PNG header');
    return { sanitizedBuffer: Buffer.from(buf), modified: false, ext: '.png', mime: 'image/png' };
  }

  if (ext === '.jpg' || ext === '.jpeg') {
    const isJpg = buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff;
    if (!isJpg) throw new Error('ERR_ICON_MAGIC_MISMATCH: File with .jpg/.jpeg extension does not have JPEG header');
    return { sanitizedBuffer: Buffer.from(buf), modified: false, ext, mime: 'image/jpeg' };
  }

  if (ext === '.webp') {
    const isWebp =
      buf.length >= 12 &&
      buf.subarray(0, 4).toString('ascii') === 'RIFF' &&
      buf.subarray(8, 12).toString('ascii') === 'WEBP';
    if (!isWebp) throw new Error('ERR_ICON_MAGIC_MISMATCH: File with .webp extension does not have WEBP header');
    return { sanitizedBuffer: Buffer.from(buf), modified: false, ext: '.webp', mime: 'image/webp' };
  }

  throw new Error(`ERR_ICON_EXT: Unhandled logo extension "${ext}"`);
}
