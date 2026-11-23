// Zero-dependency pure-Node streaming .tar.gz / POSIX ustar + pax parser and deterministic builder.
// Enforces hard security boundaries: rejects `..` path traversal, absolute paths, NUL bytes,
// symlinks ('2'), hardlinks ('1'), device nodes, and >100 MB decompression bombs.

import { createHash } from 'node:crypto';
import { gunzipSync, gzipSync } from 'node:zlib';
import { MAX_TARBALL_BYTES } from './constants.mjs';

function readCleanString(buf, start, length) {
  const sub = buf.subarray(start, start + length);
  const nul = sub.indexOf(0);
  return (nul === -1 ? sub : sub.subarray(0, nul)).toString('utf8');
}

function parseTarOctal(buf, start, length) {
  // Handle base-256 binary extension if high bit set
  if ((buf[start] & 0x80) !== 0) {
    let val = 0n;
    for (let i = start + 1; i < start + length; i++) {
      val = (val << 8n) | BigInt(buf[i]);
    }
    return Number(val);
  }
  const str = readCleanString(buf, start, length).trim();
  if (!str) return 0;
  const parsed = parseInt(str, 8);
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new Error(`ERR_TAR_CORRUPT: Invalid octal header value "${str}"`);
  }
  return parsed;
}

function parsePaxRecords(buf) {
  const text = buf.toString('utf8');
  const attrs = {};
  let idx = 0;
  while (idx < text.length) {
    const sp = text.indexOf(' ', idx);
    if (sp === -1) break;
    const len = parseInt(text.slice(idx, sp), 10);
    if (!Number.isFinite(len) || len <= 0) break;
    const record = text.slice(sp + 1, idx + len - 1); // strip trailing \n
    const eq = record.indexOf('=');
    if (eq !== -1) {
      attrs[record.slice(0, eq)] = record.slice(eq + 1);
    }
    idx += len;
  }
  return attrs;
}

export function validateSafeArchivePath(rawPath) {
  if (typeof rawPath !== 'string' || rawPath.length === 0) {
    throw new Error('ERR_TAR_UNSAFE_PATH: Empty entry path');
  }
  if (rawPath.includes('\0')) {
    throw new Error('ERR_TAR_UNSAFE_PATH: NUL byte in entry path');
  }
  const normalized = rawPath.replace(/\\/g, '/');
  if (normalized.startsWith('/') || /^[A-Za-z]:/.test(normalized)) {
    throw new Error(`ERR_TAR_UNSAFE_PATH: Absolute archive path prohibited ("${rawPath}")`);
  }
  const rawSegments = normalized.split('/');
  const cleanSegments = [];
  for (const seg of rawSegments) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      throw new Error(`ERR_TAR_PATH_TRAVERSAL: Parent traversal ".." prohibited ("${rawPath}")`);
    }
    cleanSegments.push(seg);
  }
  return cleanSegments.join('/');
}

/**
 * Inspect a .tar.gz / .tgz buffer in memory without writing to disk or executing anything.
 * Returns `{ sha256, compressedBytes, uncompressedBytes, files: Map<string, Buffer>, rawPaths: string[] }`.
 */
export function inspectTarGzBuffer(
  compressedBuf,
  { maxCompressedBytes = MAX_TARBALL_BYTES, maxUncompressedBytes = MAX_TARBALL_BYTES, stripSingleTopDir = true } = {},
) {
  if (!Buffer.isBuffer(compressedBuf)) {
    throw new Error('ERR_TAR_INPUT: Expected Buffer');
  }
  if (compressedBuf.length === 0) {
    throw new Error('ERR_TAR_EMPTY: Empty archive');
  }
  if (compressedBuf.length > maxCompressedBytes) {
    throw new Error(`ERR_TAR_TOO_LARGE: Compressed size ${compressedBuf.length} exceeds ${maxCompressedBytes}`);
  }

  const sha256 = createHash('sha256').update(compressedBuf).digest('hex');
  let tarBuf;
  try {
    tarBuf = gunzipSync(compressedBuf, { maxOutputLength: maxUncompressedBytes });
  } catch (err) {
    if (/Cannot create a Buffer|maxOutputLength|ERR_BUFFER_TOO_LARGE/i.test(String(err?.message))) {
      throw new Error(`ERR_TAR_DECOMPRESS_LIMIT: Uncompressed size exceeds ${maxUncompressedBytes}`);
    }
    throw new Error(`ERR_TAR_GZIP_INVALID: ${err?.message || String(err)}`);
  }

  const rawFiles = new Map();
  let offset = 0;
  let nextPax = {};
  let globalPax = {};
  let nextLongName = '';

  while (offset + 512 <= tarBuf.length) {
    const header = tarBuf.subarray(offset, offset + 512);
    offset += 512;

    // Two consecutive zero blocks mark end-of-archive
    let allZero = true;
    for (let i = 0; i < 512; i++) {
      if (header[i] !== 0) {
        allZero = false;
        break;
      }
    }
    if (allZero) continue;

    const namePart = readCleanString(header, 0, 100);
    const prefixPart = readCleanString(header, 345, 155);
    const typeFlagChar = header[156] === 0 ? '0' : String.fromCharCode(header[156]);
    let size = parseTarOctal(header, 124, 12);
    if (nextPax.size !== undefined) {
      size = Number(nextPax.size);
    }

    if (offset + size > tarBuf.length) {
      throw new Error('ERR_TAR_TRUNCATED: Unexpected EOF inside tar entry payload');
    }

    const payload = tarBuf.subarray(offset, offset + size);
    const blocks = Math.ceil(size / 512);
    offset += blocks * 512;

    // PAX extended headers
    if (typeFlagChar === 'x') {
      nextPax = parsePaxRecords(payload);
      continue;
    }
    if (typeFlagChar === 'g') {
      globalPax = { ...globalPax, ...parsePaxRecords(payload) };
      continue;
    }
    // GNU LongLink path override
    if (typeFlagChar === 'L') {
      nextLongName = readCleanString(payload, 0, payload.length);
      continue;
    }

    const mergedPax = { ...globalPax, ...nextPax };
    nextPax = {};

    const rawEntryName =
      nextLongName ||
      mergedPax.path ||
      (prefixPart ? `${prefixPart}/${namePart}` : namePart);
    nextLongName = '';

    // Hard-block symlinks, hardlinks, FIFOs, character/block devices
    if (typeFlagChar === '1' || typeFlagChar === '2') {
      throw new Error(`ERR_TAR_SYMLINK_FORBIDDEN: Archive entry "${rawEntryName}" is a link (typeflag=${typeFlagChar})`);
    }
    if (typeFlagChar !== '0' && typeFlagChar !== '5') {
      throw new Error(`ERR_TAR_UNSUPPORTED_TYPE: Archive entry "${rawEntryName}" has disallowed typeflag "${typeFlagChar}"`);
    }

    const safePath = validateSafeArchivePath(rawEntryName);
    if (!safePath || typeFlagChar === '5' || rawEntryName.endsWith('/')) {
      continue; // directory entry
    }

    rawFiles.set(safePath, Buffer.from(payload));
  }

  // Normalize optional single top-level wrapper folder (e.g. `package/plugin.json` or `my-plugin-1.0.0/plugin.json`)
  // ONLY when `plugin.json` is not already at the archive root.
  let files = rawFiles;
  let strippedRoot = '';
  if (stripSingleTopDir && !rawFiles.has('plugin.json') && rawFiles.size > 0) {
    const firstSegments = new Set();
    let allNested = true;
    for (const p of rawFiles.keys()) {
      const slash = p.indexOf('/');
      if (slash === -1) {
        allNested = false;
        break;
      }
      firstSegments.add(p.slice(0, slash));
    }
    if (allNested && firstSegments.size === 1) {
      const [onlyRoot] = firstSegments;
      strippedRoot = onlyRoot;
      files = new Map();
      for (const [p, buf] of rawFiles.entries()) {
        files.set(p.slice(onlyRoot.length + 1), buf);
      }
    }
  }

  return {
    sha256,
    compressedBytes: compressedBuf.length,
    uncompressedBytes: tarBuf.length,
    strippedRoot,
    files,
    rawPaths: [...rawFiles.keys()],
  };
}

function writeOctalField(buf, strVal, offset, length) {
  const oct = strVal.padStart(length - 1, '0');
  buf.write(oct, offset, length - 1, 'ascii');
  buf[offset + length - 1] = 0;
}

function createUstarHeader(relPath, byteLength, { mode = 0o644, mtime = 0, typeflag = '0' } = {}) {
  const header = Buffer.alloc(512, 0);
  const safe = validateSafeArchivePath(relPath);
  let name = safe;
  let prefix = '';

  if (Buffer.byteLength(safe, 'utf8') > 100) {
    const slashIdx = safe.lastIndexOf('/');
    if (slashIdx === -1) {
      throw new Error(`Filename exceeds 100 bytes without directory prefix: ${safe}`);
    }
    prefix = safe.slice(0, slashIdx);
    name = safe.slice(slashIdx + 1);
    if (Buffer.byteLength(prefix, 'utf8') > 155 || Buffer.byteLength(name, 'utf8') > 100) {
      throw new Error(`Path exceeds POSIX ustar 255-byte limit: ${safe}`);
    }
  }

  header.write(name, 0, Math.min(100, Buffer.byteLength(name)), 'utf8');
  writeOctalField(header, mode.toString(8), 100, 8);
  writeOctalField(header, '0', 108, 8); // uid
  writeOctalField(header, '0', 116, 8); // gid
  writeOctalField(header, byteLength.toString(8), 124, 12);
  writeOctalField(header, mtime.toString(8), 136, 12);

  // Checksum placeholder (8 spaces)
  header.fill(0x20, 148, 156);
  header.write(typeflag, 156, 1, 'ascii');
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  if (prefix) {
    header.write(prefix, 345, Math.min(155, Buffer.byteLength(prefix)), 'utf8');
  }

  let sum = 0;
  for (let i = 0; i < 512; i++) sum += header[i];
  const chk = sum.toString(8).padStart(6, '0');
  header.write(chk, 148, 6, 'ascii');
  header[154] = 0;
  header[155] = 0x20;
  return header;
}

/**
 * Deterministic POSIX ustar .tar.gz builder (sorted paths, mtime=0, gzip OS=3).
 * `entries`: Record<string, string | Buffer> or Map<string, string | Buffer>.
 */
export function createTarGzBuffer(entries) {
  const pairs = entries instanceof Map ? [...entries.entries()] : Object.entries(entries || {});
  const normalized = pairs
    .map(([p, content]) => [
      validateSafeArchivePath(p),
      Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8'),
    ])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));

  const chunks = [];
  for (const [relPath, buf] of normalized) {
    const mode = relPath.startsWith('bin/') || relPath.endsWith('.sh') ? 0o755 : 0o644;
    chunks.push(createUstarHeader(relPath, buf.length, { mode, mtime: 0, typeflag: '0' }));
    chunks.push(buf);
    const rem = buf.length % 512;
    if (rem !== 0) {
      chunks.push(Buffer.alloc(512 - rem, 0));
    }
  }
  // End-of-archive marker: two 512-byte zero blocks
  chunks.push(Buffer.alloc(1024, 0));

  const tarRaw = Buffer.concat(chunks);
  const gz = gzipSync(tarRaw, { level: 9 });
  // Normalize gzip header mtime (bytes 4..7) & OS byte (byte 9 = 3 Unix) for 100% deterministic SHA-256 across Windows/Linux/macOS
  if (gz.length >= 10 && gz[0] === 0x1f && gz[1] === 0x8b) {
    gz[4] = 0;
    gz[5] = 0;
    gz[6] = 0;
    gz[7] = 0;
    gz[9] = 3;
  }
  return gz;
}
