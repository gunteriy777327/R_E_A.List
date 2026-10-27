import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import {
  WINDOWS_NATIVE_ARTIFACT,
  parseWindowsNativeManifest,
  validateWindowsNativeArtifact,
  type WindowsNativeManifest,
} from "./windowsNativeArtifact.js";
import { err, ok, type Result } from "./result.js";

/** Published tarball paths of the two files a source checkout may restore. */
export const WINDOWS_NATIVE_TARBALL_ENTRIES = {
  manifest: "package/native/windows/build/manifest.json",
  artifact: `package/native/windows/build/${WINDOWS_NATIVE_ARTIFACT.artifact}`,
} as const;

/** Bounds applied before any decompressed byte is retained. */
export const WINDOWS_NATIVE_RESTORE_LIMITS = {
  tarballBytes: 256 * 1_024 * 1_024,
  manifestBytes: 4 * 1_024,
  artifactBytes: 64 * 1_024 * 1_024,
} as const;

export class WindowsNativeRestoreError extends Error {
  readonly _tag = "WindowsNativeRestoreError" as const;
}

export type RestoredWindowsNativeFiles = {
  readonly manifest: WindowsNativeManifest;
  readonly manifestBytes: Buffer;
  readonly artifactBytes: Buffer;
};

const fail = (message: string) => err(new WindowsNativeRestoreError(message));

/** Check npm's `dist.integrity` (sha512 SRI) against the downloaded bytes. */
export const verifyTarballIntegrity = (
  bytes: Buffer,
  integrity: string,
): Result<void, WindowsNativeRestoreError> => {
  const digests = integrity
    .trim()
    .split(/\s+/u)
    .filter((entry) => entry.startsWith("sha512-"))
    .map((entry) => entry.slice("sha512-".length));
  if (digests.length === 0)
    return fail("Published tarball has no sha512 integrity digest");
  const observed = createHash("sha512").update(bytes).digest("base64");
  return digests.includes(observed)
    ? ok(undefined)
    : fail("Published tarball does not match its registry sha512 integrity");
};

const field = (header: Buffer, offset: number, length: number) => {
  const raw = header.subarray(offset, offset + length);
  const end = raw.indexOf(0);
  return raw.toString("utf8", 0, end === -1 ? length : end);
};

const octal = (header: Buffer, offset: number, length: number) => {
  const text = field(header, offset, length).trim();
  return /^[0-7]+$/u.test(text) ? Number.parseInt(text, 8) : undefined;
};

const checksumMatches = (header: Buffer) => {
  const declared = octal(header, 148, 8);
  let sum = 0;
  for (let index = 0; index < 512; index += 1)
    sum += index >= 148 && index < 156 ? 0x20 : (header[index] ?? 0);
  return declared === sum;
};

const paxPath = (body: Buffer): string | undefined => {
  let path: string | undefined;
  let offset = 0;
  while (offset < body.length) {
    const space = body.indexOf(0x20, offset);
    if (space === -1) return undefined;
    const length = Number(body.toString("ascii", offset, space));
    if (!Number.isSafeInteger(length) || length <= space - offset)
      return undefined;
    const record = body.toString("utf8", space + 1, offset + length - 1);
    if (record.startsWith("path=")) path = record.slice("path=".length);
    offset += length;
  }
  return path;
};

type TarEntry = {
  readonly type: string;
  readonly path: string;
  readonly body: Buffer;
  readonly next: number;
};

const readTarEntry = (
  archive: Buffer,
  offset: number,
): Result<TarEntry | undefined, WindowsNativeRestoreError> => {
  if (offset + 512 > archive.length)
    return fail("Published tarball ends before its end-of-archive marker");
  const header = archive.subarray(offset, offset + 512);
  if (header.every((byte) => byte === 0)) return ok(undefined);
  if (!checksumMatches(header))
    return fail("Published tarball has a corrupt entry header");
  const size = octal(header, 124, 12);
  if (size === undefined)
    return fail("Published tarball has an invalid entry size");
  const bodyStart = offset + 512;
  if (bodyStart + size > archive.length)
    return fail("Published tarball entry exceeds the archive");
  const prefix = field(header, 345, 155);
  const name = field(header, 0, 100);
  return ok({
    type: String.fromCharCode(header[156] ?? 0),
    path: prefix === "" ? name : `${prefix}/${name}`,
    body: archive.subarray(bodyStart, bodyStart + size),
    next: bodyStart + Math.ceil(size / 512) * 512,
  });
};

const wantedEntries = new Map<string, number>([
  [
    WINDOWS_NATIVE_TARBALL_ENTRIES.manifest,
    WINDOWS_NATIVE_RESTORE_LIMITS.manifestBytes,
  ],
  [
    WINDOWS_NATIVE_TARBALL_ENTRIES.artifact,
    WINDOWS_NATIVE_RESTORE_LIMITS.artifactBytes,
  ],
]);

const decompress = (
  tarball: Buffer,
): Result<Buffer, WindowsNativeRestoreError> => {
  try {
    return ok(
      gunzipSync(tarball, {
        maxOutputLength: WINDOWS_NATIVE_RESTORE_LIMITS.tarballBytes,
      }),
    );
  } catch (cause) {
    return fail(
      `Published tarball cannot be decompressed: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
};

/** Select only the two Windows native files from a published npm tarball. */
export const extractWindowsNativeTarball = (
  tarball: Buffer,
): Result<
  { readonly manifestBytes: Buffer; readonly artifactBytes: Buffer },
  WindowsNativeRestoreError
> => {
  const archive = decompress(tarball);
  if (!archive.ok) return archive;
  const found = new Map<string, Buffer>();
  let pendingPath: string | undefined;
  let offset = 0;
  for (;;) {
    const read = readTarEntry(archive.value, offset);
    if (!read.ok) return read;
    if (read.value === undefined) break;
    const { type, body, next } = read.value;
    offset = next;
    if (type === "x" || type === "L") {
      pendingPath = type === "x" ? paxPath(body) : field(body, 0, body.length);
      continue;
    }
    if (type === "g") continue;
    const path = pendingPath ?? read.value.path;
    pendingPath = undefined;
    const limit = wantedEntries.get(path);
    if (limit === undefined) continue;
    if (type !== "0" && type !== "\0")
      return fail(`Published tarball entry ${path} is not a regular file`);
    if (found.has(path))
      return fail(`Published tarball contains ${path} more than once`);
    if (body.length > limit)
      return fail(`Published tarball entry ${path} exceeds ${limit} bytes`);
    found.set(path, Buffer.from(body));
  }
  const manifestBytes = found.get(WINDOWS_NATIVE_TARBALL_ENTRIES.manifest);
  const artifactBytes = found.get(WINDOWS_NATIVE_TARBALL_ENTRIES.artifact);
  if (manifestBytes === undefined || artifactBytes === undefined)
    return fail("Published tarball does not contain the Windows native files");
  return ok({ manifestBytes, artifactBytes });
};

/** Admit restored files only under the loader's own version and digest rules. */
export const admitRestoredWindowsNativeFiles = (
  files: { readonly manifestBytes: Buffer; readonly artifactBytes: Buffer },
  packageVersion: string,
): Result<RestoredWindowsNativeFiles, WindowsNativeRestoreError> => {
  let json: unknown;
  try {
    json = JSON.parse(files.manifestBytes.toString("utf8"));
  } catch {
    return fail("Windows native artifact manifest is not valid JSON");
  }
  const manifest = parseWindowsNativeManifest(json, packageVersion);
  if (!manifest.ok) return fail(manifest.error.message);
  const valid = validateWindowsNativeArtifact(
    manifest.value,
    files.artifactBytes,
  );
  if (!valid.ok) return fail(valid.error.message);
  return ok({ manifest: manifest.value, ...files });
};
