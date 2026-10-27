import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import {
  WINDOWS_NATIVE_TARBALL_ENTRIES,
  admitRestoredWindowsNativeFiles,
  extractWindowsNativeTarball,
  verifyTarballIntegrity,
} from "./windowsNativeRestore.js";

const artifactFixture = () => {
  const bytes = Buffer.alloc(128);
  bytes.write("MZ");
  bytes.writeUInt32LE(64, 0x3c);
  bytes.write("PE\0\0", 64, "ascii");
  bytes.writeUInt16LE(0x8664, 68);
  bytes.writeUInt16LE(0x20b, 88);
  return bytes;
};

const manifestFor = (bytes: Buffer, packageVersion = "6.8.0") =>
  Buffer.from(
    JSON.stringify({
      packageVersion,
      platform: "win32",
      architecture: "x64",
      abiVersion: 1,
      nodeApiVersion: 8,
      artifact: "rea-windows-x64.node",
      artifactSha256: createHash("sha256").update(bytes).digest("hex"),
    }),
  );

type Entry = { path: string; body: Buffer; type?: string; prefix?: string };

const header = ({ path, body, type = "0", prefix = "" }: Entry) => {
  const block = Buffer.alloc(512);
  block.write(path, 0, 100, "utf8");
  block.write("0000644\0", 100, "ascii");
  block.write(`${body.length.toString(8).padStart(11, "0")}\0`, 124, "ascii");
  block.write(type, 156, "ascii");
  block.write("ustar\0", 257, "ascii");
  block.write("00", 263, "ascii");
  block.write(prefix, 345, 155, "utf8");
  block.fill(0x20, 148, 156);
  let sum = 0;
  for (const byte of block) sum += byte;
  block.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
  return block;
};

const tar = (entries: readonly Entry[]) =>
  Buffer.concat([
    ...entries.flatMap((entry) => [
      header(entry),
      entry.body,
      Buffer.alloc((512 - (entry.body.length % 512)) % 512),
    ]),
    Buffer.alloc(1_024),
  ]);

const pax = (path: string) => {
  const record = (length: number) => `${length} path=${path}\n`;
  let length = record(0).length;
  while (record(length).length !== length) length = record(length).length;
  return Buffer.from(record(length));
};

const published = (artifact = artifactFixture()) => [
  { path: "package/package.json", body: Buffer.from("{}") },
  {
    path: WINDOWS_NATIVE_TARBALL_ENTRIES.manifest,
    body: manifestFor(artifact),
  },
  { path: WINDOWS_NATIVE_TARBALL_ENTRIES.artifact, body: artifact },
];

describe("verifyTarballIntegrity", () => {
  it("accepts only the registry sha512 digest", () => {
    const bytes = Buffer.from("tarball");
    const digest = createHash("sha512").update(bytes).digest("base64");
    expect(verifyTarballIntegrity(bytes, `sha512-${digest}`).ok).toBe(true);
    expect(verifyTarballIntegrity(bytes, `sha1-abc sha512-${digest}`).ok).toBe(
      true,
    );
    expect(
      verifyTarballIntegrity(Buffer.from("other"), `sha512-${digest}`),
    ).toMatchObject({ ok: false });
    expect(verifyTarballIntegrity(bytes, "sha1-abc")).toMatchObject({
      ok: false,
      error: { message: expect.stringContaining("no sha512") },
    });
  });
});

describe("extractWindowsNativeTarball", () => {
  it("selects the manifest and addon and admits them for the exact version", () => {
    const artifact = artifactFixture();
    const extracted = extractWindowsNativeTarball(
      gzipSync(tar(published(artifact))),
    );
    if (!extracted.ok) throw extracted.error;
    expect(extracted.value.artifactBytes).toEqual(artifact);
    const admitted = admitRestoredWindowsNativeFiles(extracted.value, "6.8.0");
    if (!admitted.ok) throw admitted.error;
    expect(admitted.value.manifest.packageVersion).toBe("6.8.0");
    expect(
      admitRestoredWindowsNativeFiles(extracted.value, "6.9.0"),
    ).toMatchObject({
      ok: false,
      error: { message: expect.stringContaining("another REA version") },
    });
  });

  it("honours ustar prefixes and pax path overrides", () => {
    const artifact = artifactFixture();
    const entries: Entry[] = [
      {
        path: "manifest.json",
        prefix: "package/native/windows/build",
        body: manifestFor(artifact),
      },
      {
        path: "PaxHeader",
        type: "x",
        body: pax(WINDOWS_NATIVE_TARBALL_ENTRIES.artifact),
      },
      { path: "decoy.bin", body: artifact },
    ];
    const extracted = extractWindowsNativeTarball(gzipSync(tar(entries)));
    if (!extracted.ok) throw extracted.error;
    expect(admitRestoredWindowsNativeFiles(extracted.value, "6.8.0").ok).toBe(
      true,
    );
  });

  it("refuses missing, duplicated, linked, or corrupt entries", () => {
    const [, manifest, artifact] = published();
    if (manifest === undefined || artifact === undefined)
      throw new Error("fixture");
    expect(
      extractWindowsNativeTarball(gzipSync(tar([manifest]))),
    ).toMatchObject({ ok: false });
    expect(
      extractWindowsNativeTarball(
        gzipSync(tar([manifest, artifact, artifact])),
      ),
    ).toMatchObject({
      ok: false,
      error: { message: expect.stringContaining("more than once") },
    });
    expect(
      extractWindowsNativeTarball(
        gzipSync(tar([manifest, { ...artifact, type: "2" }])),
      ),
    ).toMatchObject({
      ok: false,
      error: { message: expect.stringContaining("not a regular file") },
    });
    const corrupt = tar([manifest, artifact]);
    corrupt[10] = 0x41;
    expect(extractWindowsNativeTarball(gzipSync(corrupt))).toMatchObject({
      ok: false,
      error: { message: expect.stringContaining("corrupt") },
    });
    expect(extractWindowsNativeTarball(Buffer.from("not gzip"))).toMatchObject({
      ok: false,
    });
  });

  it("rejects an addon whose digest differs from the manifest", () => {
    const artifact = artifactFixture();
    const tampered = Buffer.from(artifact);
    tampered[100] = 1;
    const extracted = extractWindowsNativeTarball(
      gzipSync(
        tar([
          {
            path: WINDOWS_NATIVE_TARBALL_ENTRIES.manifest,
            body: manifestFor(artifact),
          },
          { path: WINDOWS_NATIVE_TARBALL_ENTRIES.artifact, body: tampered },
        ]),
      ),
    );
    if (!extracted.ok) throw extracted.error;
    expect(
      admitRestoredWindowsNativeFiles(extracted.value, "6.8.0"),
    ).toMatchObject({
      ok: false,
      error: { message: expect.stringContaining("SHA-256") },
    });
  });
});
