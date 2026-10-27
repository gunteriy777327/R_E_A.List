#!/usr/bin/env node

import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { importVerifierSource } from "./lib/verifier-source-loader.mjs";

const {
  WINDOWS_NATIVE_RESTORE_LIMITS,
  admitRestoredWindowsNativeFiles,
  extractWindowsNativeTarball,
  verifyTarballIntegrity,
} = await importVerifierSource(
  new URL("../src/domain/windowsNativeRestore.ts", import.meta.url).href,
  import.meta.url,
);
const { WINDOWS_NATIVE_ARTIFACT } = await importVerifierSource(
  new URL("../src/domain/windowsNativeArtifact.ts", import.meta.url).href,
  import.meta.url,
);

const args = process.argv.slice(2);
const force = args.includes("--force");
if (args.some((arg) => arg !== "--force"))
  throw new Error("Usage: npm run restore:windows-native [-- --force]");

const root = new URL("../", import.meta.url);
const build = new URL("native/windows/build/", root);
const manifestUrl = new URL("manifest.json", build);
const artifactUrl = new URL(WINDOWS_NATIVE_ARTIFACT.artifact, build);
const packageJson = JSON.parse(
  await readFile(new URL("package.json", root), "utf8"),
);
const version = packageJson.version;

const report = (value) =>
  process.stdout.write(`${JSON.stringify({ version, ...value })}\n`);

const current = await Promise.all([
  readFile(manifestUrl),
  readFile(artifactUrl),
]).then(
  ([manifestBytes, artifactBytes]) =>
    admitRestoredWindowsNativeFiles({ manifestBytes, artifactBytes }, version),
  () => undefined,
);
if (current?.ok && !force) {
  report({ ok: true, restored: false, reason: "already-valid" });
  process.exit(0);
}

const registry = (
  process.env.npm_config_registry ?? "https://registry.npmjs.org/"
).replace(/\/?$/u, "/");
const fetchChecked = async (url, what) => {
  const response = await fetch(url, { signal: AbortSignal.timeout(120_000) });
  if (!response.ok)
    throw new Error(
      `${what} download failed: ${url}: HTTP ${response.status}` +
        (response.status === 404
          ? `. Version ${version} is not published; build the artifact with npm run build:windows-native instead.`
          : ""),
    );
  return response;
};
const metadata = await (
  await fetchChecked(
    new URL(`${packageJson.name}/${encodeURIComponent(version)}`, registry),
    "Registry metadata",
  )
).json();
if (metadata?.version !== version)
  throw new Error(
    `Registry returned ${String(metadata?.version)} instead of ${version}`,
  );
const { tarball, integrity } = metadata.dist ?? {};
if (typeof tarball !== "string" || typeof integrity !== "string")
  throw new Error("Registry metadata has no tarball or integrity");
const response = await fetchChecked(tarball, "Published tarball");
const declared = Number(response.headers.get("content-length"));
if (declared > WINDOWS_NATIVE_RESTORE_LIMITS.tarballBytes)
  throw new Error("Published tarball exceeds the restore size bound");
const bytes = Buffer.from(await response.arrayBuffer());
if (bytes.length > WINDOWS_NATIVE_RESTORE_LIMITS.tarballBytes)
  throw new Error("Published tarball exceeds the restore size bound");

const unwrap = (result) => {
  if (!result.ok) throw result.error;
  return result.value;
};
unwrap(verifyTarballIntegrity(bytes, integrity));
const files = unwrap(
  admitRestoredWindowsNativeFiles(
    unwrap(extractWindowsNativeTarball(bytes)),
    version,
  ),
);

await mkdir(build, { recursive: true });
const staged = async (target, contents) => {
  const temporary = new URL(`${target.href}.restore-${process.pid}`);
  await writeFile(temporary, contents, { flag: "wx" });
  return { temporary, target };
};
const writes = [
  await staged(artifactUrl, files.artifactBytes),
  await staged(manifestUrl, files.manifestBytes),
];
try {
  for (const { temporary, target } of writes) await rename(temporary, target);
} finally {
  await Promise.all(
    writes.map(({ temporary }) => rm(temporary, { force: true })),
  );
}

unwrap(
  admitRestoredWindowsNativeFiles(
    {
      manifestBytes: await readFile(manifestUrl),
      artifactBytes: await readFile(artifactUrl),
    },
    version,
  ),
);
report({
  ok: true,
  restored: true,
  tarball,
  artifactSha256: files.manifest.artifactSha256,
  artifactBytes: files.artifactBytes.length,
});
