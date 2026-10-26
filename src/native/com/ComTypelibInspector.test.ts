import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import {
  inspectComTypelibInputSchema,
  type InspectComTypelibInput,
} from "../../domain/native/comTypelib.js";
import { peResourceFixture } from "../pe/PeResources.fixture.js";
import { demoTypelib, extensionTypelib } from "./ComTypelib.fixture.js";
import { inspectComTypelib } from "./ComTypelibInspector.js";
import { ComTypelibLimitFailure } from "./MsftTypelibParser.js";

const input = (
  overrides: Partial<InspectComTypelibInput> = {},
): InspectComTypelibInput =>
  inspectComTypelibInputSchema.parse({ path: "/artifacts/demo", ...overrides });

const artifact = (bytes: Buffer) => ({
  path: "/artifacts/demo",
  sha256: createHash("sha256").update(bytes).digest("hex"),
  bytes: bytes.length,
});

const inspect = (bytes: Buffer, overrides?: Partial<InspectComTypelibInput>) =>
  inspectComTypelib(bytes, artifact(bytes), input(overrides));

const registrar = Buffer.from(`HKCR
{
  DemoCad.Application.7 = s 'DemoCad Application'
  {
    CLSID = s '{5B2A9D34-1C4E-4F6A-9B1D-2E3F4A5B6C7D}'
  }
  NoRemove CLSID
  {
    ForceRemove {5B2A9D34-1C4E-4F6A-9B1D-2E3F4A5B6C7D} = s 'DemoCad Application'
    {
      ProgID = s 'DemoCad.Application.7'
      VersionIndependentProgID = s 'DemoCad.Application'
    }
  }
}
`);

it("inventories a standalone type library", async () => {
  const bytes = demoTypelib();
  const report = await inspect(bytes);
  expect(report).toMatchObject({
    container: "typelib",
    registration_scripts: [],
    unmatched_type_names: [],
    coverage: {
      status: "complete",
      reason: null,
      libraries: 1,
      type_infos: 10,
      functions: 12,
      variables: 11,
      reported_members: 23,
    },
  });
  expect(report.libraries[0]).toMatchObject({
    index: 0,
    source: { kind: "file" },
    location: { offset: 0, bytes: bytes.length },
    sha256: artifact(bytes).sha256,
    name: "DemoCad",
  });
});

it("reads TYPELIB resources and joins registrar ProgIDs to coclasses", async () => {
  const demo = demoTypelib();
  const { bytes } = peResourceFixture(true, [
    { type: "REGISTRY", name: 101, language: 1033, payload: registrar },
    { type: "TYPELIB", name: 1, language: 0, payload: demo },
    { type: "TYPELIB", name: 2, language: 0, payload: extensionTypelib() },
    { type: 16, name: 1, language: 1033, payload: Buffer.from("version") },
  ]);
  const report = await inspect(bytes);
  expect(report.container).toBe("pe32-plus");
  expect(report.libraries.map(({ name, source }) => [name, source])).toEqual([
    [
      "DemoCad",
      {
        kind: "pe-resource",
        resource_index: 1,
        resource_name: "#1",
        language: 0,
      },
    ],
    [
      "DemoExt",
      {
        kind: "pe-resource",
        resource_index: 2,
        resource_name: "#2",
        language: 0,
      },
    ],
  ]);
  const library = report.libraries[0];
  if (library === undefined) throw new Error("Missing library");
  expect(
    bytes.subarray(library.location.offset).subarray(0, demo.length),
  ).toEqual(demo);
  expect(library.sha256).toBe(artifact(demo).sha256);
  expect(
    library.type_infos.find(({ name }) => name === "Application")?.prog_ids,
  ).toEqual(["DemoCad.Application", "DemoCad.Application.7"]);
  expect(
    library.type_infos.find(({ name }) => name === "IDocument")?.prog_ids,
  ).toEqual([]);
  expect(report.registration_scripts).toEqual([
    expect.objectContaining({ resource_index: 0, issues: [] }),
  ]);
  expect(report.coverage).toMatchObject({ status: "complete", libraries: 2 });
});

it("reports an image without TYPELIB resources as an empty inventory", async () => {
  const { bytes } = peResourceFixture();
  const report = await inspect(bytes);
  expect(report).toMatchObject({
    container: "pe32",
    libraries: [],
    coverage: { status: "complete", libraries: 0 },
  });
});

it("identifies SLTG and unknown TYPELIB payloads without decoding them", async () => {
  const sltg = Buffer.alloc(64);
  sltg.write("SLTG", 0, "latin1");
  const { bytes } = peResourceFixture(false, [
    { type: "TYPELIB", name: 1, language: 0, payload: sltg },
    { type: "TYPELIB", name: 2, language: 0, payload: Buffer.from("nope") },
  ]);
  const report = await inspect(bytes);
  expect(
    report.libraries.map(({ format, status }) => [format, status]),
  ).toEqual([
    ["sltg", "unsupported"],
    ["unknown", "unsupported"],
  ]);
  expect(report.coverage).toMatchObject({
    status: "partial",
    reason: "library 0 is unsupported; library 1 is unsupported",
  });
});

it("limits members to selected type names and reports unmatched names", async () => {
  const report = await inspect(demoTypelib(), {
    type_names: ["iapplication", "IMissing"],
  });
  const types = report.libraries[0]?.type_infos ?? [];
  expect(
    types
      .filter(({ members_reported }) => members_reported)
      .map(({ name }) => name),
  ).toEqual(["IApplication"]);
  expect(report.unmatched_type_names).toEqual(["IMissing"]);
  expect(report.coverage.reported_members).toBe(2);
});

it("matches type names in a summary without decoding members", async () => {
  const report = await inspect(demoTypelib(), {
    include_members: false,
    type_names: ["IApplication"],
  });
  expect(report.unmatched_type_names).toEqual([]);
  expect(report.coverage).toMatchObject({ reported_members: 0, functions: 12 });
});

it("fails without partial success when the member budget is exhausted", async () => {
  await expect(inspect(demoTypelib(), { max_members: 5 })).rejects.toEqual(
    expect.objectContaining({ limit: "members", allowance: 5 }),
  );
  await expect(
    inspect(demoTypelib(), { max_members: 5 }),
  ).rejects.toBeInstanceOf(ComTypelibLimitFailure);
});

it("rejects inputs that are neither type libraries nor PE images", async () => {
  await expect(inspect(Buffer.from("ELF\0 not a typelib"))).rejects.toEqual(
    expect.objectContaining({ reason: "format" }),
  );
  await expect(inspect(Buffer.from("MS"))).rejects.toBeInstanceOf(
    ArtifactReaderFailure,
  );
});
