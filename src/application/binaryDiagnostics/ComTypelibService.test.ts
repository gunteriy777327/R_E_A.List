import { expect, it } from "vitest";
import { ComTypelibService } from "./ComTypelibService.js";
import { COM_TYPELIB_PROVIDER } from "../../domain/investigationProviders.js";
import type { ComTypelib } from "../../domain/native/comTypelib.js";
import { ok } from "../../domain/result.js";
import {
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";

const identity = COM_TYPELIB_PROVIDER;
const report: ComTypelib = {
  artifact: { path: "/artifacts/demo.tlb", sha256: "a".repeat(64), bytes: 512 },
  container: "typelib",
  libraries: [
    {
      index: 0,
      source: { kind: "file" },
      location: { offset: 0, bytes: 512 },
      sha256: "a".repeat(64),
      format: "msft",
      status: "decoded",
      name: "Demo",
      guid: "{5B2A9D30-1C4E-4F6A-9B1D-2E3F4A5B6C7D}",
      version: { major: 1, minor: 0 },
      lcid: 0,
      syskind: "win32",
      flags_value: 0,
      flags: [],
      doc_string: null,
      help_file: null,
      help_context: 0,
      string_code_page: { code_page: 1252, source: "default" },
      imports: [],
      type_infos: [
        {
          index: 0,
          kind: "coclass",
          kind_value: 5,
          name: "Application",
          guid: "{5B2A9D34-1C4E-4F6A-9B1D-2E3F4A5B6C7D}",
          version: { major: 0, minor: 0 },
          flags_value: 2,
          flags: ["cancreate"],
          doc_string: null,
          help_context: 0,
          size: 8,
          alignment: 4,
          vtable_bytes: 0,
          implemented: [],
          alias_of: null,
          dll_name: null,
          prog_ids: ["Demo.Application"],
          function_count: 0,
          variable_count: 0,
          members_reported: false,
          functions: [],
          variables: [],
          location: { offset: 0x100, bytes: 0x64 },
        },
      ],
      issues: [],
    },
  ],
  registration_scripts: [],
  unmatched_type_names: [],
  coverage: {
    status: "complete",
    reason: null,
    libraries: 1,
    type_infos: 1,
    functions: 0,
    variables: 0,
    reported_members: 0,
  },
  limitations: ["Static inventory."],
};

const serve = (value: ComTypelib) =>
  new ComTypelibService({
    identity,
    inspect: () => Promise.resolve(ok(value)),
  });

it("rejects a relative path and extra arguments before reading", async () => {
  let calls = 0;
  const service = new ComTypelibService({
    identity,
    inspect: () => {
      calls += 1;
      return Promise.resolve(ok(report));
    },
  });
  for (const input of [
    { path: "demo.tlb" },
    { path: report.artifact.path, extra: true },
    { path: report.artifact.path, code_page: 65001 },
  ]) {
    const result = await service.inspect(input);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisInputError);
  }
  expect(calls).toBe(0);
});

it("records a standalone type library as observed file Evidence", async () => {
  const result = await serve(report).inspect({ path: report.artifact.path });
  if (!result.ok) throw result.error;
  expect(result.value).toMatchObject({
    confidence: "observed",
    subject: { format: "file" },
    normalized_result: report,
  });
});

const library = report.libraries[0];
const typeInfo = library?.type_infos[0];
if (library === undefined || typeInfo === undefined)
  throw new Error("Malformed test report");

it.each<[string, ComTypelib]>([
  [
    "coverage counts",
    { ...report, coverage: { ...report.coverage, type_infos: 2 } },
  ],
  [
    "complete coverage over an undecoded library",
    { ...report, libraries: [{ ...library, status: "partial" }] },
  ],
  [
    "ProgIDs on a non-coclass",
    {
      ...report,
      libraries: [
        { ...library, type_infos: [{ ...typeInfo, kind: "interface" }] },
      ],
    },
  ],
  [
    "a type info outside its library",
    {
      ...report,
      libraries: [
        {
          ...library,
          type_infos: [{ ...typeInfo, location: { offset: 500, bytes: 100 } }],
        },
      ],
    },
  ],
  [
    "a registration script in a standalone library",
    {
      ...report,
      registration_scripts: [
        {
          resource_index: 0,
          location: { offset: 0, bytes: 1 },
          classes: [],
          prog_ids: [],
          issues: [],
        },
      ],
    },
  ],
])("rejects contradictory %s", async (_name, value) => {
  const result = await serve(value).inspect({ path: report.artifact.path });
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisOutputError);
});

it("rejects reported members when the caller asked for a summary", async () => {
  const result = await serve({
    ...report,
    libraries: [
      {
        ...library,
        type_infos: [{ ...typeInfo, members_reported: true }],
      },
    ],
  }).inspect({ path: report.artifact.path, include_members: false });
  expect(result.ok).toBe(false);
});
