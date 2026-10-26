import { describe, expect, it } from "vitest";
import { demoTypelib, extensionTypelib } from "./ComTypelib.fixture.js";
import {
  ComTypelibLimitFailure,
  decodeMsftTypelib,
  type ComTypelibBudget,
  type DecodedTypelib,
} from "./MsftTypelibParser.js";
import type { ComTypeInfo } from "../../domain/native/comTypelib.js";

const unlimited: ComTypelibBudget = { takeMembers() {}, takeText() {} };

const decode = (
  bytes: Buffer,
  options: Partial<Parameters<typeof decodeMsftTypelib>[1]> = {},
) =>
  decodeMsftTypelib(bytes, {
    baseOffset: 0,
    codePage: undefined,
    includeMembers: () => true,
    budget: unlimited,
    ...options,
  });

const type = (library: DecodedTypelib, name: string): ComTypeInfo => {
  const found = library.type_infos.find((info) => info.name === name);
  if (found === undefined) throw new Error(`Missing type ${name}`);
  return found;
};

describe("widl-compiled DemoCad library", () => {
  it("reports the library identity and LCID-derived Cyrillic help strings", async () => {
    const library = await decode(demoTypelib());
    expect(library).toMatchObject({
      format: "msft",
      status: "decoded",
      name: "DemoCad",
      guid: "{5B2A9D30-1C4E-4F6A-9B1D-2E3F4A5B6C7D}",
      version: { major: 2, minor: 5 },
      lcid: 0x419,
      syskind: "win64",
      doc_string: "Библиотека автоматизации DemoCad",
      string_code_page: { code_page: 1251, source: "lcid" },
      issues: [],
    });
    expect(library.imports).toEqual([
      {
        index: 0,
        guid: "{00020430-0000-0000-C000-000000000046}",
        file_name: "stdole2.tlb",
        version: { major: 2, minor: 0 },
        lcid: 0x419,
      },
    ]);
    expect(library.type_infos.map(({ kind, name }) => [kind, name])).toEqual([
      ["enum", "DocType"],
      ["interface", "IDocument"],
      ["interface", "IUnknown"],
      ["record", "_GUID"],
      ["interface", "IApplication"],
      ["dispatch", "DApplicationEvents"],
      ["coclass", "Application"],
      ["module", "Native"],
      ["record", "Point"],
      ["alias", "DocHandle"],
    ]);
  });

  it("decodes packed and stored enum constants", async () => {
    const docType = type(await decode(demoTypelib()), "DocType");
    expect(docType.doc_string).toBe("Тип документа");
    expect(
      docType.variables.map(({ name, var_kind, value }) => [
        name,
        var_kind,
        value,
      ]),
    ).toEqual([
      ["dtDrawing", "const", { vt: "I4", value: 1 }],
      ["dtPart", "const", { vt: "I4", value: 2 }],
      ["dtNegative", "const", { vt: "I4", value: -5 }],
      ["dtLarge", "const", { vt: "I4", value: 0x10000000 }],
    ]);
  });

  it("decodes accessors, parameter flags and default values", async () => {
    const document = type(await decode(demoTypelib()), "IDocument");
    expect(document).toMatchObject({
      guid: "{5B2A9D32-1C4E-4F6A-9B1D-2E3F4A5B6C7D}",
      flags: ["oleautomation"],
      doc_string: "Document",
      function_count: 4,
      members_reported: true,
      implemented: [
        {
          ref: { kind: "local", type_index: 2, name: "IUnknown" },
          flags: [],
        },
      ],
    });
    const [get, put, save, items] = document.functions;
    expect(get).toMatchObject({
      memid: 1,
      name: "Name",
      invoke_kind: "propget",
      func_kind: "pure-virtual",
      call_conv: "stdcall",
      vtable_offset: 24,
      doc_string: "File name",
      return_type: { vt: "HRESULT", text: "HRESULT", ref: null },
      parameters: [
        {
          name: "value",
          type: { vt: "PTR", text: "BSTR*" },
          flags: ["out", "retval"],
          default_value: null,
        },
      ],
    });
    // Typelibs do not store the name of a property put's value parameter.
    expect(put).toMatchObject({
      memid: 1,
      name: "Name",
      invoke_kind: "propput",
      parameters: [{ name: null, type: { text: "BSTR" }, flags: ["in"] }],
    });
    expect(save?.parameters).toEqual([
      {
        name: "path",
        type: { vt: "BSTR", text: "BSTR", ref: null },
        flags_value: 0x31,
        flags: ["in", "optional", "hasdefault"],
        default_value: { vt: "BSTR", value: "draft.cdw" },
      },
      {
        name: "flags",
        type: { vt: "I4", text: "long", ref: null },
        flags_value: 0x31,
        flags: ["in", "optional", "hasdefault"],
        default_value: { vt: "I4", value: 1 },
      },
      {
        name: "ok",
        type: { vt: "PTR", text: "VARIANT_BOOL*", ref: null },
        flags_value: 0x0a,
        flags: ["out", "retval"],
        default_value: null,
      },
    ]);
    expect(save?.optional_parameters).toBe(1);
    expect(items?.parameters[0]?.type.text).toBe("SAFEARRAY(double)*");
  });
});

describe("widl-compiled DemoCad references and shapes", () => {
  it("resolves local references and fixed arrays", async () => {
    const application = type(await decode(demoTypelib()), "IApplication");
    const [open, matrix] = application.functions;
    expect(open?.parameters.map(({ name, type }) => [name, type])).toEqual([
      [
        "kind",
        {
          vt: "USERDEFINED",
          text: "DocType",
          ref: { kind: "local", hreftype: 0, type_index: 0, name: "DocType" },
        },
      ],
      [
        "document",
        {
          vt: "PTR",
          text: "IDocument**",
          ref: {
            kind: "local",
            hreftype: 100,
            type_index: 1,
            name: "IDocument",
          },
        },
      ],
    ]);
    expect(matrix?.parameters[0]?.type).toEqual({
      vt: "CARRAY",
      text: "double[4][3]",
      ref: null,
    });
  });

  it("reports coclass interfaces with default and source roles", async () => {
    const library = await decode(demoTypelib());
    const application = type(library, "Application");
    expect(application.flags).toEqual(["cancreate"]);
    expect(application.doc_string).toBe("Application object");
    expect(
      application.implemented.map(({ ref, flags }) => [
        ref.kind === "local" ? ref.name : null,
        flags,
      ]),
    ).toEqual([
      ["IApplication", ["default"]],
      ["IDocument", []],
      ["DApplicationEvents", ["default", "source"]],
    ]);
    const events = type(library, "DApplicationEvents");
    expect(events.functions[0]).toMatchObject({
      memid: 2,
      name: "Closed",
      func_kind: "dispatch",
      return_type: { text: "void" },
    });
    // MSFT name tables are case-insensitive, so the property shares the
    // earlier parameter spelling "flags".
    expect(events.variables[0]).toMatchObject({
      memid: 1,
      name: "flags",
      var_kind: "dispatch",
      instance_offset: null,
    });
  });

  it("reports module, record and alias shapes", async () => {
    const library = await decode(demoTypelib());
    expect(type(library, "Native")).toMatchObject({
      dll_name: "democad.dll",
      function_count: 2,
    });
    expect(
      type(library, "Native").functions.map(({ name, func_kind }) => [
        name,
        func_kind,
      ]),
    ).toEqual([
      ["Version", "static"],
      ["Build", "static"],
    ]);
    expect(
      type(library, "Point").variables.map(
        ({ name, type: field, instance_offset }) => [
          name,
          field.text,
          instance_offset,
        ],
      ),
    ).toEqual([
      ["x", "double", 0],
      ["y", "double", 8],
    ]);
    expect(type(library, "Point").size).toBe(16);
    expect(type(library, "DocHandle").alias_of).toEqual({
      vt: "I4",
      text: "long",
      ref: null,
    });
  });
});

describe("DemoCad decoding options", () => {
  it("applies a caller-selected code page", async () => {
    const library = await decode(demoTypelib(), { codePage: 1252 });
    expect(library.string_code_page).toEqual({
      code_page: 1252,
      source: "caller",
    });
    expect(library.doc_string).not.toBe("Библиотека автоматизации DemoCad");
  });

  it("keeps type inventories without members when members are not selected", async () => {
    const library = await decode(demoTypelib(), {
      includeMembers: (name) => name === "IApplication",
    });
    expect(type(library, "IDocument")).toMatchObject({
      function_count: 4,
      members_reported: false,
      functions: [],
    });
    expect(type(library, "IApplication").functions).toHaveLength(2);
  });

  it("propagates an exhausted member budget", async () => {
    await expect(
      decode(demoTypelib(), {
        budget: {
          takeMembers() {
            throw new ComTypelibLimitFailure("members", 1, "too many");
          },
          takeText() {},
        },
      }),
    ).rejects.toBeInstanceOf(ComTypelibLimitFailure);
  });

  it("offsets locations by the library's position in the artifact", async () => {
    const at = await decode(demoTypelib(), { baseOffset: 0x1000 });
    const zero = await decode(demoTypelib());
    expect(type(at, "IDocument").location.offset).toBe(
      type(zero, "IDocument").location.offset + 0x1000,
    );
  });
});

describe("widl-compiled DemoExt library", () => {
  it("resolves a base interface imported from stdole2 by GUID", async () => {
    const library = await decode(extensionTypelib());
    expect(library.name).toBe("DemoExt");
    expect(library.string_code_page).toEqual({
      code_page: 1252,
      source: "default",
    });
    const extension = type(library, "IExtension");
    expect(extension).toMatchObject({
      kind: "dispatch",
      flags: ["dual", "oleautomation", "dispatchable"],
      doc_string: "Extension point",
      implemented: [
        {
          ref: {
            kind: "imported",
            import_index: 0,
            guid: "{00020400-0000-0000-C000-000000000046}",
            type_index: null,
          },
        },
      ],
    });
    expect(
      extension.functions.map(({ memid, name, invoke_kind }) => [
        memid,
        name,
        invoke_kind,
      ]),
    ).toEqual([
      [10, "Attach", "func"],
      [11, "Count", "propget"],
    ]);
  });
});

describe("malformed libraries", () => {
  it("returns partial header facts for a truncated header", async () => {
    const library = await decode(demoTypelib().subarray(0, 0x40));
    expect(library).toMatchObject({
      status: "partial",
      name: null,
      type_infos: [],
    });
    expect(library.issues[0]?.code).toBe("malformed_entry");
  });

  it("keeps other members when one function record is corrupt", async () => {
    const original = await decode(demoTypelib());
    const bytes = Buffer.from(demoTypelib());
    const save = type(original, "IDocument").functions[2];
    if (save === undefined) throw new Error("Missing Save");
    // An impossible record length makes Save and later IDocument members unreadable.
    bytes.writeUInt16LE(0xfff0, save.location.offset);
    const library = await decode(bytes);
    expect(library.status).toBe("partial");
    expect(
      type(library, "IDocument").functions.map(({ name }) => name),
    ).toEqual(["Name", "Name"]);
    expect(type(library, "IApplication").functions).toHaveLength(2);
    expect(library.issues).toEqual([
      expect.objectContaining({
        code: "malformed_entry",
        location: `0x${save.location.offset.toString(16)}`,
      }),
    ]);
  });

  it("reports an unreadable type name without dropping the type", async () => {
    const bytes = Buffer.from(demoTypelib());
    const original = await decode(bytes);
    const document = type(original, "IDocument");
    bytes.writeInt32LE(0x7ffffff0, document.location.offset + 0x34);
    const library = await decode(bytes);
    expect(library.type_infos[1]).toMatchObject({
      name: null,
      guid: document.guid,
      function_count: 4,
    });
    expect(library.status).toBe("partial");
  });
});
