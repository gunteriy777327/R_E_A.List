import { expect, it } from "vitest";
import {
  decodeRegistryScript,
  parseRegistryScript,
} from "./RegistryScriptParser.js";

/** ATL wizard registrar layout for an in-process server. */
const script = `HKCR
{
  DemoCad.Application.7 = s 'DemoCad Application'
  {
    CLSID = s '{5b2a9d34-1c4e-4f6a-9b1d-2e3f4a5b6c7d}'
  }
  DemoCad.Application = s 'DemoCad Application'
  {
    CLSID = s '{5B2A9D34-1C4E-4F6A-9B1D-2E3F4A5B6C7D}'
    CurVer = s 'DemoCad.Application.7'
  }
  NoRemove CLSID
  {
    ForceRemove {5B2A9D34-1C4E-4F6A-9B1D-2E3F4A5B6C7D} = s 'Demo ''CAD'' Application'
    {
      ProgID = s 'DemoCad.Application.7'
      VersionIndependentProgID = s 'DemoCad.Application'
      ForceRemove 'Programmable'
      InprocServer32 = s '%MODULE%'
      {
        val ThreadingModel = s 'Apartment'
      }
      TypeLib = s '{5B2A9D30-1C4E-4F6A-9B1D-2E3F4A5B6C7D}'
    }
  }
}
`;

it("extracts classes and ProgIDs from an ATL registrar script", () => {
  expect(parseRegistryScript(script)).toEqual({
    classes: [
      {
        clsid: "{5B2A9D34-1C4E-4F6A-9B1D-2E3F4A5B6C7D}",
        name: "Demo 'CAD' Application",
        prog_id: "DemoCad.Application.7",
        version_independent_prog_id: "DemoCad.Application",
        typelib: "{5B2A9D30-1C4E-4F6A-9B1D-2E3F4A5B6C7D}",
      },
    ],
    prog_ids: [
      {
        prog_id: "DemoCad.Application.7",
        clsid: "{5B2A9D34-1C4E-4F6A-9B1D-2E3F4A5B6C7D}",
      },
      {
        prog_id: "DemoCad.Application",
        clsid: "{5B2A9D34-1C4E-4F6A-9B1D-2E3F4A5B6C7D}",
      },
    ],
    issues: [],
  });
});

it("reads HKLM\\Software\\Classes and ignores non-class roots", () => {
  const result = parseRegistryScript(`HKLM { Software { Classes {
    Demo.Tool = s 'Tool' { CLSID = s '{11111111-2222-3333-4444-555555555555}' }
  } } }
  HKCU { Software { Demo { Ignored = s 'x' } } }`);
  expect(result.prog_ids).toEqual([
    { prog_id: "Demo.Tool", clsid: "{11111111-2222-3333-4444-555555555555}" },
  ]);
});

it("skips unresolved replaceable CLSIDs and reports syntax errors", () => {
  expect(
    parseRegistryScript("HKCR { Demo.X = s 'X' { CLSID = s '%CLSID%' } }")
      .prog_ids,
  ).toEqual([]);
  const broken = parseRegistryScript("HKCR { Demo.X = s 'X' {");
  expect(broken.issues).toEqual([
    {
      code: "malformed_entry",
      location: null,
      message: "Registrar script ends inside a key.",
    },
  ]);
});

it("decodes UTF-16LE and code-page scripts", () => {
  expect(
    decodeRegistryScript(
      Buffer.concat([
        Buffer.from([0xff, 0xfe]),
        Buffer.from("HKCR", "utf16le"),
      ]),
      1252,
    ),
  ).toBe("HKCR");
  expect(decodeRegistryScript(Buffer.from("HKCR", "utf16le"), 1252)).toBe(
    "HKCR",
  );
  expect(decodeRegistryScript(Buffer.from([0xcf, 0xf0, 0xe8]), 1251)).toBe(
    "При",
  );
});
