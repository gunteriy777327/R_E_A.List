import { z } from "zod";

import { digestSchema } from "../digests.js";
import { absoluteLocalPathStringSchema } from "../localPath.js";
import {
  MAX_INSPECT_PE_DIRECTORY_ENTRIES,
  MAX_INSPECT_PE_FILE_BYTES,
} from "./peResources.js";

const uint = z.number().int().min(0).max(0xffffffff);
const u16 = z.number().int().min(0).max(0xffff);
const int32 = z.number().int().min(-0x80000000).max(0x7fffffff);
const range = z.strictObject({ offset: uint, bytes: uint });
const guidSchema = z
  .string()
  .regex(/^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$/u);
const text = z.string().nullable();

/** Hard ceiling on functions and variables decoded across every library. */
export const MAX_INSPECT_COM_TYPELIB_MEMBERS = 1048576;
/** Fixed ceiling on decoded names, documentation and values retained in one report. */
export const MAX_INSPECT_COM_TYPELIB_RETAINED_TEXT_BYTES = 32 * 1024 * 1024;

/** Windows ANSI code pages the decoder can apply to typelib narrow strings. */
export const COM_TYPELIB_CODE_PAGES = [
  874, 932, 936, 949, 950, 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258,
] as const;

/** Static inventory of COM type libraries in a .tlb/.olb file or a PE image's TYPELIB resources. */
export const inspectComTypelibInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute filesystem path to a .tlb/.olb type library or a PE image (DLL, EXE, OCX) with embedded TYPELIB resources",
  ),
  max_file_bytes: z
    .number()
    .int()
    .min(64)
    .max(MAX_INSPECT_PE_FILE_BYTES)
    .default(67108864)
    .describe("Maximum stable artifact bytes to read (default 64 MiB)"),
  max_entries: z
    .number()
    .int()
    .min(1)
    .max(MAX_INSPECT_PE_DIRECTORY_ENTRIES)
    .default(16384)
    .describe(
      "Maximum PE resource directory entries to examine when the input is a PE image; exceeding the budget fails without partial success",
    ),
  max_members: z
    .number()
    .int()
    .min(1)
    .max(MAX_INSPECT_COM_TYPELIB_MEMBERS)
    .default(65536)
    .describe(
      "Maximum functions and variables to decode across every library; exceeding the budget fails without partial success",
    ),
  include_members: z
    .boolean()
    .default(true)
    .describe(
      "Report functions, parameters and variables; false returns the type inventory with member counts only",
    ),
  type_names: z
    .array(z.string().min(1).max(1024))
    .max(256)
    .optional()
    .describe(
      "Report members only for these type names (case-insensitive, as COM compares names); other types keep their counts",
    ),
  code_page: z
    .literal(COM_TYPELIB_CODE_PAGES)
    .optional()
    .describe(
      "Windows code page for narrow names and help strings; defaults to the code page implied by each library's LCID, or 1252 for neutral LCIDs",
    ),
});
export type InspectComTypelibInput = z.infer<
  typeof inspectComTypelibInputSchema
>;

const versionSchema = z.strictObject({ major: u16, minor: u16 });

/**
 * A user-defined type reference. `local` indexes `type_infos` in the same
 * library; `imported` names the import by its `imports` index and the target
 * by GUID or by type index inside the imported library, as the file records it.
 */
const typeRefSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("local"),
    hreftype: uint,
    type_index: uint,
    name: text,
  }),
  z.strictObject({
    kind: z.literal("imported"),
    hreftype: uint,
    import_index: uint.nullable(),
    guid: guidSchema.nullable(),
    type_index: uint.nullable(),
  }),
  z.strictObject({ kind: z.literal("unresolved"), hreftype: uint }),
]);

/** IDL-like spelling plus the innermost user-defined reference, when any. */
const typeDescSchema = z.strictObject({
  vt: z.string().min(1),
  text: z.string().min(1),
  ref: typeRefSchema.nullable(),
});

const valueSchema = z.strictObject({
  vt: z.string().min(1),
  value: z.union([z.number(), z.string()]).nullable(),
});

const flagsSchema = z.array(z.string().min(1));

const parameterSchema = z.strictObject({
  name: text,
  type: typeDescSchema,
  flags_value: u16,
  flags: flagsSchema,
  default_value: valueSchema.nullable(),
});

const functionSchema = z.strictObject({
  memid: int32,
  name: text,
  func_kind: z.string().min(1),
  invoke_kind: z.string().min(1),
  call_conv: z.string().min(1),
  vtable_offset: z.number().int().min(-0x8000).max(0xffff),
  flags_value: u16,
  flags: flagsSchema,
  return_type: typeDescSchema,
  parameters: z.array(parameterSchema),
  optional_parameters: z.number().int().min(-0x8000).max(0x7fff),
  doc_string: text,
  help_context: uint,
  entry: z.union([z.string(), uint]).nullable(),
  location: range,
});

const variableSchema = z.strictObject({
  memid: int32,
  name: text,
  var_kind: z.string().min(1),
  type: typeDescSchema,
  flags_value: u16,
  flags: flagsSchema,
  value: valueSchema.nullable(),
  instance_offset: uint.nullable(),
  doc_string: text,
  help_context: uint,
  location: range,
});

const implementedSchema = z.strictObject({
  ref: typeRefSchema,
  flags_value: uint,
  flags: flagsSchema,
});

const typeInfoSchema = z.strictObject({
  index: uint,
  kind: z.enum([
    "enum",
    "record",
    "module",
    "interface",
    "dispatch",
    "coclass",
    "alias",
    "union",
    "unknown",
  ]),
  kind_value: uint,
  name: text,
  guid: guidSchema.nullable(),
  version: versionSchema,
  flags_value: uint,
  flags: flagsSchema,
  doc_string: text,
  help_context: uint,
  size: uint,
  alignment: uint,
  vtable_bytes: u16,
  implemented: z.array(implementedSchema),
  alias_of: typeDescSchema.nullable(),
  dll_name: text,
  prog_ids: z
    .array(z.string().min(1))
    .describe(
      "ProgIDs that registration scripts in the same artifact declare for this coclass GUID",
    ),
  function_count: u16,
  variable_count: u16,
  members_reported: z.boolean(),
  functions: z.array(functionSchema),
  variables: z.array(variableSchema),
  location: range,
});

const issueSchema = z.strictObject({
  code: z.enum([
    "malformed_entry",
    "unreadable",
    "unsupported_form",
    "inconsistent",
  ]),
  location: z.string().min(1).nullable(),
  message: z.string().min(1),
});

const importSchema = z.strictObject({
  index: uint,
  guid: guidSchema.nullable(),
  file_name: text,
  version: versionSchema,
  lcid: uint,
});

const sourceSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("file") }),
  z.strictObject({
    kind: z.literal("pe-resource"),
    resource_index: uint,
    resource_name: z.string(),
    language: uint.nullable(),
  }),
]);

const librarySchema = z.strictObject({
  index: uint,
  source: sourceSchema,
  location: range,
  sha256: digestSchema,
  format: z.enum(["msft", "sltg", "unknown"]),
  status: z.enum(["decoded", "partial", "unsupported"]),
  name: text,
  guid: guidSchema.nullable(),
  version: versionSchema.nullable(),
  lcid: uint.nullable(),
  syskind: z.enum(["win16", "win32", "mac", "win64", "unknown"]).nullable(),
  flags_value: uint.nullable(),
  flags: flagsSchema,
  doc_string: text,
  help_file: text,
  help_context: uint.nullable(),
  string_code_page: z
    .strictObject({
      code_page: uint,
      source: z.enum(["caller", "lcid", "default"]),
    })
    .nullable(),
  imports: z.array(importSchema),
  type_infos: z.array(typeInfoSchema),
  issues: z.array(issueSchema),
});

const registrationSchema = z.strictObject({
  resource_index: uint,
  location: range,
  classes: z.array(
    z.strictObject({
      clsid: guidSchema,
      name: text,
      prog_id: text,
      version_independent_prog_id: text,
      typelib: guidSchema.nullable(),
    }),
  ),
  prog_ids: z.array(
    z.strictObject({ prog_id: z.string().min(1), clsid: guidSchema }),
  ),
  issues: z.array(issueSchema),
});

/** Static COM type library inventory read without loading, registering or executing the target. */
export const comTypelibSchema = z.strictObject({
  artifact: z.strictObject({
    path: z.string().min(1),
    sha256: digestSchema,
    bytes: uint,
  }),
  container: z.enum(["typelib", "pe32", "pe32-plus"]),
  libraries: z.array(librarySchema),
  registration_scripts: z.array(registrationSchema),
  unmatched_type_names: z.array(z.string()),
  coverage: z.strictObject({
    status: z.enum(["complete", "partial"]),
    reason: z.string().min(1).nullable(),
    libraries: uint,
    type_infos: uint,
    functions: uint,
    variables: uint,
    reported_members: uint,
  }),
  limitations: z.array(z.string().min(1)),
});

export type ComTypelib = z.infer<typeof comTypelibSchema>;
export type ComTypelibLibrary = z.infer<typeof librarySchema>;
export type ComTypeInfo = z.infer<typeof typeInfoSchema>;
export type ComTypeDesc = z.infer<typeof typeDescSchema>;
export type ComTypeRef = z.infer<typeof typeRefSchema>;
export type ComFunction = z.infer<typeof functionSchema>;
export type ComVariable = z.infer<typeof variableSchema>;
export type ComValue = z.infer<typeof valueSchema>;
export type ComTypelibIssue = z.infer<typeof issueSchema>;
export type ComRegistrationScript = z.infer<typeof registrationSchema>;
