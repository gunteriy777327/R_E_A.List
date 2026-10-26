import type {
  ComTypeInfo,
  ComTypelibLibrary,
} from "../../domain/native/comTypelib.js";
import { decoderFor, lcidCodePage } from "./ComCodePages.js";
import { MsftTypes } from "./MsftTypeDescriptions.js";
import { decodeFunctions, decodeVariables } from "./MsftTypelibMembers.js";
import {
  MalformedTypelib,
  MsftReader,
  type ComTypelibBudget,
  type Segment,
} from "./MsftTypelibReader.js";
import {
  HEADER_BYTES,
  HELP_DLL_FLAG,
  IMPL_FLAGS,
  LIB_FLAGS,
  MSFT_MAGIC,
  REF_RECORD_BYTES,
  SEGMENT,
  SEGMENTS,
  SEGMENT_BYTES,
  SYSKINDS,
  TYPEINFO_BYTES,
  TYPE_FLAGS,
  TYPE_KINDS,
  flagNames,
} from "./MsftTypelibTables.js";

export {
  ComTypelibLimitFailure,
  type ComTypelibBudget,
  type ComTypelibLimit,
} from "./MsftTypelibReader.js";
export { MSFT_MAGIC, SLTG_MAGIC } from "./MsftTypelibTables.js";

export interface MsftDecodeOptions {
  /** Absolute file offset of the type library inside the artifact. */
  readonly baseOffset: number;
  readonly codePage: number | undefined;
  readonly includeMembers: (name: string | null) => boolean;
  readonly budget: ComTypelibBudget;
  readonly signal?: AbortSignal;
}

export type DecodedTypelib = Omit<
  ComTypelibLibrary,
  "index" | "source" | "location" | "sha256"
>;

const emptyLibrary = (reader: MsftReader): DecodedTypelib => ({
  format: "msft",
  status: "decoded",
  name: null,
  guid: null,
  version: null,
  lcid: null,
  syskind: null,
  flags_value: null,
  flags: [],
  doc_string: null,
  help_file: null,
  help_context: null,
  string_code_page: null,
  imports: [],
  type_infos: [],
  issues: reader.issues,
});

const version = (value: number) => ({
  major: value & 0xffff,
  minor: (value >>> 16) & 0xffff,
});

/** Header, type-info count and segment directory; segments outside the file are ignored. */
const readHeader = (reader: MsftReader) => {
  if (reader.u32(0) !== MSFT_MAGIC) reader.fail("Missing MSFT magic.");
  reader.need(0, HEADER_BYTES);
  const varflags = reader.i32(0x14);
  const typeInfoCount = reader.i32(0x20);
  if (typeInfoCount < 0) reader.fail("Negative type-info count.");
  const offsetsAt = HEADER_BYTES + ((varflags & HELP_DLL_FLAG) !== 0 ? 4 : 0);
  const segmentsAt = offsetsAt + typeInfoCount * 4;
  reader.need(segmentsAt, SEGMENTS * SEGMENT_BYTES);
  const segments: Segment[] = [];
  for (let index = 0; index < SEGMENTS; index += 1) {
    const at = segmentsAt + index * SEGMENT_BYTES;
    const offset = reader.i32(at);
    const length = reader.i32(at + 4);
    const outside = offset > reader.bytes.length - length;
    segments.push(
      offset < 0 || length <= 0 || outside
        ? { offset: -1, length: 0 }
        : { offset, length },
    );
    if (offset >= 0 && length > 0 && outside && index <= SEGMENT.custData)
      reader.issue(
        "malformed_entry",
        at,
        `Segment ${String(index)} leaves the type library and was ignored.`,
      );
  }
  return { varflags, typeInfoCount, segments };
};

const readLibraryFacts = (
  reader: MsftReader,
  result: DecodedTypelib,
  options: MsftDecodeOptions,
  varflags: number,
): void => {
  const lcid = reader.u32(0x0c);
  const implied = lcidCodePage(lcid);
  result.string_code_page =
    options.codePage !== undefined
      ? { code_page: options.codePage, source: "caller" }
      : implied === null
        ? { code_page: 1252, source: "default" }
        : { code_page: implied, source: "lcid" };
  reader.decoder = decoderFor(result.string_code_page.code_page);
  result.lcid = lcid;
  result.syskind = SYSKINDS[varflags & 0xf] ?? "unknown";
  result.version = version(reader.i32(0x18));
  result.flags_value = reader.u32(0x1c);
  result.flags = flagNames(result.flags_value, LIB_FLAGS);
  result.help_context = reader.u32(0x2c);
  result.guid = reader.optional(
    () => reader.guid(reader.i32(0x08)),
    0x08,
    "Library GUID",
  );
  result.name = reader.optional(
    () => reader.name(reader.i32(0x38)),
    0x38,
    "Library name",
  );
  result.doc_string = reader.optional(
    () => reader.string(reader.i32(0x24)),
    0x24,
    "Library help string",
  );
  result.help_file = reader.optional(
    () => reader.string(reader.i32(0x3c)),
    0x3c,
    "Library help file",
  );
};

/** Import-file records: GUID offset, LCID, version, then a length-coded file name. */
const readImports = (
  reader: MsftReader,
  result: DecodedTypelib,
): Map<number, number> => {
  const byOffset = new Map<number, number>();
  const files = reader.segment(SEGMENT.impFiles);
  let relative = 0;
  while (files.offset >= 0 && relative < files.length) {
    const start = files.offset + relative;
    const next = reader.recover(
      start,
      "Imported library record",
      () => {
        reader.inSegment(SEGMENT.impFiles, relative, 16);
        const size = reader.u16(start + 12) >> 2;
        reader.inSegment(SEGMENT.impFiles, relative, 14 + size);
        byOffset.set(relative, result.imports.length);
        result.imports.push({
          index: result.imports.length,
          guid: reader.optional(
            () => reader.guid(reader.i32(start)),
            start,
            "Imported library GUID",
          ),
          lcid: reader.u32(start + 4),
          version: {
            major: reader.u16(start + 8),
            minor: reader.u16(start + 10),
          },
          file_name: reader.text(start + 14, size),
        });
        return (relative + 14 + size + 3) & ~3;
      },
      null,
    );
    if (next === null) break;
    relative = next;
  }
  return byOffset;
};

/** Names of every readable type info; stops at the first record outside its segment. */
const readTypeNames = (
  reader: MsftReader,
  typeInfoCount: number,
): (string | null)[] => {
  const names: (string | null)[] = [];
  for (let index = 0; index < typeInfoCount; index += 1) {
    const base = reader.recover(
      null,
      `Type info ${String(index)} of ${String(typeInfoCount)}`,
      () =>
        reader.inSegment(
          SEGMENT.typeInfo,
          index * TYPEINFO_BYTES,
          TYPEINFO_BYTES,
        ),
      null,
    );
    if (base === null) break;
    names.push(
      reader.optional(
        () => reader.name(reader.i32(base + 0x34)),
        base + 0x34,
        "Type name",
      ),
    );
  }
  return names;
};

/** Coclass interfaces follow a reference-record chain; other kinds name one base. */
const readImplemented = (
  types: MsftTypes,
  info: ComTypeInfo,
  base: number,
): void => {
  const reader = types.reader;
  const count = reader.i16(base + 0x4c);
  const datatype1 = reader.i32(base + 0x54);
  if (info.kind === "alias") info.alias_of = types.describe(datatype1);
  if (info.kind === "module")
    info.dll_name = reader.optional(
      () => reader.string(datatype1),
      base + 0x54,
      "Module DLL name",
    );
  if (count <= 0 || info.kind === "alias") return;
  if (info.kind !== "coclass") {
    if (datatype1 !== -1)
      info.implemented.push({
        ref: types.reference(datatype1),
        flags_value: 0,
        flags: [],
      });
    return;
  }
  let next = datatype1;
  for (let item = 0; item < count && next >= 0; item += 1) {
    const record = reader.inSegment(SEGMENT.refTab, next, REF_RECORD_BYTES);
    const flags = reader.i32(record + 4) >>> 0;
    info.implemented.push({
      ref: types.reference(reader.i32(record)),
      flags_value: flags,
      flags: flagNames(flags, IMPL_FLAGS),
    });
    next = reader.i32(record + 12);
  }
  if (info.implemented.length !== count)
    reader.issue(
      "inconsistent",
      base + 0x4c,
      `Coclass declares ${String(count)} implemented interfaces but its reference chain holds ${String(info.implemented.length)}.`,
    );
};

const readTypeInfo = async (
  types: MsftTypes,
  index: number,
  options: MsftDecodeOptions,
): Promise<ComTypeInfo> => {
  const reader = types.reader;
  const base = reader.inSegment(
    SEGMENT.typeInfo,
    index * TYPEINFO_BYTES,
    TYPEINFO_BYTES,
  );
  const typekind = reader.i32(base);
  const elements = reader.u32(base + 0x18);
  const flagsValue = reader.u32(base + 0x30);
  const info: ComTypeInfo = {
    index,
    kind: TYPE_KINDS[typekind & 0xf] ?? "unknown",
    kind_value: typekind & 0xf,
    name: types.typeNames[index] ?? null,
    guid: reader.optional(
      () => reader.guid(reader.i32(base + 0x2c)),
      base + 0x2c,
      "Type GUID",
    ),
    version: version(reader.i32(base + 0x38)),
    flags_value: flagsValue,
    flags: flagNames(flagsValue, TYPE_FLAGS),
    doc_string: reader.optional(
      () => reader.string(reader.i32(base + 0x3c)),
      base + 0x3c,
      "Type help string",
    ),
    help_context: reader.u32(base + 0x44),
    size: reader.u32(base + 0x50),
    alignment: (typekind >> 11) & 0x1f,
    vtable_bytes: reader.u16(base + 0x4e),
    implemented: [],
    alias_of: null,
    dll_name: null,
    prog_ids: [],
    function_count: elements & 0xffff,
    variable_count: elements >>> 16,
    members_reported: false,
    functions: [],
    variables: [],
    location: { offset: reader.baseOffset + base, bytes: TYPEINFO_BYTES },
  };
  reader.recover(
    base,
    `Type info ${String(index)} references`,
    () => readImplemented(types, info, base),
    undefined,
  );
  const area = {
    memoffset: reader.i32(base + 0x04),
    functions: info.function_count,
    variables: info.variable_count,
  };
  if (
    !options.includeMembers(info.name) ||
    area.functions + area.variables === 0
  )
    return info;
  options.budget.takeMembers(area.functions + area.variables);
  info.members_reported = true;
  try {
    reader.need(area.memoffset, 4);
    if (area.functions > 0)
      info.functions = await decodeFunctions(types, area, options.signal);
    if (area.variables > 0)
      info.variables = await decodeVariables(types, area, options.signal);
  } catch (cause) {
    if (!(cause instanceof MalformedTypelib)) throw cause;
    reader.issue(
      cause.code,
      area.memoffset,
      `Type info ${String(index)} members: ${cause.message}`,
    );
  }
  return info;
};

/**
 * Decode one MSFT type library, following the layout Wine's `typelib.c`
 * reads. Header failures leave library facts null; a failing type info or
 * member is reported as an issue while earlier and later entries survive.
 */
export const decodeMsftTypelib = async (
  bytes: Buffer,
  options: MsftDecodeOptions,
): Promise<DecodedTypelib> => {
  const reader = new MsftReader(bytes, options.baseOffset, options.budget);
  const result = emptyLibrary(reader);
  const header = reader.recover(
    0,
    "Library header",
    () => readHeader(reader),
    null,
  );
  if (header === null) {
    result.status = "partial";
    return result;
  }
  reader.segments = header.segments;
  readLibraryFacts(reader, result, options, header.varflags);
  const importsByOffset = readImports(reader, result);
  const typeNames = readTypeNames(reader, header.typeInfoCount);
  const types = new MsftTypes(
    reader,
    importsByOffset,
    typeNames,
    result.imports.map(({ file_name }) => file_name),
  );
  for (let index = 0; index < typeNames.length; index += 1)
    result.type_infos.push(await readTypeInfo(types, index, options));
  if (reader.issues.length > 0) result.status = "partial";
  return result;
};
