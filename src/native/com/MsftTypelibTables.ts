/** `MSFT` little-endian magic of an OLE Automation type library. */
export const MSFT_MAGIC = 0x5446534d;
/** `SLTG` magic of the older compressed type-library form. */
export const SLTG_MAGIC = 0x47544c53;

export const HEADER_BYTES = 0x54;
export const SEGMENT_BYTES = 16;
export const SEGMENTS = 15;
export const TYPEINFO_BYTES = 0x64;
export const GUID_ENTRY_BYTES = 24;
export const NAME_INTRO_BYTES = 12;
export const PARAMETER_BYTES = 12;
export const REF_RECORD_BYTES = 16;
export const IMPINFO_BYTES = 12;
export const FUNC_FIXED_BYTES = 24;
export const VAR_FIXED_BYTES = 20;
export const HELP_DLL_FLAG = 0x100;
export const IMPINFO_OFFSET_IS_GUID = 0x10000;
export const TYPEDESC_DEPTH = 32;
/** Members decoded between event-loop yields and cancellation checks. */
export const MEMBERS_PER_YIELD = 512;

export const SEGMENT = {
  typeInfo: 0,
  impInfo: 1,
  impFiles: 2,
  refTab: 3,
  guidTab: 5,
  nameTab: 7,
  stringTab: 8,
  typeDescTab: 9,
  arrayDescTab: 10,
  custData: 11,
} as const;

const VT_NAMES: Readonly<Record<number, string>> = {
  0: "EMPTY",
  1: "NULL",
  2: "I2",
  3: "I4",
  4: "R4",
  5: "R8",
  6: "CY",
  7: "DATE",
  8: "BSTR",
  9: "DISPATCH",
  10: "ERROR",
  11: "BOOL",
  12: "VARIANT",
  13: "UNKNOWN",
  14: "DECIMAL",
  16: "I1",
  17: "UI1",
  18: "UI2",
  19: "UI4",
  20: "I8",
  21: "UI8",
  22: "INT",
  23: "UINT",
  24: "VOID",
  25: "HRESULT",
  26: "PTR",
  27: "SAFEARRAY",
  28: "CARRAY",
  29: "USERDEFINED",
  30: "LPSTR",
  31: "LPWSTR",
  36: "RECORD",
  37: "INT_PTR",
  38: "UINT_PTR",
  64: "FILETIME",
  65: "BLOB",
  66: "STREAM",
  67: "STORAGE",
  68: "STREAMED_OBJECT",
  69: "STORED_OBJECT",
  70: "BLOB_OBJECT",
  71: "CF",
  72: "CLSID",
};

/** IDL spellings of automation base types; other VTs keep their VT name. */
export const VT_IDL: Readonly<Record<number, string>> = {
  2: "short",
  3: "long",
  4: "single",
  5: "double",
  6: "CURRENCY",
  7: "DATE",
  8: "BSTR",
  9: "IDispatch*",
  10: "SCODE",
  11: "VARIANT_BOOL",
  12: "VARIANT",
  13: "IUnknown*",
  14: "DECIMAL",
  16: "char",
  17: "unsigned char",
  18: "unsigned short",
  19: "unsigned long",
  20: "int64",
  21: "uint64",
  22: "int",
  23: "unsigned int",
  24: "void",
  25: "HRESULT",
  30: "LPSTR",
  31: "LPWSTR",
  37: "INT_PTR",
  38: "UINT_PTR",
};

export const isProperty = (kind: number): boolean =>
  kind === 2 || kind === 4 || kind === 8;

export const vtName = (vt: number): string =>
  VT_NAMES[vt] ?? `VT_${String(vt)}`;

export const TYPE_KINDS = [
  "enum",
  "record",
  "module",
  "interface",
  "dispatch",
  "coclass",
  "alias",
  "union",
] as const;
export const SYSKINDS = ["win16", "win32", "mac", "win64"] as const;
export const FUNC_KINDS = [
  "virtual",
  "pure-virtual",
  "non-virtual",
  "static",
  "dispatch",
];
export const INVOKE_KINDS: Readonly<Record<number, string>> = {
  1: "func",
  2: "propget",
  4: "propput",
  8: "propputref",
};
export const CALL_CONVS: Readonly<Record<number, string>> = {
  0: "fastcall",
  1: "cdecl",
  2: "pascal",
  3: "macpascal",
  4: "stdcall",
  5: "fpfastcall",
  6: "syscall",
  7: "mpwcdecl",
  8: "mpwpascal",
};
export const VAR_KINDS = ["per-instance", "static", "const", "dispatch"];

export const LIB_FLAGS = ["restricted", "control", "hidden", "hasdiskimage"];
export const TYPE_FLAGS = [
  "appobject",
  "cancreate",
  "licensed",
  "predeclid",
  "hidden",
  "control",
  "dual",
  "nonextensible",
  "oleautomation",
  "restricted",
  "aggregatable",
  "replaceable",
  "dispatchable",
  "reversebind",
  "proxy",
];
export const FUNC_FLAGS = [
  "restricted",
  "source",
  "bindable",
  "requestedit",
  "displaybind",
  "defaultbind",
  "hidden",
  "usesgetlasterror",
  "defaultcollelem",
  "uidefault",
  "nonbrowsable",
  "replaceable",
  "immediatebind",
];
export const VAR_FLAGS = [
  "readonly",
  "source",
  "bindable",
  "requestedit",
  "displaybind",
  "defaultbind",
  "hidden",
  "restricted",
  "defaultcollelem",
  "uidefault",
  "nonbrowsable",
  "replaceable",
  "immediatebind",
];
export const PARAM_FLAGS = [
  "in",
  "out",
  "lcid",
  "retval",
  "optional",
  "hasdefault",
  "hascustdata",
];
export const IMPL_FLAGS = ["default", "source", "restricted", "defaultvtable"];

/** Named bits of a flag word; unnamed set bits keep their hexadecimal value. */
export const flagNames = (
  value: number,
  names: readonly string[],
): string[] => {
  const result: string[] = [];
  for (let bit = 0; bit < 32; bit += 1) {
    const mask = 2 ** bit;
    if (Math.floor(value / mask) % 2 === 0) continue;
    result.push(names[bit] ?? `0x${mask.toString(16)}`);
  }
  return result;
};

/** Canonical registry spelling of a little-endian GUID. */
export const formatGuid = (bytes: Buffer, at: number): string => {
  const hex = (start: number, end: number) =>
    bytes.subarray(start, end).toString("hex");
  const data1 = bytes.readUInt32LE(at).toString(16).padStart(8, "0");
  const data2 = bytes
    .readUInt16LE(at + 4)
    .toString(16)
    .padStart(4, "0");
  const data3 = bytes
    .readUInt16LE(at + 6)
    .toString(16)
    .padStart(4, "0");
  return `{${data1}-${data2}-${data3}-${hex(at + 8, at + 10)}-${hex(at + 10, at + 16)}}`.toUpperCase();
};
