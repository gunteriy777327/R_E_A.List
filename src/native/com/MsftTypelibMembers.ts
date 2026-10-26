import { setImmediate } from "node:timers/promises";
import { assertArtifactReadActive } from "../../artifacts/ArtifactFileOperation.js";
import type {
  ComFunction,
  ComVariable,
} from "../../domain/native/comTypelib.js";
import type { MsftTypes } from "./MsftTypeDescriptions.js";
import { MalformedTypelib } from "./MsftTypelibReader.js";
import {
  CALL_CONVS,
  FUNC_FIXED_BYTES,
  FUNC_FLAGS,
  FUNC_KINDS,
  INVOKE_KINDS,
  MEMBERS_PER_YIELD,
  PARAMETER_BYTES,
  PARAM_FLAGS,
  VAR_FIXED_BYTES,
  VAR_FLAGS,
  VAR_KINDS,
  flagNames,
  isProperty,
} from "./MsftTypelibTables.js";

const FUNC_HAS_DEFAULTS = 0x1000;
const FUNC_ENTRY_IS_ORDINAL = 0x2000;
const PARAM_HAS_DEFAULT = 0x20;
const VAR_CONST = 2;
const VAR_PER_INSTANCE = 0;

/**
 * A type info's member area: a length-prefixed run of function then variable
 * records, followed by parallel tables of member IDs, name offsets and record
 * offsets, functions first. This is the layout Wine's `MSFT_DoFuncs` reads.
 */
export interface MemberArea {
  readonly memoffset: number;
  readonly functions: number;
  readonly variables: number;
}

const yieldEvery = (signal: AbortSignal | undefined) => {
  let decoded = 0;
  return async () => {
    decoded += 1;
    if (decoded % MEMBERS_PER_YIELD !== 0) return;
    await setImmediate();
    assertArtifactReadActive(signal);
  };
};

const tables = (types: MsftTypes, area: MemberArea) => {
  const end = area.memoffset + 4 + types.reader.i32(area.memoffset);
  return { recordsEnd: end, table: end };
};

/** Decode one function record at `record`; returns the record length. */
const decodeFunction = (
  types: MsftTypes,
  area: MemberArea,
  { index, record }: { readonly index: number; readonly record: number },
  previous: { decoded: ComFunction; invokeKind: number } | undefined,
): { decoded: ComFunction; invokeKind: number } => {
  const reader = types.reader;
  const { recordsEnd, table } = tables(types, area);
  const length = reader.i32(record) & 0xffff;
  if (length < FUNC_FIXED_BYTES || record + length > recordsEnd)
    reader.fail(
      `Function record length ${String(length)} is outside its member area.`,
    );
  reader.need(record, length);
  const fkccic = reader.i32(record + 16);
  const parameterCount = reader.i16(record + 20);
  if (parameterCount < 0) reader.fail("Negative parameter count.");
  const parameterBytes = parameterCount * PARAMETER_BYTES;
  const defaultBytes =
    (fkccic & FUNC_HAS_DEFAULTS) !== 0 ? parameterCount * 4 : 0;
  const fixedEnd = length - parameterBytes - defaultBytes;
  if (fixedEnd < FUNC_FIXED_BYTES)
    reader.fail("Parameter descriptions overlap the fixed function record.");
  // Optional fields are present only when the fixed part extends past them.
  const has = (fieldOffset: number) => fixedEnd > fieldOffset;
  const invokeKind = (fkccic >> 3) & 0xf;
  const callConv = (fkccic >> 8) & 0xf;
  const flagsValue = reader.i32(record + 8) & 0xffff;
  const nameOffset = reader.i32(
    table + (area.functions + area.variables + index) * 4,
  );
  const parameters: ComFunction["parameters"] = [];
  for (let parameter = 0; parameter < parameterCount; parameter += 1) {
    const at = record + length - parameterBytes + parameter * PARAMETER_BYTES;
    const flags = reader.i32(at + 8) & 0xffff;
    parameters.push({
      name: reader.name(reader.i32(at + 4)),
      type: types.describe(reader.i32(at)),
      flags_value: flags,
      flags: flagNames(flags, PARAM_FLAGS),
      default_value:
        (flags & PARAM_HAS_DEFAULT) !== 0 && defaultBytes > 0
          ? types.value(reader.i32(record + fixedEnd + parameter * 4))
          : null,
    });
  }
  const entry = (): ComFunction["entry"] => {
    if (!has(32)) return null;
    if ((fkccic & FUNC_ENTRY_IS_ORDINAL) !== 0)
      return reader.i32(record + 32) & 0xffff;
    return reader.optional(
      () => reader.string(reader.i32(record + 32)),
      record + 32,
      "Function entry",
    );
  };
  const decoded: ComFunction = {
    memid: reader.i32(table + index * 4),
    // The second half of a property accessor pair may omit its name.
    name:
      nameOffset === -1 &&
      previous !== undefined &&
      isProperty(invokeKind) &&
      isProperty(previous.invokeKind)
        ? previous.decoded.name
        : reader.name(nameOffset),
    func_kind: FUNC_KINDS[fkccic & 0x7] ?? `funckind-${String(fkccic & 0x7)}`,
    invoke_kind: INVOKE_KINDS[invokeKind] ?? `invokekind-${String(invokeKind)}`,
    call_conv: CALL_CONVS[callConv] ?? `callconv-${String(callConv)}`,
    vtable_offset: reader.i16(record + 12) & ~1,
    flags_value: flagsValue,
    flags: flagNames(flagsValue, FUNC_FLAGS),
    return_type: types.describe(reader.i32(record + 4)),
    parameters,
    optional_parameters: reader.i16(record + 22),
    help_context: has(24) ? reader.u32(record + 24) : 0,
    doc_string: has(28)
      ? reader.optional(
          () => reader.string(reader.i32(record + 28)),
          record + 28,
          "Function help string",
        )
      : null,
    entry: entry(),
    location: { offset: reader.baseOffset + record, bytes: length },
  };
  return { decoded, invokeKind };
};

/** Functions in record order; a malformed record ends the run with an issue. */
export const decodeFunctions = async (
  types: MsftTypes,
  area: MemberArea,
  signal?: AbortSignal,
): Promise<ComFunction[]> => {
  const functions: ComFunction[] = [];
  const reader = types.reader;
  const yieldPoint = yieldEvery(signal);
  let record = area.memoffset + 4;
  let previous: { decoded: ComFunction; invokeKind: number } | undefined;
  for (let index = 0; index < area.functions; index += 1) {
    try {
      previous = decodeFunction(types, area, { index, record }, previous);
    } catch (cause) {
      if (!(cause instanceof MalformedTypelib)) throw cause;
      reader.issue(
        cause.code,
        record,
        `Function ${String(index)}: ${cause.message}`,
      );
      break;
    }
    functions.push(previous.decoded);
    record += previous.decoded.location.bytes;
    await yieldPoint();
  }
  return functions;
};

const decodeVariable = (
  types: MsftTypes,
  area: MemberArea,
  index: number,
  record: number,
): ComVariable => {
  const reader = types.reader;
  const { recordsEnd, table } = tables(types, area);
  const length = reader.i32(record) & 0xff;
  if (length < VAR_FIXED_BYTES || record + length > recordsEnd)
    reader.fail(
      `Variable record length ${String(length)} is outside its member area.`,
    );
  reader.need(record, length);
  const flagsValue = reader.i32(record + 8) & 0xffff;
  const kind = reader.i16(record + 12);
  const offsValue = reader.i32(record + 16);
  return {
    memid: reader.i32(table + (area.functions + index) * 4),
    name: reader.name(
      reader.i32(table + (2 * area.functions + area.variables + index) * 4),
    ),
    var_kind: VAR_KINDS[kind] ?? `varkind-${String(kind)}`,
    type: types.describe(reader.i32(record + 4)),
    flags_value: flagsValue,
    flags: flagNames(flagsValue, VAR_FLAGS),
    value: kind === VAR_CONST ? types.value(offsValue) : null,
    instance_offset:
      kind === VAR_PER_INSTANCE && offsValue >= 0 ? offsValue : null,
    help_context: length > 20 ? reader.u32(record + 20) : 0,
    doc_string:
      length > 24
        ? reader.optional(
            () => reader.string(reader.i32(record + 24)),
            record + 24,
            "Variable help string",
          )
        : null,
    location: { offset: reader.baseOffset + record, bytes: length },
  };
};

/** Variables start at the record offset the first variable's table slot names. */
export const decodeVariables = async (
  types: MsftTypes,
  area: MemberArea,
  signal?: AbortSignal,
): Promise<ComVariable[]> => {
  const variables: ComVariable[] = [];
  const reader = types.reader;
  const yieldPoint = yieldEvery(signal);
  const { table } = tables(types, area);
  const members = area.functions + area.variables;
  let record =
    area.memoffset + 4 + reader.i32(table + (members * 2 + area.functions) * 4);
  for (let index = 0; index < area.variables; index += 1) {
    let decoded: ComVariable;
    try {
      decoded = decodeVariable(types, area, index, record);
    } catch (cause) {
      if (!(cause instanceof MalformedTypelib)) throw cause;
      reader.issue(
        cause.code,
        record,
        `Variable ${String(index)}: ${cause.message}`,
      );
      break;
    }
    variables.push(decoded);
    record += decoded.location.bytes;
    await yieldPoint();
  }
  return variables;
};
