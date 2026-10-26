import type {
  ComTypeDesc,
  ComTypeRef,
  ComValue,
} from "../../domain/native/comTypelib.js";
import { MalformedTypelib, type MsftReader } from "./MsftTypelibReader.js";
import {
  IMPINFO_BYTES,
  IMPINFO_OFFSET_IS_GUID,
  SEGMENT,
  TYPEDESC_DEPTH,
  TYPEINFO_BYTES,
  VT_IDL,
  vtName,
} from "./MsftTypelibTables.js";

const VT_PTR = 26;
const VT_SAFEARRAY = 27;
const VT_CARRAY = 28;
const VT_USERDEFINED = 29;

const baseType = (vt: number): ComTypeDesc => ({
  vt: vtName(vt),
  text: VT_IDL[vt] ?? vtName(vt),
  ref: null,
});

/** Fixed-size custom-data values, keyed by VT: byte count and reader. */
const FIXED_VALUES: Readonly<
  Record<
    number,
    readonly [number, (bytes: Buffer, at: number) => number | string]
  >
> = {
  2: [4, (bytes, at) => bytes.readInt16LE(at)],
  3: [4, (bytes, at) => bytes.readInt32LE(at)],
  4: [4, (bytes, at) => bytes.readFloatLE(at)],
  5: [8, (bytes, at) => bytes.readDoubleLE(at)],
  6: [8, (bytes, at) => currency(bytes.readBigInt64LE(at))],
  7: [8, (bytes, at) => bytes.readDoubleLE(at)],
  10: [4, (bytes, at) => bytes.readInt32LE(at)],
  11: [4, (bytes, at) => bytes.readInt16LE(at)],
  16: [4, (bytes, at) => bytes.readInt8(at)],
  17: [4, (bytes, at) => bytes.readUInt8(at)],
  18: [4, (bytes, at) => bytes.readUInt16LE(at)],
  19: [4, (bytes, at) => bytes.readUInt32LE(at)],
  20: [8, (bytes, at) => bytes.readBigInt64LE(at).toString()],
  21: [8, (bytes, at) => bytes.readBigUInt64LE(at).toString()],
  22: [4, (bytes, at) => bytes.readInt32LE(at)],
  23: [4, (bytes, at) => bytes.readUInt32LE(at)],
  25: [4, (bytes, at) => bytes.readInt32LE(at)],
};

/** CURRENCY is a 64-bit integer scaled by 10,000; keep it exact as decimal text. */
const currency = (scaled: bigint): string => {
  const sign = scaled < 0n ? "-" : "";
  const magnitude = scaled < 0n ? -scaled : scaled;
  return `${sign}${(magnitude / 10000n).toString()}.${(magnitude % 10000n).toString().padStart(4, "0")}`;
};

/** Decodes type descriptions, references and constant values of one library. */
export class MsftTypes {
  readonly #descriptions = new Map<number, ComTypeDesc>();

  constructor(
    readonly reader: MsftReader,
    /** Import index by its offset in the import-file segment. */
    readonly importsByOffset: ReadonlyMap<number, number>,
    /** Names of the decodable type infos, by index. */
    readonly typeNames: readonly (string | null)[],
    /** Imported library file names, by import index. */
    readonly importNames: readonly (string | null)[],
  ) {}

  /** Local names, imported GUIDs, or `file#index` for imports by position. */
  #refText(ref: ComTypeRef): string {
    if (ref.kind === "local" && ref.name !== null) return ref.name;
    if (ref.kind === "imported" && ref.guid !== null) return ref.guid;
    if (ref.kind === "imported" && ref.type_index !== null) {
      const file =
        ref.import_index === null ? null : this.importNames[ref.import_index];
      return `${file ?? "import"}#${String(ref.type_index)}`;
    }
    return `hreftype 0x${ref.hreftype.toString(16)}`;
  }

  /** Local hreftypes are type-info table offsets; others index import-info records. */
  reference(href: number): ComTypeRef {
    const hreftype = href >>> 0;
    if ((hreftype & 3) === 0) {
      const index = hreftype / TYPEINFO_BYTES;
      return Number.isInteger(index) && index < this.typeNames.length
        ? {
            kind: "local",
            hreftype,
            type_index: index,
            name: this.typeNames[index] ?? null,
          }
        : { kind: "unresolved", hreftype };
    }
    try {
      const reader = this.reader;
      const record = reader.inSegment(
        SEGMENT.impInfo,
        hreftype & ~3,
        IMPINFO_BYTES,
      );
      const byGuid = (reader.i32(record) & IMPINFO_OFFSET_IS_GUID) !== 0;
      const target = reader.i32(record + 8);
      return {
        kind: "imported",
        hreftype,
        import_index: this.importsByOffset.get(reader.i32(record + 4)) ?? null,
        guid: byGuid ? reader.guid(target) : null,
        type_index: byGuid || target < 0 ? null : target,
      };
    } catch (cause) {
      if (!(cause instanceof MalformedTypelib)) throw cause;
      return { kind: "unresolved", hreftype };
    }
  }

  /** Negative encodings carry a base VT; others are type-description table offsets. */
  describe(encoded: number, depth = 0): ComTypeDesc {
    if (encoded < 0) return baseType(encoded & 0xfff);
    const cached = this.#descriptions.get(encoded);
    if (cached !== undefined) return cached;
    const reader = this.reader;
    if (depth > TYPEDESC_DEPTH)
      reader.fail(
        `Type description nesting exceeds ${String(TYPEDESC_DEPTH)}.`,
      );
    if (encoded % 8 !== 0)
      reader.fail(`Unaligned type description ${String(encoded)}.`);
    const entry = reader.inSegment(SEGMENT.typeDescTab, encoded, 8);
    const vt = reader.u16(entry) & 0xfff;
    const value = reader.i32(entry + 4);
    let decoded: ComTypeDesc;
    if (vt === VT_PTR || vt === VT_SAFEARRAY) {
      const inner = this.describe(value, depth + 1);
      decoded = {
        vt: vtName(vt),
        text: vt === VT_PTR ? `${inner.text}*` : `SAFEARRAY(${inner.text})`,
        ref: inner.ref,
      };
    } else if (vt === VT_CARRAY) decoded = this.#array(value, depth);
    else if (vt === VT_USERDEFINED) {
      const ref = this.reference(value);
      decoded = { vt: "USERDEFINED", text: this.#refText(ref), ref };
    } else decoded = baseType(vt);
    this.#descriptions.set(encoded, decoded);
    return decoded;
  }

  /** Array descriptions: element type, dimension count, then count/lower-bound pairs. */
  #array(offset: number, depth: number): ComTypeDesc {
    const reader = this.reader;
    const array = reader.inSegment(SEGMENT.arrayDescTab, offset, 8);
    const element = reader.i32(array);
    const dimensions = reader.u16(array + 4);
    reader.inSegment(SEGMENT.arrayDescTab, offset, 8 + dimensions * 8);
    const inner = this.describe(element, depth + 1);
    let bounds = "";
    for (let index = 0; index < dimensions; index += 1) {
      const elements = reader.u32(array + 8 + index * 8);
      const lower = reader.i32(array + 12 + index * 8);
      bounds +=
        lower === 0
          ? `[${String(elements)}]`
          : `[${String(lower)}..${String(lower + elements - 1)}]`;
    }
    return { vt: "CARRAY", text: `${inner.text}${bounds}`, ref: inner.ref };
  }

  /** Constants and defaults: packed small values, or a VARIANT in custom data. */
  value(encoded: number): ComValue {
    if (encoded < 0)
      // Packed as 0x80000000 | VT << 26 | unsigned 26-bit value.
      return {
        vt: vtName((encoded & 0x7c000000) >>> 26),
        value: encoded & 0x3ffffff,
      };
    const reader = this.reader;
    const start = reader.inSegment(SEGMENT.custData, encoded, 2);
    const vt = reader.u16(start);
    const fixed = FIXED_VALUES[vt];
    if (fixed !== undefined) {
      reader.inSegment(SEGMENT.custData, encoded, 2 + fixed[0]);
      return { vt: vtName(vt), value: fixed[1](reader.bytes, start + 2) };
    }
    if (vt === 8) {
      reader.inSegment(SEGMENT.custData, encoded, 6);
      const length = reader.i32(start + 2);
      if (length < 0) return { vt: "BSTR", value: null };
      reader.inSegment(SEGMENT.custData, encoded, 6 + length);
      return { vt: "BSTR", value: reader.text(start + 6, length) };
    }
    return { vt: vtName(vt), value: null };
  }
}
