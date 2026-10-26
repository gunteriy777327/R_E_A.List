import type { ComTypelibIssue } from "../../domain/native/comTypelib.js";
import { BinaryResourceFailure } from "../metadata/BinaryContainer.js";
import {
  GUID_ENTRY_BYTES,
  NAME_INTRO_BYTES,
  SEGMENT,
  formatGuid,
} from "./MsftTypelibTables.js";

export type ComTypelibLimit = "members" | "retained_text";

/** A caller-selected or fixed decoding allowance was exhausted. */
export class ComTypelibLimitFailure extends BinaryResourceFailure {
  constructor(
    readonly limit: ComTypelibLimit,
    readonly allowance: number,
    message: string,
  ) {
    super("structure", allowance, message);
    this.name = "ComTypelibLimitFailure";
  }
}

/** One structure could not be read; the caller records it and keeps earlier facts. */
export class MalformedTypelib extends Error {
  constructor(
    readonly code: ComTypelibIssue["code"],
    message: string,
  ) {
    super(message);
    this.name = "MalformedTypelib";
  }
}

/** Shared allowances across every library of one artifact. */
export interface ComTypelibBudget {
  /** Account decoded members; throws when the caller budget is exhausted. */
  takeMembers(count: number): void;
  /** Account retained decoded text; throws when the fixed allowance is exhausted. */
  takeText(value: string): void;
}

/** File-relative span of one directory segment; absent segments have offset -1. */
export interface Segment {
  readonly offset: number;
  readonly length: number;
}

/** Bounds-checked reads over one type library, with issue locations in artifact offsets. */
export class MsftReader {
  readonly issues: ComTypelibIssue[] = [];
  segments: readonly Segment[] = [];
  #decoder: TextDecoder | undefined;
  readonly #names = new Map<number, string>();

  constructor(
    readonly bytes: Buffer,
    readonly baseOffset: number,
    readonly budget: ComTypelibBudget,
  ) {}

  set decoder(decoder: TextDecoder) {
    this.#decoder = decoder;
  }

  /** Artifact offset of a library-relative position, as reported in issues. */
  at(offset: number): string {
    return `0x${(this.baseOffset + offset).toString(16)}`;
  }

  issue(
    code: ComTypelibIssue["code"],
    offset: number | null,
    message: string,
  ): void {
    this.issues.push({
      code,
      location: offset === null ? null : this.at(offset),
      message,
    });
  }

  fail(message: string): never {
    throw new MalformedTypelib("malformed_entry", message);
  }

  need(offset: number, length: number): void {
    if (offset < 0 || length < 0 || offset > this.bytes.length - length)
      this.fail(
        `Read of ${String(length)} bytes at ${this.at(offset)} leaves the type library.`,
      );
  }

  i32(offset: number): number {
    this.need(offset, 4);
    return this.bytes.readInt32LE(offset);
  }

  u32(offset: number): number {
    this.need(offset, 4);
    return this.bytes.readUInt32LE(offset);
  }

  i16(offset: number): number {
    this.need(offset, 2);
    return this.bytes.readInt16LE(offset);
  }

  u16(offset: number): number {
    this.need(offset, 2);
    return this.bytes.readUInt16LE(offset);
  }

  /** Library offset of a segment-relative span, refusing spans outside the segment. */
  inSegment(index: number, relative: number, length: number): number {
    const owner = this.segments[index] ?? { offset: -1, length: 0 };
    if (owner.offset < 0 || relative < 0 || relative > owner.length - length)
      this.fail(
        `Offset ${String(relative)} (+${String(length)}) leaves type-library segment ${String(index)}.`,
      );
    return owner.offset + relative;
  }

  segment(index: number): Segment {
    return this.segments[index] ?? { offset: -1, length: 0 };
  }

  /** Narrow text: ASCII as-is, otherwise through the library's code page. */
  text(start: number, length: number): string {
    this.need(start, length);
    const raw = this.bytes.subarray(start, start + length);
    const value =
      this.#decoder === undefined || raw.every((byte) => byte < 0x80)
        ? raw.toString("latin1")
        : this.#decoder.decode(raw);
    this.budget.takeText(value);
    return value;
  }

  /** Name-table entry: hreftype, hash link, then a length-prefixed name. */
  name(offset: number): string | null {
    if (offset < 0) return null;
    const cached = this.#names.get(offset);
    if (cached !== undefined) return cached;
    const intro = this.inSegment(SEGMENT.nameTab, offset, NAME_INTRO_BYTES);
    const length = this.i32(intro + 8) & 0xff;
    this.inSegment(SEGMENT.nameTab, offset, NAME_INTRO_BYTES + length);
    const value = this.text(intro + NAME_INTRO_BYTES, length);
    this.#names.set(offset, value);
    return value;
  }

  /** String-table entry: 16-bit length, then narrow text. */
  string(offset: number): string | null {
    if (offset < 0) return null;
    const start = this.inSegment(SEGMENT.stringTab, offset, 2);
    const length = this.u16(start);
    this.inSegment(SEGMENT.stringTab, offset, 2 + length);
    return this.text(start + 2, length);
  }

  guid(offset: number): string | null {
    if (offset < 0) return null;
    return formatGuid(
      this.bytes,
      this.inSegment(SEGMENT.guidTab, offset, GUID_ENTRY_BYTES),
    );
  }

  /** Run one structural step; a malformed structure becomes an issue and `fallback`. */
  recover<T>(
    offset: number | null,
    context: string,
    step: () => T,
    fallback: T,
  ): T {
    try {
      return step();
    } catch (cause) {
      if (!(cause instanceof MalformedTypelib)) throw cause;
      this.issue(cause.code, offset, `${context}: ${cause.message}`);
      return fallback;
    }
  }

  /** Read optional facts, demoting a bad offset to a recorded issue. */
  optional<T>(read: () => T, offset: number, what: string): T | null {
    try {
      return read();
    } catch (cause) {
      if (!(cause instanceof MalformedTypelib)) throw cause;
      this.issue("unreadable", offset, `${what}: ${cause.message}`);
      return null;
    }
  }
}
