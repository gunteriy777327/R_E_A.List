import type {
  PeResourceIdentity,
  PeResources,
} from "../../domain/native/peResources.js";
import type {
  PeUiString,
  PeUiStringRole,
  PeUiStrings,
} from "../../domain/native/peUiStrings.js";

const RT_MENU = 4;
const RT_DIALOG = 5;
const RT_STRING = 6;
const RT_MESSAGETABLE = 11;
const MF_POPUP = 0x10;
const MF_END = 0x80;
const MFT_SEPARATOR = 0x800;
const DS_SETFONT = 0x40;
/** Templates nest popups; real menus stay a few levels deep. */
const MAX_MENU_DEPTH = 64;

type Resource = PeResources["resources"][number];
type Language = PeUiString["language"];
type Box = NonNullable<PeUiString["box"]>;

/** A template field that does not fit the payload or the conventional layout. */
class TemplateMismatch extends Error {}

/** Little-endian reads over one payload; every offset is payload-relative. */
class PayloadCursor {
  #at = 0;
  constructor(
    readonly bytes: Buffer,
    readonly fileOffset: number,
  ) {}

  get at(): number {
    return this.#at;
  }

  get remaining(): number {
    return this.bytes.length - this.#at;
  }

  seek(at: number): void {
    if (at > this.bytes.length)
      throw new TemplateMismatch(
        `offset ${String(at)} exceeds the ${String(this.bytes.length)}-byte payload`,
      );
    this.#at = at;
  }

  #take(size: number): number {
    if (this.#at + size > this.bytes.length)
      throw new TemplateMismatch(
        `template ends at payload byte ${String(this.#at)} before a ${String(size)}-byte field`,
      );
    const at = this.#at;
    this.#at += size;
    return at;
  }

  u8 = (): number => this.bytes.readUInt8(this.#take(1));
  u16 = (): number => this.bytes.readUInt16LE(this.#take(2));
  i16 = (): number => this.bytes.readInt16LE(this.#take(2));
  u32 = (): number => this.bytes.readUInt32LE(this.#take(4));
  skip = (size: number): void => void this.#take(size);
  align4 = (): void =>
    this.seek(Math.min(this.bytes.length, (this.#at + 3) & ~3));

  /** NUL-terminated UTF-16LE text and its file range without the terminator. */
  sz(): { text: string; location: { offset: number; bytes: number } } {
    const start = this.#at;
    for (;;) if (this.u16() === 0) break;
    const end = this.#at - 2;
    return {
      text: this.bytes.toString("utf16le", start, end),
      location: { offset: this.fileOffset + start, bytes: end - start },
    };
  }

  /** sz_Or_Ord: absent, a 16-bit ordinal, or NUL-terminated text. */
  szOrOrd():
    | { kind: "none" }
    | { kind: "ordinal"; ordinal: number }
    | ({ kind: "text" } & ReturnType<PayloadCursor["sz"]>) {
    const first =
      this.bytes.length - this.#at >= 2
        ? this.bytes.readUInt16LE(this.#at)
        : -1;
    if (first === 0) {
      this.skip(2);
      return { kind: "none" };
    }
    if (first === 0xffff) {
      this.skip(2);
      return { kind: "ordinal", ordinal: this.u16() };
    }
    return { kind: "text", ...this.sz() };
  }
}

const identityLabel = (identity: PeResourceIdentity): string =>
  identity.kind === "id" ? String(identity.id) : JSON.stringify(identity.name);

const languageOf = (resource: Resource): Language =>
  resource.language.kind === "id"
    ? resource.language
    : { kind: "name", name: resource.language.name };

const PLACEHOLDER =
  /%%|\{\{|\}\}|%(?:\d+\$)?[-+ #0']*(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:hh|h|ll|l|L|q|j|z|t|I64|I32|I|w)?[diouxXeEfFgGaAcCsSpn]|%[1-9]\d?(?:![^!]+!)?|\{\d+(?:,-?\d+)?(?::[^{}]*)?\}/gu;

/** Tokens whose spelling a translation must keep; escapes are not tokens. */
export const peUiPlaceholders = (text: string): string[] =>
  [...text.matchAll(PLACEHOLDER)]
    .map(([token]) => token)
    .filter((token) => token !== "%%" && token !== "{{" && token !== "}}");

/** Windows menu/control mnemonic: the character after a single '&'. */
const mnemonicOf = (text: string): string | null => {
  for (let at = 0; at < text.length - 1; at += 1) {
    if (text[at] !== "&") continue;
    const next = text[at + 1];
    if (next === "&") {
      at += 1;
      continue;
    }
    return next ?? null;
  }
  return null;
};

const CONTROL_ORDINALS: Readonly<Record<number, string>> = {
  0x80: "Button",
  0x81: "Edit",
  0x82: "Static",
  0x83: "ListBox",
  0x84: "ScrollBar",
  0x85: "ComboBox",
};

const SS_TYPEMASK = 0x1f;
const SS_ICON = 0x03;
const SS_BITMAP = 0x0e;
const SS_ENHMETAFILE = 0x0f;

/** Role from the predefined class and its type bits; unknown classes stay generic. */
const controlRole = (
  className: string,
  style: number,
): PeUiStringRole | "image" => {
  switch (className.toLowerCase()) {
    case "button": {
      const kind = style & 0x0f;
      if (kind === 2 || kind === 3 || kind === 5 || kind === 6)
        return "checkbox";
      if (kind === 4 || kind === 9) return "radio";
      if (kind === 7) return "group-box";
      return "button";
    }
    case "static": {
      const kind = style & SS_TYPEMASK;
      return kind === SS_ICON || kind === SS_BITMAP || kind === SS_ENHMETAFILE
        ? "image"
        : "label";
    }
    case "edit":
      return "edit";
    case "listbox":
      return "list";
    case "combobox":
      return "combo-box";
    case "syslink":
      return "link";
    default:
      return "control";
  }
};

interface Sink {
  readonly strings: PeUiString[];
  readonly resource: Resource;
  readonly resourceIndex: number;
  readonly container: string;
}

const emit = (
  sink: Sink,
  text: { text: string; location: { offset: number; bytes: number } },
  fields: Pick<PeUiString, "key" | "role"> &
    Partial<Omit<PeUiString, "key" | "role">>,
): void => {
  if (text.text.length === 0) return;
  const [visible = text.text, accelerator = null] =
    fields.role === "menu-item" || fields.role === "menu-popup"
      ? text.text.split("\t", 2)
      : [text.text];
  sink.strings.push({
    container: sink.container,
    text: text.text,
    resource_index: sink.resourceIndex,
    language: languageOf(sink.resource),
    location: text.location,
    string_id: null,
    item_id: null,
    menu_path: [],
    control_class: null,
    style: null,
    box: null,
    mnemonic: mnemonicOf(visible),
    accelerator: accelerator === "" ? null : accelerator,
    placeholders: peUiPlaceholders(text.text),
    ...fields,
  });
};

/** RT_STRING: block N carries string IDs (N - 1) * 16 .. (N - 1) * 16 + 15. */
const decodeStringTable = (cursor: PayloadCursor, sink: Sink): void => {
  const block = sink.resource.name;
  if (block.kind !== "id" || block.id === 0)
    throw new TemplateMismatch(
      "string table blocks are addressed by a nonzero numeric name",
    );
  for (let slot = 0; slot < 16; slot += 1) {
    if (cursor.remaining < 2) break;
    const length = cursor.u16();
    const start = cursor.at;
    cursor.skip(length * 2);
    const stringId = (block.id - 1) * 16 + slot;
    emit(
      sink,
      {
        text: cursor.bytes.toString("utf16le", start, cursor.at),
        location: { offset: cursor.fileOffset + start, bytes: length * 2 },
      },
      {
        key: `string:${String(stringId)}`,
        role: "string-table",
        string_id: stringId,
      },
    );
  }
};

interface MenuLevel {
  /** Enclosing popup captions, outermost first. */
  readonly path: readonly string[];
  readonly indexPath: readonly number[];
  readonly extended: boolean;
}

const decodeMenuLevel = (
  cursor: PayloadCursor,
  sink: Sink,
  { path, indexPath, extended }: MenuLevel,
): void => {
  if (path.length >= MAX_MENU_DEPTH)
    throw new TemplateMismatch(
      `menu nests deeper than ${String(MAX_MENU_DEPTH)} popups`,
    );
  for (let index = 0; ; index += 1) {
    let popup: boolean;
    let last: boolean;
    let separator = false;
    let id: number | null;
    if (extended) {
      cursor.align4();
      const type = cursor.u32();
      cursor.skip(4);
      id = cursor.u32();
      const info = cursor.u16();
      popup = (info & 0x01) !== 0;
      last = (info & MF_END) !== 0;
      separator = (type & MFT_SEPARATOR) !== 0;
    } else {
      const option = cursor.u16();
      popup = (option & MF_POPUP) !== 0;
      last = (option & MF_END) !== 0;
      id = popup ? null : cursor.u16();
    }
    const caption = cursor.sz();
    const key = `menu:${identityLabel(sink.resource.name)}/item:${[...indexPath, index].join(".")}`;
    if (!separator)
      emit(sink, caption, {
        key,
        role: popup ? "menu-popup" : "menu-item",
        item_id: popup && !extended ? null : id,
        menu_path: [...path],
      });
    if (popup) {
      if (extended) {
        cursor.align4();
        cursor.skip(4);
      }
      decodeMenuLevel(cursor, sink, {
        path: [...path, caption.text],
        indexPath: [...indexPath, index],
        extended,
      });
    }
    if (last) return;
  }
};

/** MENUITEMTEMPLATEHEADER (version 0) or MENUEX_TEMPLATE_HEADER (version 1). */
const decodeMenu = (cursor: PayloadCursor, sink: Sink): void => {
  const version = cursor.u16();
  const offset = cursor.u16();
  if (version !== 0 && version !== 1)
    throw new TemplateMismatch(
      `unknown menu template version ${String(version)}`,
    );
  cursor.seek(4 + offset);
  if (cursor.remaining === 0) return;
  decodeMenuLevel(cursor, sink, {
    path: [],
    indexPath: [],
    extended: version === 1,
  });
};

/** DLGTEMPLATE or DLGTEMPLATEEX followed by DWORD-aligned item templates. */
const decodeDialog = (cursor: PayloadCursor, sink: Sink): void => {
  const extended =
    cursor.bytes.length >= 4 &&
    cursor.bytes.readUInt16LE(0) === 1 &&
    cursor.bytes.readUInt16LE(2) === 0xffff;
  let style: number;
  if (extended) {
    cursor.skip(8);
    cursor.skip(4);
    style = cursor.u32();
  } else {
    style = cursor.u32();
    cursor.skip(4);
  }
  const items = cursor.u16();
  const dialogBox: Box = {
    x: cursor.i16(),
    y: cursor.i16(),
    width: cursor.i16(),
    height: cursor.i16(),
  };
  cursor.szOrOrd();
  cursor.szOrOrd();
  const title = cursor.sz();
  const dialog = identityLabel(sink.resource.name);
  emit(sink, title, {
    key: `dialog:${dialog}/caption`,
    role: "dialog-caption",
    style,
    box: dialogBox,
  });
  if ((style & DS_SETFONT) !== 0) {
    cursor.skip(2);
    if (extended) cursor.skip(4);
    cursor.sz();
  }
  for (let index = 0; index < items; index += 1) {
    cursor.align4();
    let itemStyle: number;
    if (extended) {
      cursor.skip(8);
      itemStyle = cursor.u32();
    } else {
      itemStyle = cursor.u32();
      cursor.skip(4);
    }
    const itemBox: Box = {
      x: cursor.i16(),
      y: cursor.i16(),
      width: cursor.i16(),
      height: cursor.i16(),
    };
    const id = extended ? cursor.u32() : cursor.u16();
    const windowClass = cursor.szOrOrd();
    const caption = cursor.szOrOrd();
    cursor.skip(cursor.u16());
    const className =
      windowClass.kind === "text"
        ? windowClass.text
        : windowClass.kind === "ordinal"
          ? (CONTROL_ORDINALS[windowClass.ordinal] ??
            `#${String(windowClass.ordinal)}`)
          : null;
    if (caption.kind !== "text" || className === null) continue;
    const role = controlRole(className, itemStyle);
    // An image static names its icon or bitmap resource, not visible text.
    if (role === "image") continue;
    emit(sink, caption, {
      key: `dialog:${dialog}/control:${String(index)}`,
      role,
      item_id: id,
      control_class: className,
      style: itemStyle,
      box: itemBox,
    });
  }
};

/** MESSAGE_RESOURCE_DATA: Unicode entries, and ANSI entries only when ASCII. */
const decodeMessageTable = (cursor: PayloadCursor, sink: Sink): void => {
  const blocks = cursor.u32();
  if (blocks * 12 > cursor.remaining)
    throw new TemplateMismatch(
      `${String(blocks)} message blocks exceed the payload`,
    );
  const ansi: number[] = [];
  for (let block = 0; block < blocks; block += 1) {
    cursor.seek(4 + block * 12);
    const low = cursor.u32();
    const high = cursor.u32();
    const entries = cursor.u32();
    if (high < low)
      throw new TemplateMismatch(
        `message block ${String(block)} ends before it starts`,
      );
    cursor.seek(entries);
    for (let id = low; id <= high; id += 1) {
      const start = cursor.at;
      const length = cursor.u16();
      const flags = cursor.u16();
      if (length < 4)
        throw new TemplateMismatch(
          `message ${String(id)} has length ${String(length)}`,
        );
      const textStart = cursor.at;
      cursor.seek(start + length);
      let text: string;
      let bytes: number;
      if ((flags & 1) === 1) {
        const raw = cursor.bytes.toString("utf16le", textStart, start + length);
        text = raw.replace(/\0+$/u, "");
        bytes = text.length * 2;
      } else {
        const raw = cursor.bytes.subarray(textStart, start + length);
        const end = raw.indexOf(0) === -1 ? raw.length : raw.indexOf(0);
        if (raw.subarray(0, end).some((byte) => byte >= 0x80)) {
          ansi.push(id);
          continue;
        }
        text = raw.toString("latin1", 0, end);
        bytes = end;
      }
      emit(
        sink,
        { text, location: { offset: cursor.fileOffset + textStart, bytes } },
        { key: `message:${String(id)}`, role: "message", string_id: id },
      );
    }
  }
  if (ansi.length > 0)
    throw new TemplateMismatch(
      `${String(ansi.length)} ANSI messages need the image code page and were not decoded (first ID ${String(ansi[0])})`,
    );
};

const DECODERS: Readonly<
  Record<
    number,
    readonly [
      prefix: string,
      decode: (cursor: PayloadCursor, sink: Sink) => void,
    ]
  >
> = {
  [RT_STRING]: ["string-block", decodeStringTable],
  [RT_MENU]: ["menu", decodeMenu],
  [RT_DIALOG]: ["dialog", decodeDialog],
  [RT_MESSAGETABLE]: ["message-table", decodeMessageTable],
};

/**
 * Decode user-visible text from conventional Win32 UI resources already
 * located by parsePeResources. Malformed templates keep the strings decoded
 * before the mismatch and are reported in `undecoded`; nothing is executed.
 */
export const decodePeUiStrings = (
  bytes: Buffer,
  resources: PeResources["resources"],
): PeUiStrings => {
  const strings: PeUiString[] = [];
  const undecoded: PeUiStrings["undecoded"] = [];
  const coverage = {
    string_tables: 0,
    menus: 0,
    dialogs: 0,
    message_tables: 0,
  };
  for (const resource of resources) {
    if (resource.type.kind !== "id") continue;
    const decoder = DECODERS[resource.type.id];
    if (decoder === undefined) continue;
    const [prefix, decode] = decoder;
    const container = `${prefix}:${identityLabel(resource.name)}`;
    const { offset, bytes: size } = resource.payload.location;
    if (resource.type.id === RT_STRING) coverage.string_tables += 1;
    else if (resource.type.id === RT_MENU) coverage.menus += 1;
    else if (resource.type.id === RT_DIALOG) coverage.dialogs += 1;
    else coverage.message_tables += 1;
    if (offset + size > bytes.length) {
      undecoded.push({
        resource_index: resource.index,
        container,
        reason: "payload lies outside the file image",
      });
      continue;
    }
    try {
      decode(new PayloadCursor(bytes.subarray(offset, offset + size), offset), {
        strings,
        resource,
        resourceIndex: resource.index,
        container,
      });
    } catch (cause) {
      if (!(cause instanceof TemplateMismatch)) throw cause;
      undecoded.push({
        resource_index: resource.index,
        container,
        reason: cause.message,
      });
    }
  }
  return {
    strings,
    undecoded,
    coverage,
    limitations: [
      "Only resource templates are decoded; text built or loaded at runtime (SetWindowText, MessageBox literals, computed LoadString IDs) needs code analysis.",
      "Boxes are dialog units from the template; pixel size depends on the dialog font and DPI.",
      "Keys are unique per resource language; pair key with language when merging translations.",
    ],
  };
};
