import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { inspectPeResourcesInputSchema } from "../../domain/native/peResources.js";
import { peUiStringsSchema } from "../../domain/native/peUiStrings.js";
import { parsePeResources } from "./PeResourceParser.js";
import { peResourceFixture } from "./PeResources.fixture.js";
import { decodePeUiStrings, peUiPlaceholders } from "./PeUiStringDecoder.js";

/** Hand-authored little-endian template bytes, independent of the decoder. */
class Template {
  readonly #parts: Buffer[] = [];
  #size = 0;
  #push(part: Buffer): this {
    this.#parts.push(part);
    this.#size += part.length;
    return this;
  }
  u8 = (value: number) => this.#push(Buffer.from([value]));
  u16 = (value: number) => {
    const part = Buffer.alloc(2);
    part.writeUInt16LE(value & 0xffff);
    return this.#push(part);
  };
  i16 = (value: number) => {
    const part = Buffer.alloc(2);
    part.writeInt16LE(value);
    return this.#push(part);
  };
  u32 = (value: number) => {
    const part = Buffer.alloc(4);
    part.writeUInt32LE(value >>> 0);
    return this.#push(part);
  };
  sz = (text: string) =>
    this.#push(Buffer.concat([Buffer.from(text, "utf16le"), Buffer.alloc(2)]));
  ord = (ordinal: number) => this.u16(0xffff).u16(ordinal);
  align4 = () => this.#push(Buffer.alloc((4 - (this.#size % 4)) % 4));
  bytes = () => Buffer.concat(this.#parts);
}

/** RT_STRING block: sixteen length-prefixed UTF-16LE slots, no terminators. */
const stringBlock = (texts: Readonly<Record<number, string>>) => {
  const parts: Buffer[] = [];
  for (let slot = 0; slot < 16; slot += 1) {
    const text = texts[slot] ?? "";
    const length = Buffer.alloc(2);
    length.writeUInt16LE(text.length);
    parts.push(length, Buffer.from(text, "utf16le"));
  }
  return Buffer.concat(parts);
};

const MF_POPUP = 0x10;
const MF_END = 0x80;
const MF_SEPARATOR = 0x800;

const classicMenu = () =>
  new Template()
    .u16(0)
    .u16(0)
    .u16(MF_POPUP)
    .sz("&File")
    .u16(0)
    .u16(100)
    .sz("&Open...\tCtrl+O")
    .u16(0)
    .u16(0)
    .sz("")
    .u16(MF_END)
    .u16(101)
    .sz("E&xit")
    .u16(MF_POPUP | MF_END)
    .sz("&Help")
    .u16(MF_END)
    .u16(200)
    .sz("&About %s...")
    .bytes();

const extendedMenu = () => {
  const template = new Template().u16(1).u16(4).u32(0);
  const item = ({
    type = 0,
    id = 0,
    info = 0,
    text,
    popup = false,
  }: {
    type?: number;
    id?: number;
    info?: number;
    text: string;
    popup?: boolean;
  }) => {
    template.align4().u32(type).u32(0).u32(id).u16(info).sz(text);
    if (popup) template.align4().u32(0);
  };
  item({ info: 0x01 | MF_END, text: "&View", popup: true });
  item({ id: 300, text: "&Zoom\tCtrl++" });
  item({ type: MF_SEPARATOR, text: "" });
  item({ id: 301, info: MF_END, text: "Status &bar" });
  return template.bytes();
};

const DS_SETFONT = 0x40;
interface ControlSpec {
  readonly style: number;
  readonly id: number;
  readonly windowClass: number | string;
  readonly caption: number | string | null;
  readonly box?: readonly [number, number, number, number];
}

const control = (
  template: Template,
  { style, id, windowClass, caption, box = [7, 7, 50, 14] }: ControlSpec,
) => {
  template
    .align4()
    .u32(0x50000000 | style)
    .u32(0);
  for (const value of box) template.i16(value);
  template.u16(id);
  if (typeof windowClass === "number") template.ord(windowClass);
  else template.sz(windowClass);
  if (caption === null) template.u16(0);
  else if (typeof caption === "number") template.ord(caption);
  else template.sz(caption);
  template.u16(0);
};

const classicDialog = () => {
  const template = new Template()
    .u32(0x80c800c0 | DS_SETFONT)
    .u32(0)
    .u16(7)
    .i16(0)
    .i16(0)
    .i16(220)
    .i16(120)
    .u16(0)
    .u16(0)
    .sz("Settings")
    .u16(8)
    .sz("MS Shell Dlg");
  control(template, {
    style: 0x01,
    id: 1,
    windowClass: 0x80,
    caption: "OK",
    box: [163, 99, 50, 14],
  });
  control(template, {
    style: 0x00,
    id: 0xffff,
    windowClass: 0x82,
    caption: "&Path:",
    box: [7, 9, 30, 8],
  });
  control(template, {
    style: 0x03,
    id: 0xffff,
    windowClass: 0x82,
    caption: 128,
  });
  control(template, {
    style: 0x03,
    id: 0xffff,
    windowClass: 0x82,
    caption: "IDI_APP",
  });
  control(template, {
    style: 0x03,
    id: 1001,
    windowClass: 0x80,
    caption: "Remember && reuse",
  });
  control(template, {
    style: 0x00,
    id: 1002,
    windowClass: "SysLink",
    caption: "See <a>help</a> for {0}",
  });
  control(template, {
    style: 0x80,
    id: 1003,
    windowClass: 0x81,
    caption: null,
  });
  return template.bytes();
};

const extendedDialog = () => {
  const template = new Template()
    .u16(1)
    .u16(0xffff)
    .u32(0)
    .u32(0)
    .u32(0x80c80000 | 0x48)
    .u16(1)
    .i16(0)
    .i16(0)
    .i16(186)
    .i16(95)
    .u16(0)
    .u16(0)
    .sz("About")
    .u16(9)
    .u16(400)
    .u8(0)
    .u8(1)
    .sz("Segoe UI");
  template
    .align4()
    .u32(0)
    .u32(0)
    .u32(0x50020007)
    .i16(7)
    .i16(7)
    .i16(172)
    .i16(60)
    .u32(70000)
    .ord(0x80)
    .sz("Version")
    .u16(2)
    .u16(0xbeef);
  return template.bytes();
};

const messageTable = () => {
  const unicode = (text: string) => {
    const body = Buffer.from(text, "utf16le");
    const length = 4 + body.length + 2;
    const padded = Math.ceil(length / 4) * 4;
    const entry = Buffer.alloc(padded);
    entry.writeUInt16LE(padded, 0);
    entry.writeUInt16LE(1, 2);
    body.copy(entry, 4);
    return entry;
  };
  const ansi = (text: string) => {
    const body = Buffer.from(text, "latin1");
    const padded = Math.ceil((4 + body.length + 1) / 4) * 4;
    const entry = Buffer.alloc(padded);
    entry.writeUInt16LE(padded, 0);
    entry.writeUInt16LE(0, 2);
    body.copy(entry, 4);
    return entry;
  };
  const entries = Buffer.concat([
    unicode("File %1 was not found.\r\n"),
    ansi("Retry %2!d! times.\r\n"),
  ]);
  return Buffer.concat([
    new Template().u32(1).u32(0x100).u32(0x101).u32(16).bytes(),
    entries,
  ]);
};

const decode = async (resources: Parameters<typeof peResourceFixture>[1]) => {
  const { bytes } = peResourceFixture(false, resources);
  const parsed = await parsePeResources(
    bytes,
    {
      path: "/fixtures/ui.exe",
      bytes: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    },
    inspectPeResourcesInputSchema.parse({ path: "/fixtures/ui.exe" }),
  );
  return {
    bytes,
    result: peUiStringsSchema.parse(decodePeUiStrings(bytes, parsed.resources)),
  };
};

describe("decodePeUiStrings string tables", () => {
  it("numbers string-table entries from the block name and keeps placeholders", async () => {
    const { bytes, result } = await decode([
      {
        type: 6,
        name: 7,
        language: 1033,
        payload: stringBlock({
          0: "Open &file",
          2: "Deleted %d of %s files (100%%)",
          5: "Error %1 in {0:N2}",
        }),
      },
    ]);
    expect(
      result.strings.map(
        ({ key, string_id, text, mnemonic, placeholders }) => ({
          key,
          string_id,
          text,
          mnemonic,
          placeholders,
        }),
      ),
    ).toEqual([
      {
        key: "string:96",
        string_id: 96,
        text: "Open &file",
        mnemonic: "f",
        placeholders: [],
      },
      {
        key: "string:98",
        string_id: 98,
        text: "Deleted %d of %s files (100%%)",
        mnemonic: null,
        placeholders: ["%d", "%s"],
      },
      {
        key: "string:101",
        string_id: 101,
        text: "Error %1 in {0:N2}",
        mnemonic: null,
        placeholders: ["%1", "{0:N2}"],
      },
    ]);
    const [first] = result.strings;
    expect(first?.container).toBe("string-block:7");
    expect(first?.language).toEqual({ kind: "id", id: 1033 });
    if (first === undefined) throw new Error("missing string");
    expect(
      bytes.toString(
        "utf16le",
        first.location.offset,
        first.location.offset + first.location.bytes,
      ),
    ).toBe("Open &file");
    expect(result.coverage.string_tables).toBe(1);
    expect(result.undecoded).toEqual([]);
  });
});

describe("decodePeUiStrings menus", () => {
  it("walks classic and extended menus with popup paths and accelerators", async () => {
    const { result } = await decode([
      { type: 4, name: 200, language: 1033, payload: classicMenu() },
      { type: 4, name: "VIEW", language: 1033, payload: extendedMenu() },
    ]);
    expect(
      result.strings.map(
        ({ key, role, text, item_id, menu_path, mnemonic, accelerator }) => ({
          key,
          role,
          text,
          item_id,
          menu_path,
          mnemonic,
          accelerator,
        }),
      ),
    ).toEqual([
      // Named resource entries precede numeric ones in the directory.
      {
        key: 'menu:"VIEW"/item:0',
        role: "menu-popup",
        text: "&View",
        item_id: 0,
        menu_path: [],
        mnemonic: "V",
        accelerator: null,
      },
      {
        key: 'menu:"VIEW"/item:0.0',
        role: "menu-item",
        text: "&Zoom\tCtrl++",
        item_id: 300,
        menu_path: ["&View"],
        mnemonic: "Z",
        accelerator: "Ctrl++",
      },
      {
        key: 'menu:"VIEW"/item:0.2',
        role: "menu-item",
        text: "Status &bar",
        item_id: 301,
        menu_path: ["&View"],
        mnemonic: "b",
        accelerator: null,
      },
      {
        key: "menu:200/item:0",
        role: "menu-popup",
        text: "&File",
        item_id: null,
        menu_path: [],
        mnemonic: "F",
        accelerator: null,
      },
      {
        key: "menu:200/item:0.0",
        role: "menu-item",
        text: "&Open...\tCtrl+O",
        item_id: 100,
        menu_path: ["&File"],
        mnemonic: "O",
        accelerator: "Ctrl+O",
      },
      {
        key: "menu:200/item:0.2",
        role: "menu-item",
        text: "E&xit",
        item_id: 101,
        menu_path: ["&File"],
        mnemonic: "x",
        accelerator: null,
      },
      {
        key: "menu:200/item:1",
        role: "menu-popup",
        text: "&Help",
        item_id: null,
        menu_path: [],
        mnemonic: "H",
        accelerator: null,
      },
      {
        key: "menu:200/item:1.0",
        role: "menu-item",
        text: "&About %s...",
        item_id: 200,
        menu_path: ["&Help"],
        mnemonic: "A",
        accelerator: null,
      },
    ]);
    expect(result.coverage.menus).toBe(2);
    expect(result.undecoded).toEqual([]);
  });
});

describe("decodePeUiStrings dialogs", () => {
  it("reports dialog captions and text controls with class, role and box", async () => {
    const { result } = await decode([
      { type: 5, name: 101, language: 1049, payload: classicDialog() },
      { type: 5, name: 102, language: 1033, payload: extendedDialog() },
    ]);
    expect(
      result.strings.map(
        ({
          key,
          container,
          role,
          text,
          item_id,
          control_class,
          box,
          mnemonic,
          placeholders,
        }) => ({
          key,
          container,
          role,
          text,
          item_id,
          control_class,
          box,
          mnemonic,
          placeholders,
        }),
      ),
    ).toEqual([
      {
        key: "dialog:101/caption",
        container: "dialog:101",
        role: "dialog-caption",
        text: "Settings",
        item_id: null,
        control_class: null,
        box: { x: 0, y: 0, width: 220, height: 120 },
        mnemonic: null,
        placeholders: [],
      },
      {
        key: "dialog:101/control:0",
        container: "dialog:101",
        role: "button",
        text: "OK",
        item_id: 1,
        control_class: "Button",
        box: { x: 163, y: 99, width: 50, height: 14 },
        mnemonic: null,
        placeholders: [],
      },
      {
        key: "dialog:101/control:1",
        container: "dialog:101",
        role: "label",
        text: "&Path:",
        item_id: 0xffff,
        control_class: "Static",
        box: { x: 7, y: 9, width: 30, height: 8 },
        mnemonic: "P",
        placeholders: [],
      },
      {
        key: "dialog:101/control:4",
        container: "dialog:101",
        role: "checkbox",
        text: "Remember && reuse",
        item_id: 1001,
        control_class: "Button",
        box: { x: 7, y: 7, width: 50, height: 14 },
        mnemonic: null,
        placeholders: [],
      },
      {
        key: "dialog:101/control:5",
        container: "dialog:101",
        role: "link",
        text: "See <a>help</a> for {0}",
        item_id: 1002,
        control_class: "SysLink",
        box: { x: 7, y: 7, width: 50, height: 14 },
        mnemonic: null,
        placeholders: ["{0}"],
      },
      {
        key: "dialog:102/caption",
        container: "dialog:102",
        role: "dialog-caption",
        text: "About",
        item_id: null,
        control_class: null,
        box: { x: 0, y: 0, width: 186, height: 95 },
        mnemonic: null,
        placeholders: [],
      },
      {
        key: "dialog:102/control:0",
        container: "dialog:102",
        role: "group-box",
        text: "Version",
        item_id: 70000,
        control_class: "Button",
        box: { x: 7, y: 7, width: 172, height: 60 },
        mnemonic: null,
        placeholders: [],
      },
    ]);
    expect(result.strings[0]?.language).toEqual({ kind: "id", id: 1049 });
    expect(result.coverage.dialogs).toBe(2);
    expect(result.undecoded).toEqual([]);
  });
});

describe("decodePeUiStrings message tables", () => {
  it("decodes Unicode and ASCII message-table entries", async () => {
    const { result } = await decode([
      { type: 11, name: 1, language: 1033, payload: messageTable() },
    ]);
    expect(
      result.strings.map(({ key, role, text, placeholders }) => ({
        key,
        role,
        text,
        placeholders,
      })),
    ).toEqual([
      {
        key: "message:256",
        role: "message",
        text: "File %1 was not found.\r\n",
        placeholders: ["%1"],
      },
      {
        key: "message:257",
        role: "message",
        text: "Retry %2!d! times.\r\n",
        placeholders: ["%2!d!"],
      },
    ]);
  });
});

describe("decodePeUiStrings malformed templates", () => {
  it("keeps strings decoded before a truncated template and reports the mismatch", async () => {
    const dialog = classicDialog();
    const { result } = await decode([
      {
        type: 6,
        name: 1,
        language: 1033,
        payload: stringBlock({ 1: "Ready" }),
      },
      { type: 5, name: 101, language: 1033, payload: dialog.subarray(0, 140) },
      {
        type: 6,
        name: 2,
        language: 1033,
        payload: Buffer.from([5, 0, 0x41, 0]),
      },
      { type: 10, name: 1, language: 1033, payload: Buffer.from("opaque") },
    ]);
    expect(result.strings.map(({ key }) => key)).toEqual([
      "dialog:101/caption",
      "dialog:101/control:0",
      "dialog:101/control:1",
      "string:1",
    ]);
    expect(result.undecoded).toEqual([
      expect.objectContaining({ container: "dialog:101" }),
      expect.objectContaining({ container: "string-block:2" }),
    ]);
    expect(result.coverage).toEqual({
      string_tables: 2,
      menus: 0,
      dialogs: 1,
      message_tables: 0,
    });
  });

  it("refuses named string-table blocks instead of inventing IDs", async () => {
    const { result } = await decode([
      {
        type: 6,
        name: "STRINGS",
        language: 1033,
        payload: stringBlock({ 0: "Hi" }),
      },
    ]);
    expect(result.strings).toEqual([]);
    expect(result.undecoded).toEqual([
      expect.objectContaining({ container: 'string-block:"STRINGS"' }),
    ]);
  });
});

describe("peUiPlaceholders", () => {
  it.each([
    ["%-08.3lf and %I64u", ["%-08.3lf", "%I64u"]],
    ["%1$s then %2$d", ["%1$s", "%2$d"]],
    ["{{literal}} {1,-10:C}", ["{1,-10:C}"]],
    ["100%% done", []],
    ["%1!s! of %2", ["%1!s!", "%2"]],
  ])("finds the tokens in %j", (text, tokens) => {
    expect(peUiPlaceholders(text)).toEqual(tokens);
  });
});
