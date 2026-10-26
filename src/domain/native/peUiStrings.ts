import { z } from "zod";

const uint = z.number().int().min(0).max(0xffffffff);
const int16 = z.number().int().min(-0x8000).max(0x7fff);
const range = z.strictObject({ offset: uint, bytes: uint });
const identity = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("id"), id: uint }),
  z.strictObject({ kind: z.literal("name"), name: z.string() }),
]);
const box = z
  .strictObject({ x: int16, y: int16, width: int16, height: int16 })
  .describe("Template coordinates in dialog units, not pixels");

/** Where the text appears; consumers group entries by container. */
export const peUiStringRoleSchema = z.enum([
  "string-table",
  "message",
  "menu-item",
  "menu-popup",
  "dialog-caption",
  "button",
  "checkbox",
  "radio",
  "group-box",
  "label",
  "edit",
  "list",
  "combo-box",
  "link",
  "control",
]);

/** One user-visible text with the static facts a translator needs. */
export const peUiStringSchema = z.strictObject({
  key: z
    .string()
    .min(1)
    .describe(
      "Stable address of the text inside its resource, for example dialog:101/control:1002",
    ),
  container: z
    .string()
    .min(1)
    .describe("Resource that shows this text together with its siblings"),
  role: peUiStringRoleSchema,
  text: z.string().min(1),
  resource_index: uint.describe("Index into inspect_pe_resources resources"),
  language: identity,
  location: range.describe("File range of the encoded UTF-16LE text"),
  string_id: uint.nullable(),
  item_id: uint.nullable(),
  menu_path: z
    .array(z.string())
    .describe("Enclosing popup captions, outermost first; [] outside menus"),
  control_class: z.string().nullable(),
  style: uint.nullable(),
  box: box.nullable(),
  mnemonic: z
    .string()
    .nullable()
    .describe("Character after a single '&'; '&&' is a literal ampersand"),
  accelerator: z
    .string()
    .nullable()
    .describe("Menu shortcut text after a tab, shown but not bound here"),
  placeholders: z
    .array(z.string())
    .describe(
      "printf, FormatMessage and .NET composite tokens a translation must keep",
    ),
});

/** Resources whose payload did not match the conventional template. */
export const peUiStringFailureSchema = z.strictObject({
  resource_index: uint,
  container: z.string().min(1),
  reason: z.string().min(1),
});

/** Localizable text decoded from RT_STRING, RT_MESSAGETABLE, RT_MENU and RT_DIALOG payloads. */
export const peUiStringsSchema = z.strictObject({
  strings: z.array(peUiStringSchema),
  undecoded: z.array(peUiStringFailureSchema),
  coverage: z.strictObject({
    string_tables: uint,
    menus: uint,
    dialogs: uint,
    message_tables: uint,
  }),
  limitations: z.array(z.string()),
});

export type PeUiString = z.infer<typeof peUiStringSchema>;
export type PeUiStringRole = z.infer<typeof peUiStringRoleSchema>;
export type PeUiStrings = z.infer<typeof peUiStringsSchema>;
