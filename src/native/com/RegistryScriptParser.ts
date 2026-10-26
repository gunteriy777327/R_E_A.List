import { decoderFor } from "./ComCodePages.js";
import type {
  ComRegistrationScript,
  ComTypelibIssue,
} from "../../domain/native/comTypelib.js";

/** Bounded nesting accepted for one registrar script. */
const MAXIMUM_DEPTH = 64;
const GUID =
  /^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$/iu;
const MODIFIERS = new Set(["noremove", "forceremove", "delete"]);
const NOT_PROG_IDS = new Set([
  "clsid",
  "typelib",
  "interface",
  "appid",
  "record",
  "component categories",
  "mime",
  "filetype",
]);

interface Key {
  readonly name: string;
  value: string | null;
  readonly children: Key[];
}

class ScriptSyntaxError extends Error {}

/**
 * Tokens follow the ATL registrar: whitespace separates them, and a token
 * that starts with a quote runs to the matching quote, with `''` standing for
 * one literal quote.
 */
/** Read a quoted token starting after its opening quote; returns the value and the next position. */
const quoted = (script: string, from: number): [string, number] => {
  let value = "";
  let at = from;
  for (;;) {
    const end = script.indexOf("'", at);
    if (end === -1)
      throw new ScriptSyntaxError("Unterminated quoted registrar token.");
    value += script.slice(at, end);
    if (script.charAt(end + 1) !== "'") return [value, end + 1];
    value += "'";
    at = end + 2;
  }
};

const tokenize = (script: string): string[] => {
  const tokens: string[] = [];
  let at = 0;
  while (at < script.length) {
    while (at < script.length && /\s/u.test(script.charAt(at))) at += 1;
    if (at >= script.length) break;
    if (script.charAt(at) === "'") {
      const [value, next] = quoted(script, at + 1);
      tokens.push(`'${value}`);
      at = next;
      continue;
    }
    const start = at;
    while (at < script.length && !/\s/u.test(script.charAt(at))) at += 1;
    tokens.push(script.slice(start, at));
  }
  return tokens;
};

const unquote = (token: string): string =>
  token.startsWith("'") ? token.slice(1) : token;

const parseTree = (tokens: readonly string[]): Key[] => {
  let at = 0;
  const next = (): string => {
    const token = tokens[at];
    if (token === undefined)
      throw new ScriptSyntaxError("Registrar script ends inside a key.");
    at += 1;
    return token;
  };
  const keys = (depth: number): Key[] => {
    if (depth > MAXIMUM_DEPTH)
      throw new ScriptSyntaxError(
        `Registrar key nesting exceeds ${String(MAXIMUM_DEPTH)}.`,
      );
    const result: Key[] = [];
    for (;;) {
      let token = next();
      if (token === "}") return result;
      if (token.toLowerCase() === "val") {
        // Named values do not affect class or ProgID identity.
        next();
        if (next() !== "=")
          throw new ScriptSyntaxError("Registrar value lacks '='.");
        next();
        next();
        continue;
      }
      while (MODIFIERS.has(token.toLowerCase())) token = next();
      const key: Key = { name: unquote(token), value: null, children: [] };
      if (tokens[at] === "=") {
        at += 1;
        const type = next().toLowerCase();
        const value = unquote(next());
        if (type === "s") key.value = value;
      }
      if (tokens[at] === "{") {
        at += 1;
        key.children.push(...keys(depth + 1));
      }
      result.push(key);
    }
  };
  const roots: Key[] = [];
  while (at < tokens.length) {
    const name = next();
    if (next() !== "{")
      throw new ScriptSyntaxError(`Registrar root ${name} lacks '{'.`);
    roots.push({ name, value: null, children: keys(1) });
  }
  return roots;
};

const child = (key: Key, name: string): Key | undefined =>
  key.children.find((item) => item.name.toLowerCase() === name);

const classesRoots = (roots: readonly Key[]): Key[] =>
  roots.flatMap((root) => {
    const name = root.name.toUpperCase();
    if (name === "HKCR" || name === "HKEY_CLASSES_ROOT") return [root];
    if (name !== "HKLM" && name !== "HKEY_LOCAL_MACHINE") return [];
    const classes = child(root, "software")?.children.find(
      (item) => item.name.toLowerCase() === "classes",
    );
    return classes === undefined ? [] : [classes];
  });

const canonicalGuid = (value: string | null | undefined): string | null =>
  value !== null && value !== undefined && GUID.test(value)
    ? value.toUpperCase()
    : null;

/** `HKCR\CLSID\{clsid}` keys with their name, ProgIDs and type library. */
const classEntries = (clsidKey: Key): ComRegistrationScript["classes"] =>
  clsidKey.children.flatMap((item) => {
    const clsid = canonicalGuid(item.name);
    return clsid === null
      ? []
      : [
          {
            clsid,
            name: item.value,
            prog_id: child(item, "progid")?.value ?? null,
            version_independent_prog_id:
              child(item, "versionindependentprogid")?.value ?? null,
            typelib: canonicalGuid(child(item, "typelib")?.value),
          },
        ];
  });

/** Decode registrar script bytes: UTF-16LE or UTF-8 by BOM or shape, otherwise the given code page. */
export const decodeRegistryScript = (
  bytes: Buffer,
  codePage: number,
): string => {
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe)
    return bytes.subarray(2).toString("utf16le");
  if (
    bytes.length >= 3 &&
    bytes[0] === 0xef &&
    bytes[1] === 0xbb &&
    bytes[2] === 0xbf
  )
    return bytes.subarray(3).toString("utf8");
  if (
    bytes.length >= 4 &&
    bytes.length % 2 === 0 &&
    bytes[1] === 0 &&
    bytes[3] === 0
  )
    return bytes.toString("utf16le");
  return decoderFor(codePage).decode(bytes);
};

/**
 * Class and ProgID declarations of one ATL registrar (`REGISTRY`) script.
 * These are what the module would write when registered, not observed
 * registry state; replaceable parameters such as `%MODULE%` stay verbatim.
 */
export const parseRegistryScript = (
  script: string,
): Pick<ComRegistrationScript, "classes" | "prog_ids" | "issues"> => {
  const issues: ComTypelibIssue[] = [];
  let roots: Key[] = [];
  try {
    roots = parseTree(tokenize(script.replace(/\0+$/u, "")));
  } catch (cause) {
    if (!(cause instanceof ScriptSyntaxError)) throw cause;
    issues.push({
      code: "malformed_entry",
      location: null,
      message: cause.message,
    });
  }
  const classes: ComRegistrationScript["classes"] = [];
  const progIds: ComRegistrationScript["prog_ids"] = [];
  for (const root of classesRoots(roots))
    for (const key of root.children) {
      const name = key.name.toLowerCase();
      if (name === "clsid") classes.push(...classEntries(key));
      else if (!NOT_PROG_IDS.has(name) && !name.startsWith(".")) {
        const clsid = canonicalGuid(child(key, "clsid")?.value);
        if (clsid !== null) progIds.push({ prog_id: key.name, clsid });
      }
    }
  return { classes, prog_ids: progIds, issues };
};
