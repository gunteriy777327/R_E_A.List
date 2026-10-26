import { createHash } from "node:crypto";
import { assertArtifactReadActive } from "../../artifacts/ArtifactFileOperation.js";
import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import {
  MAX_INSPECT_COM_TYPELIB_RETAINED_TEXT_BYTES,
  type ComRegistrationScript,
  type ComTypelib,
  type ComTypelibLibrary,
  type InspectComTypelibInput,
} from "../../domain/native/comTypelib.js";
import type { PeResourceIdentity } from "../../domain/native/peResources.js";
import { parsePeResources } from "../pe/PeResourceParser.js";
import {
  ComTypelibLimitFailure,
  decodeMsftTypelib,
  MSFT_MAGIC,
  SLTG_MAGIC,
  type ComTypelibBudget,
} from "./MsftTypelibParser.js";
import {
  decodeRegistryScript,
  parseRegistryScript,
} from "./RegistryScriptParser.js";

const LIMITATIONS = [
  "Type information is read from the file without loading, registering or calling the COM server; registry state, class factories and IDispatch name lookups at run time are not observed.",
  "ProgIDs come only from REGISTRY registrar scripts embedded in the same PE image. Servers that register in code, through .reg files or through installers declare ProgIDs this inspection cannot see.",
  "Absence of TYPELIB resources does not show that a module exposes no COM classes; type libraries also ship as separate .tlb/.olb files.",
  "SLTG-format type libraries are identified but not decoded.",
  "Each type info is reported as stored. The interface and dispatch views that ITypeInfo synthesizes for dual interfaces are not reconstructed, and inherited members appear only on their base interface.",
  "Narrow names and help strings use the reported code page. With a neutral LCID and no caller code_page, non-ASCII text is decoded as windows-1252 and may be wrong.",
  "Custom data (IDL custom attributes) is not decoded.",
];

const identityText = (identity: PeResourceIdentity): string =>
  identity.kind === "id" ? `#${String(identity.id)}` : identity.name;
const namedType = (identity: PeResourceIdentity, name: string): boolean =>
  identity.kind === "name" && identity.name.toUpperCase() === name;

/** Member and retained-text allowances shared by every library of the artifact. */
const createBudget = (input: InspectComTypelibInput): ComTypelibBudget => {
  let members = 0;
  let text = 0;
  return {
    takeMembers(count) {
      members += count;
      if (members > input.max_members)
        throw new ComTypelibLimitFailure(
          "members",
          input.max_members,
          `Type libraries declare more than ${String(input.max_members)} functions and variables to decode.`,
        );
    },
    takeText(value) {
      text += Buffer.byteLength(value, "utf8");
      if (text > MAX_INSPECT_COM_TYPELIB_RETAINED_TEXT_BYTES)
        throw new ComTypelibLimitFailure(
          "retained_text",
          MAX_INSPECT_COM_TYPELIB_RETAINED_TEXT_BYTES,
          `Decoded type-library text exceeds the ${String(MAX_INSPECT_COM_TYPELIB_RETAINED_TEXT_BYTES)}-byte retained-text allowance.`,
        );
    },
  };
};

/** Case-insensitive type selection that remembers which requested names matched. */
const createSelection = (input: InspectComTypelibInput) => {
  const requested =
    input.type_names === undefined
      ? null
      : new Map(input.type_names.map((name) => [name.toLowerCase(), name]));
  const matched = new Set<string>();
  return {
    includeMembers(name: string | null): boolean {
      if (requested === null) return input.include_members;
      const key = name?.toLowerCase();
      if (key === undefined || !requested.has(key)) return false;
      matched.add(key);
      return input.include_members;
    },
    unmatched(): string[] {
      return requested === null
        ? []
        : [...requested]
            .filter(([key]) => !matched.has(key))
            .map(([, name]) => name);
    },
  };
};

interface Decoding {
  readonly bytes: Buffer;
  readonly input: InspectComTypelibInput;
  readonly budget: ComTypelibBudget;
  readonly includeMembers: (name: string | null) => boolean;
  readonly signal: AbortSignal | undefined;
}

const unsupportedLibrary = (
  magic: number | null,
  offset: number,
): Omit<ComTypelibLibrary, "index" | "source" | "location" | "sha256"> => ({
  format: magic === SLTG_MAGIC ? "sltg" : "unknown",
  status: "unsupported",
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
  issues: [
    {
      code: "unsupported_form",
      location: `0x${offset.toString(16)}`,
      message:
        magic === SLTG_MAGIC
          ? "SLTG type libraries are not decoded."
          : "Resource does not start with the MSFT or SLTG type-library magic.",
    },
  ],
});

/** Decode the library bytes at one artifact range. */
const decodeLibrary = async (
  decoding: Decoding,
  location: { readonly offset: number; readonly bytes: number },
  source: ComTypelibLibrary["source"],
  index: number,
): Promise<ComTypelibLibrary> => {
  const blob = decoding.bytes.subarray(
    location.offset,
    location.offset + location.bytes,
  );
  const common = {
    index,
    source,
    location: { offset: location.offset, bytes: location.bytes },
    sha256: createHash("sha256").update(blob).digest("hex"),
  };
  const magic = blob.length >= 4 ? blob.readUInt32LE(0) : null;
  if (magic !== MSFT_MAGIC)
    return { ...common, ...unsupportedLibrary(magic, location.offset) };
  return {
    ...common,
    ...(await decodeMsftTypelib(blob, {
      baseOffset: location.offset,
      codePage: decoding.input.code_page,
      includeMembers: decoding.includeMembers,
      budget: decoding.budget,
      ...(decoding.signal === undefined ? {} : { signal: decoding.signal }),
    })),
  };
};

/** TYPELIB libraries and REGISTRY scripts among a PE image's resources. */
const decodePeContents = async (
  decoding: Decoding,
  artifact: ComTypelib["artifact"],
) => {
  const { bytes, input, signal } = decoding;
  const resources = await parsePeResources(
    bytes,
    artifact,
    {
      path: input.path,
      max_file_bytes: input.max_file_bytes,
      max_entries: input.max_entries,
    },
    signal,
  );
  const libraries: ComTypelibLibrary[] = [];
  const scripts: ComRegistrationScript[] = [];
  for (const resource of resources.resources) {
    const { location } = resource.payload;
    if (namedType(resource.type, "TYPELIB"))
      libraries.push(
        await decodeLibrary(
          decoding,
          location,
          {
            kind: "pe-resource",
            resource_index: resource.index,
            resource_name: identityText(resource.name),
            language:
              resource.language.kind === "id" ? resource.language.id : null,
          },
          libraries.length,
        ),
      );
    else if (namedType(resource.type, "REGISTRY")) {
      const script = decodeRegistryScript(
        bytes.subarray(location.offset, location.offset + location.bytes),
        input.code_page ?? 1252,
      );
      decoding.budget.takeText(script);
      scripts.push({
        resource_index: resource.index,
        location: { offset: location.offset, bytes: location.bytes },
        ...parseRegistryScript(script),
      });
    }
    assertArtifactReadActive(signal);
  }
  return { container: resources.format, libraries, scripts };
};

/** Join ProgIDs that registrar scripts declare to coclasses with the same GUID. */
const applyProgIds = (
  libraries: readonly ComTypelibLibrary[],
  scripts: readonly ComRegistrationScript[],
): void => {
  const progIds = new Map<string, Set<string>>();
  const add = (clsid: string, progId: string | null) => {
    if (progId === null || progId === "") return;
    progIds.set(clsid, (progIds.get(clsid) ?? new Set()).add(progId));
  };
  for (const script of scripts) {
    for (const item of script.classes) {
      add(item.clsid, item.prog_id);
      add(item.clsid, item.version_independent_prog_id);
    }
    for (const item of script.prog_ids) add(item.clsid, item.prog_id);
  }
  for (const library of libraries)
    for (const info of library.type_infos)
      if (info.kind === "coclass" && info.guid !== null)
        info.prog_ids = [...(progIds.get(info.guid) ?? [])].sort();
};

const coverage = (
  libraries: readonly ComTypelibLibrary[],
  scripts: readonly ComRegistrationScript[],
): ComTypelib["coverage"] => {
  const infos = libraries.flatMap(({ type_infos }) => type_infos);
  const partial = [
    ...libraries
      .filter(({ status }) => status !== "decoded")
      .map(({ index, status }) => `library ${String(index)} is ${status}`),
    ...scripts
      .filter(({ issues }) => issues.length > 0)
      .map(
        ({ resource_index }) =>
          `registration script in resource ${String(resource_index)} is malformed`,
      ),
  ];
  const sum = (count: (info: (typeof infos)[number]) => number) =>
    infos.reduce((total, info) => total + count(info), 0);
  return {
    status: partial.length === 0 ? "complete" : "partial",
    reason: partial.length === 0 ? null : partial.join("; "),
    libraries: libraries.length,
    type_infos: infos.length,
    functions: sum(({ function_count }) => function_count),
    variables: sum(({ variable_count }) => variable_count),
    reported_members: sum(
      ({ functions, variables }) => functions.length + variables.length,
    ),
  };
};

/** Inventory COM type libraries in one .tlb/.olb file or PE image; never loads or registers it. */
export const inspectComTypelib = async (
  bytes: Buffer,
  artifact: ComTypelib["artifact"],
  input: InspectComTypelibInput,
  signal?: AbortSignal,
): Promise<ComTypelib> => {
  assertArtifactReadActive(signal);
  if (bytes.length < 4)
    throw new ArtifactReaderFailure(
      "format",
      "Selected artifact is too small to be a type library or PE image.",
    );
  const selection = createSelection(input);
  const decoding: Decoding = {
    bytes,
    input,
    budget: createBudget(input),
    includeMembers: (name) => selection.includeMembers(name),
    signal,
  };
  const magic = bytes.readUInt32LE(0);
  let contents: {
    container: ComTypelib["container"];
    libraries: ComTypelibLibrary[];
    scripts: ComRegistrationScript[];
  };
  if (magic === MSFT_MAGIC || magic === SLTG_MAGIC)
    contents = {
      container: "typelib",
      libraries: [
        await decodeLibrary(
          decoding,
          { offset: 0, bytes: bytes.length },
          { kind: "file" },
          0,
        ),
      ],
      scripts: [],
    };
  else if (bytes.readUInt16LE(0) === 0x5a4d)
    contents = await decodePeContents(decoding, artifact);
  else
    throw new ArtifactReaderFailure(
      "format",
      "Selected artifact is neither an MSFT/SLTG type library nor a PE image.",
    );
  applyProgIds(contents.libraries, contents.scripts);
  return {
    artifact,
    container: contents.container,
    libraries: contents.libraries,
    registration_scripts: contents.scripts,
    unmatched_type_names: selection.unmatched(),
    coverage: coverage(contents.libraries, contents.scripts),
    limitations: LIMITATIONS,
  };
};
