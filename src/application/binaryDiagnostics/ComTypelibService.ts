import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { ComTypelibPort } from "./ComTypelibPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  comTypelibSchema,
  inspectComTypelibInputSchema,
  type ComTypelib,
  type InspectComTypelibInput,
} from "../../domain/native/comTypelib.js";
import { err, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
import { parseAnalysisInput } from "../AnalysisInput.js";

const OPERATION = "inspect_com_typelib";

/** Shared caller validation, output parsing and Evidence provenance for CLI/MCP. */
export class ComTypelibService {
  constructor(readonly provider: ComTypelibPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const input = parseAnalysisInput(
      OPERATION,
      rawInput,
      inspectComTypelibInputSchema,
      options?.signal,
    );
    if (!input.ok) return input;
    if (!isAbsolute(input.value.path))
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const result = await this.provider.inspect(input.value, options);
    if (!result.ok) return result;
    const report = comTypelibSchema.safeParse(result.value);
    if (
      !report.success ||
      report.data.artifact.path !== input.value.path ||
      !validReport(report.data, input.value)
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "COM type-library provider returned malformed output or changed artifact identity.",
        ),
      );
    const value = report.data;
    return completeProviderEvidence(
      createEvidence(
        {
          path: value.artifact.path,
          format: value.container === "typelib" ? "file" : "pe",
          sha256: value.artifact.sha256,
        },
        this.provider.identity,
        {
          operation: OPERATION,
          parameters: input.value,
          result: value,
          confidence: "observed",
          limitations: value.limitations,
          locations: [
            { kind: "artifact-path", path: value.artifact.path },
            ...value.libraries.map(({ location }) => ({
              kind: "file-offset-range" as const,
              start: location.offset,
              end: location.offset + location.bytes,
            })),
          ],
        },
      ),
      options?.signal,
    );
  }
}

type Range = { readonly offset: number; readonly bytes: number };

const within = (outer: Range, inner: Range): boolean =>
  inner.offset >= outer.offset &&
  inner.offset + inner.bytes <= outer.offset + outer.bytes;

/** A type info's members and locations stay inside its library and declared counts. */
const validTypeInfo = (
  info: ComTypelib["libraries"][number]["type_infos"][number],
  position: number,
  library: Range,
  input: InspectComTypelibInput,
): boolean =>
  info.index === position &&
  within(library, info.location) &&
  info.functions.length <= info.function_count &&
  info.variables.length <= info.variable_count &&
  (info.members_reported ||
    info.functions.length + info.variables.length === 0) &&
  (input.include_members || !info.members_reported) &&
  (info.kind === "coclass" || info.prog_ids.length === 0) &&
  [...info.functions, ...info.variables].every((member) =>
    within(library, member.location),
  );

const validLibrary = (
  report: ComTypelib,
  library: ComTypelib["libraries"][number],
  index: number,
  input: InspectComTypelibInput,
): boolean =>
  library.index === index &&
  library.location.offset <= report.artifact.bytes - library.location.bytes &&
  (library.source.kind === "file") === (report.container === "typelib") &&
  (library.status === "decoded") === (library.issues.length === 0) &&
  library.type_infos.every((info, position) =>
    validTypeInfo(info, position, library.location, input),
  );

/** Coverage totals restate the libraries, and complete coverage means nothing failed. */
const validCoverage = (
  report: ComTypelib,
  input: InspectComTypelibInput,
): boolean => {
  const infos = report.libraries.flatMap(({ type_infos }) => type_infos);
  const sum = (count: (info: (typeof infos)[number]) => number) =>
    infos.reduce((total, info) => total + count(info), 0);
  const reported = sum(
    ({ functions, variables }) => functions.length + variables.length,
  );
  const failed =
    report.libraries.some(({ status }) => status !== "decoded") ||
    report.registration_scripts.some(({ issues }) => issues.length > 0);
  const { coverage } = report;
  return (
    coverage.libraries === report.libraries.length &&
    coverage.type_infos === infos.length &&
    coverage.functions === sum(({ function_count }) => function_count) &&
    coverage.variables === sum(({ variable_count }) => variable_count) &&
    coverage.reported_members === reported &&
    reported <= input.max_members &&
    (coverage.status === "complete") === (coverage.reason === null) &&
    (coverage.status === "partial" || !failed)
  );
};

/** Check cross-field invariants before provider output becomes public Evidence. */
const validReport = (
  report: ComTypelib,
  input: InspectComTypelibInput,
): boolean =>
  report.artifact.bytes <= input.max_file_bytes &&
  (report.container !== "typelib" ||
    (report.libraries.length === 1 &&
      report.registration_scripts.length === 0)) &&
  report.libraries.every((library, index) =>
    validLibrary(report, library, index, input),
  ) &&
  report.registration_scripts.every(
    ({ location }) => location.offset <= report.artifact.bytes - location.bytes,
  ) &&
  validCoverage(report, input) &&
  report.unmatched_type_names.length <= (input.type_names?.length ?? 0);
