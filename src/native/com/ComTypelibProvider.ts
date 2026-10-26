import {
  projectStableArtifactFailure,
  projectArtifactCloseFailure,
} from "../../artifacts/StableArtifactFailure.js";
import { isSelectedRegularFileError } from "../../filesystem/RegularFile.js";
import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import {
  artifactFilePrimaryFacts,
  type ArtifactFilePrimaryFacts,
  assertArtifactReadActive,
  artifactFileCancellationCause,
} from "../../artifacts/ArtifactFileOperation.js";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import type { ComTypelibPort } from "../../application/binaryDiagnostics/ComTypelibPort.js";
import type { ExecutionOptions } from "../../application/AnalysisProvider.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  type ResourceConstraintRecovery,
} from "../../domain/analysisErrorCore.js";
import { fixedAllowanceOptions } from "../../domain/fixedAllowanceRemediation.js";
import {
  MAX_INSPECT_COM_TYPELIB_MEMBERS,
  MAX_INSPECT_COM_TYPELIB_RETAINED_TEXT_BYTES,
  type InspectComTypelibInput,
} from "../../domain/native/comTypelib.js";
import {
  MAX_INSPECT_PE_DIRECTORY_ENTRIES,
  MAX_INSPECT_PE_FILE_BYTES,
} from "../../domain/native/peResources.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { err, ok } from "../../domain/result.js";
import { COM_TYPELIB_PROVIDER } from "../../domain/investigationProviders.js";
import { PE_RESOURCE_METADATA_BYTES } from "../pe/PeResourceParser.js";
import { inspectComTypelib } from "./ComTypelibInspector.js";
import {
  ComTypelibLimitFailure,
  type ComTypelibLimit,
} from "./MsftTypelibParser.js";

const OPERATION = "inspect_com_typelib";

/** Portable type-library reader over one bounded, identity-checked regular file. */
export class ComTypelibProvider implements ComTypelibPort {
  readonly identity = COM_TYPELIB_PROVIDER;
  readonly #resources = new ArtifactResourceScope();

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      throw projectArtifactCloseFailure(
        cause,
        COM_TYPELIB_PROVIDER.id,
        OPERATION,
      );
    }
  }

  async inspect(input: InspectComTypelibInput, options?: ExecutionOptions) {
    try {
      return await this.#resources.run(async () => {
        const snapshot = await readStableArtifact(
          input.path,
          input.max_file_bytes,
          options?.signal,
          undefined,
          this.#resources,
        );
        assertArtifactReadActive(options?.signal);
        const report = await inspectComTypelib(
          snapshot.bytes,
          {
            path: input.path,
            sha256: snapshot.sha256,
            bytes: snapshot.bytes.length,
          },
          input,
          options?.signal,
        );
        assertArtifactReadActive(options?.signal);
        return ok(report);
      });
    } catch (cause) {
      return err(comTypelibFailure(cause, input));
    }
  }
}

const fileSizeRemediation = (input: InspectComTypelibInput): string =>
  input.max_file_bytes >= MAX_INSPECT_PE_FILE_BYTES
    ? `The artifact exceeds the ${String(MAX_INSPECT_PE_FILE_BYTES)}-byte input ceiling this operation accepts. This release has no runtime override. Select a smaller artifact.`
    : `Raise max_file_bytes above ${String(input.max_file_bytes)} bytes or select a smaller artifact; the limit is the caller-selected input read budget.`;

const entryRemediation = (input: InspectComTypelibInput): string =>
  input.max_entries >= MAX_INSPECT_PE_DIRECTORY_ENTRIES
    ? `The image exceeds the ${String(MAX_INSPECT_PE_DIRECTORY_ENTRIES)}-entry resource-directory ceiling this operation accepts. Select a smaller artifact.`
    : `Raise max_entries above ${String(input.max_entries)} or select a smaller artifact; the limit is the caller-selected resource directory entry budget.`;

const memberRemediation = (input: InspectComTypelibInput): string =>
  input.max_members >= MAX_INSPECT_COM_TYPELIB_MEMBERS
    ? `The libraries exceed the ${String(MAX_INSPECT_COM_TYPELIB_MEMBERS)}-member ceiling this operation accepts; select types with type_names or set include_members to false.`
    : `Raise max_members above ${String(input.max_members)}, select types with type_names, or set include_members to false; the limit is the caller-selected member budget.`;

/** Recovery for one exhausted allowance, chosen from the parser's structured tag. */
const limitRecovery = (
  limit: ComTypelibLimit,
  input: InspectComTypelibInput,
): ResourceConstraintRecovery =>
  limit === "members"
    ? { retryable: false, remediationAction: memberRemediation(input) }
    : fixedAllowanceOptions(
        `The ${String(MAX_INSPECT_COM_TYPELIB_RETAINED_TEXT_BYTES)}-byte COM type-library retained-text allowance (this release has no runtime override; type_names or include_members=false reduce retained text)`,
        "bytes",
      );

const comTypelibFailurePrimary = (
  facts: ArtifactFilePrimaryFacts,
  input: InspectComTypelibInput,
): AnalysisError => {
  const { cause, origin } = facts;
  if (origin === "owned-or-classified" && cause instanceof AnalysisError)
    return cause;
  if (
    origin === "owned-or-classified" &&
    cause instanceof ArtifactReaderFailure &&
    cause.reason === "integrity"
  )
    return new AnalysisArtifactChangedError(
      OPERATION,
      input.path,
      cause.message,
      { cause },
    );
  if (
    origin === "owned-or-classified" &&
    cause instanceof ArtifactReaderFailure &&
    cause.reason === "cancelled"
  )
    return new AnalysisCancelledError(OPERATION, {
      cause: artifactFileCancellationCause(cause),
    });
  if (cause instanceof ComTypelibLimitFailure)
    return new AnalysisResourceConstraintError(
      OPERATION,
      "capacity",
      `Selected artifact ${input.path}: ${cause.message}`,
      {
        boundary: cause.boundary,
        maximum: cause.maximum_bytes,
        limit: cause.limit,
      },
      { cause, ...limitRecovery(cause.limit, input) },
    );
  if (
    origin === "owned-or-classified" &&
    cause instanceof ArtifactReaderFailure
  ) {
    if (cause.reason === "limit") {
      // The read budget is a file-size bound; PE resource entries are a
      // capacity bound; the PE resource metadata allowance is fixed.
      const boundary = cause.boundary ?? "file-size";
      return new AnalysisResourceConstraintError(
        OPERATION,
        boundary,
        cause.message,
        {
          max_file_bytes: input.max_file_bytes,
          max_entries: input.max_entries,
          ...(boundary === "memory"
            ? { maximum_metadata_bytes: PE_RESOURCE_METADATA_BYTES }
            : {}),
        },
        {
          cause,
          ...(boundary === "memory"
            ? fixedAllowanceOptions(
                `The ${String(PE_RESOURCE_METADATA_BYTES)}-byte PE resource metadata allowance`,
                "parser",
              )
            : {
                retryable: false as const,
                remediationAction:
                  boundary === "capacity"
                    ? entryRemediation(input)
                    : fileSizeRemediation(input),
              }),
        },
      );
    }
    if (cause.reason === "path" || cause.reason === "format")
      return new AnalysisInputError(OPERATION, { cause }, [
        { path: ["path"], reason: "invalid_format", message: cause.message },
      ]);
  }
  if (cause instanceof Error && "code" in cause) {
    if (cause.code === "EACCES" || cause.code === "EPERM")
      return new AnalysisAccessDeniedError(OPERATION, input.path, cause.code, {
        cause,
      });
    if (isSelectedRegularFileError(cause))
      return new AnalysisInputError(OPERATION, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Selected artifact could not be read (${String(cause.code)}): ${input.path}.`,
        },
      ]);
  }
  return new ProviderAdapterError(COM_TYPELIB_PROVIDER.id, OPERATION, {
    cause,
    diagnostics: {
      path: input.path,
      reason: cause instanceof Error ? cause.message : String(cause),
    },
  });
};

const comTypelibFailure = (
  cause: unknown,
  input: InspectComTypelibInput,
): AnalysisError => {
  const primary = comTypelibFailurePrimary(
    artifactFilePrimaryFacts(cause),
    input,
  );
  return projectStableArtifactFailure(
    cause,
    primary,
    input.path,
    COM_TYPELIB_PROVIDER.id,
    OPERATION,
  );
};
