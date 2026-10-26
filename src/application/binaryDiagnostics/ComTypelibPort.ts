import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  ComTypelib,
  InspectComTypelibInput,
} from "../../domain/native/comTypelib.js";
import type { Result } from "../../domain/result.js";

/** Stable read and COM type-library decoding, independent of a COM runtime or registry. */
export interface ComTypelibPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  inspect(
    input: InspectComTypelibInput,
    options?: ExecutionOptions,
  ): Promise<Result<ComTypelib, AnalysisError>>;
}
