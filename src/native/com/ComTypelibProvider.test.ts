import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  AnalysisInputError,
  AnalysisResourceConstraintError,
} from "../../domain/analysisErrorCore.js";
import {
  inspectComTypelibInputSchema,
  type InspectComTypelibInput,
} from "../../domain/native/comTypelib.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { peResourceFixture } from "../pe/PeResources.fixture.js";
import { demoTypelib } from "./ComTypelib.fixture.js";
import { ComTypelibProvider } from "./ComTypelibProvider.js";

const inspect = async (
  bytes: Buffer,
  input: Partial<InspectComTypelibInput> = {},
) => {
  const root = await createTestTempDirectory("rea-com-typelib-");
  const path = join(root, "demo.tlb");
  await writeFile(path, bytes);
  const provider = new ComTypelibProvider();
  try {
    return await provider.inspect(
      inspectComTypelibInputSchema.parse({ path, ...input }),
    );
  } finally {
    await provider.close();
  }
};

describe("COM type-library provider", () => {
  it("reads a stable file and reports its identity", async () => {
    const bytes = demoTypelib();
    const result = await inspect(bytes);
    if (!result.ok) throw result.error;
    expect(result.value.artifact.bytes).toBe(bytes.length);
    expect(result.value.libraries[0]?.name).toBe("DemoCad");
  });

  it("reports an exhausted member budget as a capacity bound with recovery", async () => {
    const result = await inspect(demoTypelib(), { max_members: 3 });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected a refusal");
    expect(result.error).toBeInstanceOf(AnalysisResourceConstraintError);
    expect(result.error).toMatchObject({ resource: "capacity" });
    expect(
      (result.error as AnalysisResourceConstraintError).reportedLimits,
    ).toMatchObject({ limit: "members", maximum: 3 });
    const error = result.error as AnalysisResourceConstraintError;
    expect(error.retryable).toBe(false);
    expect(error.remediationAction).toContain("type_names");
  });

  it("reports the PE resource entry budget as a capacity bound", async () => {
    const result = await inspect(peResourceFixture().bytes, { max_entries: 1 });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected a refusal");
    expect(result.error).toMatchObject({ resource: "capacity" });
    const error = result.error as AnalysisResourceConstraintError;
    expect(error.retryable).toBe(false);
    expect(error.remediationAction).toContain("max_entries");
  });

  it("rejects an unrecognized container as invalid input", async () => {
    const result = await inspect(Buffer.from("not a type library"));
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected a refusal");
    expect(result.error).toBeInstanceOf(AnalysisInputError);
  });
});
