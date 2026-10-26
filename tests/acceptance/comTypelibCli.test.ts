import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { toolContract } from "../../src/contracts/toolContracts.js";
import { demoTypelib } from "../../src/native/com/ComTypelib.fixture.js";
import { peResourceFixture } from "../../src/native/pe/PeResources.fixture.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

const registrar = Buffer.from(
  "HKCR { DemoCad.Application.7 = s 'DemoCad' { CLSID = s '{5B2A9D34-1C4E-4F6A-9B1D-2E3F4A5B6C7D}' } }",
);

cliTest(
  "inventories embedded COM type libraries through CLI and stdio MCP",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-com-typelib-cli-");
    const call = await cli.sharedMcpCall!();
    const path = join(root, "democad.dll");
    await writeFile(
      path,
      peResourceFixture(true, [
        { type: "REGISTRY", name: 101, language: 1033, payload: registrar },
        { type: "TYPELIB", name: 1, language: 0, payload: demoTypelib() },
      ]).bytes,
    );
    const result = await cli.run({
      arguments: [
        "inspect-com-typelib",
        path,
        "--type-name",
        "IApplication",
        "--json",
      ],
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const response = await call("inspect_com_typelib", {
      path,
      type_names: ["IApplication"],
    });
    expect(response.isError, JSON.stringify(response)).not.toBe(true);
    for (const value of [result.json, response.structuredContent]) {
      const report = toolContract("inspect_com_typelib").outputSchema.parse(
        value,
      ).normalized_result;
      expect(report).toMatchObject({
        container: "pe32-plus",
        coverage: { status: "complete", libraries: 1, reported_members: 2 },
      });
      const types = report.libraries[0]?.type_infos ?? [];
      expect(
        types.find(({ name }) => name === "Application")?.prog_ids,
      ).toEqual(["DemoCad.Application.7"]);
      expect(
        types
          .find(({ name }) => name === "IApplication")
          ?.functions.map(({ name }) => name),
      ).toEqual(["Open", "Matrix"]);
    }
  },
);

cliTest("summarizes a relative standalone type library", async ({ cli }) => {
  const root = await createTestTempDirectory("rea-com-typelib-cli-rel-");
  await writeFile(join(root, "democad.tlb"), demoTypelib());
  const result = await cli.run({
    arguments: ["inspect-com-typelib", "democad.tlb", "--summary", "--json"],
    cwd: root,
  });
  expect(result.exitCode, result.stderr).toBe(0);
  const report = toolContract("inspect_com_typelib").outputSchema.parse(
    result.json,
  ).normalized_result;
  expect(report.artifact.path).toBe(join(root, "democad.tlb"));
  expect(report.container).toBe("typelib");
  expect(report.coverage).toMatchObject({
    type_infos: 10,
    reported_members: 0,
  });
});
