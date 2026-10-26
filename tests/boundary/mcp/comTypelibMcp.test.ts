import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { createServer } from "../../../src/server/createServer.js";
import { demoTypelib } from "../../../src/native/com/ComTypelib.fixture.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { advertisedMcpToolSchemas } from "../../fixtures/advertisedMcpTool.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { mcpTest, type TestMcp } from "../../support/mcp/mcpFixture.js";

const connect = async (mcp: TestMcp) => {
  const session = createTestBinarySession(() => {
    throw new Error(
      "COM type-library inspection must not start a deep provider",
    );
  });
  const client = await mcp.connect(createServer({ kind: "session", session }));
  return { client, session };
};

mcpTest(
  "advertises inspect_com_typelib and reads a type library",
  async ({ mcp }) => {
    const { client, session } = await connect(mcp);
    try {
      const { ajv, outputSchema } = await advertisedMcpToolSchemas(
        client,
        "inspect_com_typelib",
      );
      const root = await createTestTempDirectory("rea-com-typelib-mcp-");
      const path = join(root, "democad.tlb");
      await writeFile(path, demoTypelib());
      const response = await client.callTool({
        name: "inspect_com_typelib",
        arguments: { path, code_page: 1251 },
      });
      expect(response.isError, JSON.stringify(response.content)).not.toBe(true);
      expect(
        ajv.validate(outputSchema, response.structuredContent),
        JSON.stringify(ajv.errors),
      ).toBe(true);
      const report = toolContract("inspect_com_typelib").outputSchema.parse(
        response.structuredContent,
      ).normalized_result;
      expect(report.libraries[0]).toMatchObject({
        name: "DemoCad",
        doc_string: "Библиотека автоматизации DemoCad",
        string_code_page: { code_page: 1251, source: "caller" },
      });
      // Partial libraries remain valid advertised output.
      const truncated = join(root, "truncated.tlb");
      await writeFile(truncated, demoTypelib().subarray(0, 0x200));
      const partial = await client.callTool({
        name: "inspect_com_typelib",
        arguments: { path: truncated },
      });
      expect(partial.isError, JSON.stringify(partial.content)).not.toBe(true);
      expect(
        ajv.validate(outputSchema, partial.structuredContent),
        JSON.stringify(ajv.errors),
      ).toBe(true);
      expect(
        toolContract("inspect_com_typelib").outputSchema.parse(
          partial.structuredContent,
        ).normalized_result.coverage.status,
      ).toBe("partial");
    } finally {
      await session.close();
    }
  },
);

mcpTest(
  "refuses an exhausted member budget with recovery advice",
  async ({ mcp }) => {
    const { client, session } = await connect(mcp);
    try {
      const root = await createTestTempDirectory("rea-com-typelib-mcp-budget-");
      const path = join(root, "democad.tlb");
      await writeFile(path, demoTypelib());
      const response = await client.callTool({
        name: "inspect_com_typelib",
        arguments: { path, max_members: 1 },
      });
      expect(response.isError).toBe(true);
      const error = parseMcpToolError(response);
      expect(JSON.stringify(error)).toContain("type_names");
    } finally {
      await session.close();
    }
  },
);
