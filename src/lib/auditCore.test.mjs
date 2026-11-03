import assert from "node:assert/strict";
import test from "node:test";
import {
  buildAuditPrompt,
  isFindingSupportedBySource,
  parseGitHubRepositoryUrl,
} from "./auditCore.ts";

test("repository URLs are limited to public GitHub repository pages", () => {
  assert.deepEqual(
    parseGitHubRepositoryUrl("https://github.com/example/project.git"),
    { owner: "example", repo: "project" },
  );
  assert.equal(parseGitHubRepositoryUrl("https://example.com/example/project"), null);
  assert.equal(parseGitHubRepositoryUrl("javascript:alert(1)"), null);
});

test("audit prompt contains source code instead of only file names", () => {
  const prompt = buildAuditPrompt("project", [
    { path: "src/handler.ts", content: "const value = eval(input);" },
  ]);

  assert.match(prompt, /src\/handler\.ts/);
  assert.match(prompt, /const value = eval\(input\);/);
  assert.match(prompt, /Do not invent findings/);
});

test("findings must cite a matching snippet and real source line range", () => {
  const sources = [{ path: "src/handler.ts", content: "const safe = true;\nconst value = eval(input);\n" }];
  const finding = {
    file_name: "src/handler.ts",
    line_numbers: "L2 - L2",
    vulnerable_code: "const value = eval(input);",
  };

  assert.equal(isFindingSupportedBySource(finding, sources), true);
  assert.equal(
    isFindingSupportedBySource({ ...finding, file_name: "src/missing.ts" }, sources),
    false,
  );
  assert.equal(
    isFindingSupportedBySource({ ...finding, line_numbers: "L20 - L21" }, sources),
    false,
  );
  assert.equal(
    isFindingSupportedBySource({ ...finding, vulnerable_code: "eval(userInput);" }, sources),
    false,
  );
});
