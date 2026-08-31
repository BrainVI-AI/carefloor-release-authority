import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const EXECUTOR_SHA = "053fe13b864a129baf3d76d9d76d4ee984b12440";

for (const name of ["migration", "retention"]) {
  test(`${name} runs only the authority-pinned executor source`, async () => {
    const workflow = await readFile(
      new URL(`../.github/workflows/execute-carefloor-${name}.yml`, import.meta.url),
      "utf8",
    );
    assert.match(workflow, new RegExp(`CAREFLOOR_EXECUTOR_SOURCE_SHA: ${EXECUTOR_SHA}`));
    assert.match(workflow, /repository: BrainVI-AI\/brainvi-monorepo/);
    assert.match(workflow, /ref: \$\{\{ env\.CAREFLOOR_EXECUTOR_SOURCE_SHA \}\}/);
    assert.doesNotMatch(workflow, /ref: \$\{\{ inputs\.source_sha \}\}/);
    assert.match(workflow, /environment: carefloor-(?:production-migration|retention)/);
  });
}

test("migration executor preserves the canonical expand-contract gate", async () => {
  const workflow = await readFile(
    new URL("../.github/workflows/execute-carefloor-migration.yml", import.meta.url),
    "utf8",
  );
  assert.match(workflow, /0043_carefloor_legal_hold_generations_contract\.sql/);
  assert.match(workflow, /legalHoldGenerations!=="expand-contract-v1"/);
});
