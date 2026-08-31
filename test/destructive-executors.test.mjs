import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const EXECUTOR_SHA = "da4791ca32ee587e7e2b230f1780086b18d5c9ea";

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

test("destructive scope comes only from authority environment secrets", async () => {
  for (const name of ["migration", "retention"]) {
    const workflow = await readFile(
      new URL(`../.github/workflows/execute-carefloor-${name}.yml`, import.meta.url),
      "utf8",
    );
    assert.doesNotMatch(workflow, /inputs\.(?:tenant_id|b2_|ledger_retention|worker_batch|backup_retention)/);
    assert.match(workflow, /GITHUB_REPOSITORY!=="BrainVI-AI\/brainvi-monorepo"/);
  }
  const retention = await readFile(
    new URL("../.github/workflows/execute-carefloor-retention.yml", import.meta.url),
    "utf8",
  );
  assert.match(retention, /backblazeb2/);
  assert.match(retention, /secrets\.B2_BUCKET/);
});

test("migration executor preserves the canonical expand-contract gate", async () => {
  const workflow = await readFile(
    new URL("../.github/workflows/execute-carefloor-migration.yml", import.meta.url),
    "utf8",
  );
  assert.match(workflow, /0043_carefloor_legal_hold_generations_contract\.sql/);
  assert.match(workflow, /legalHoldGenerations!=="expand-contract-v1"/);
  assert.match(
    workflow,
    /CAREFLOOR_CANONICAL_URL: https:\/\/brainvi-carefloor\.vercel\.app/,
  );
  assert.doesNotMatch(workflow, /canonical_url:|inputs\.canonical_url/);
});

test("control-plane signing key is confined to the authority workflow", async () => {
  const workflow = await readFile(
    new URL("../.github/workflows/sign-carefloor-control-plane.yml", import.meta.url),
    "utf8",
  );
  assert.match(workflow, /environment: carefloor-release-signing/);
  assert.match(
    workflow,
    /secrets\.CAREFLOOR_CONTROL_PLANE_SIGNING_PRIVATE_KEY_PEM/,
  );
  assert.doesNotMatch(workflow, /actions\/checkout/);
  assert.match(workflow, /CALLER_WORKFLOW_REF: \$\{\{ github\.workflow_ref \}\}/);
  assert.match(workflow, /CALLER_WORKFLOW_SHA: \$\{\{ github\.workflow_sha \}\}/);
  assert.match(workflow, /carefloor-production-release\.yml/);
  assert.match(workflow, /carefloor-control-plane-refresh\.yml/);
  assert.match(workflow, /signing caller workflow is not admitted/);
});

test("Vercel deploy tooling is authority-owned and hash locked", async () => {
  const workflow = await readFile(
    new URL("../.github/workflows/deploy-carefloor-vercel.yml", import.meta.url),
    "utf8",
  );
  const lock = await readFile(new URL("../package-lock.json", import.meta.url), "utf8");
  assert.match(workflow, /environment: carefloor-vercel-deployment/);
  assert.match(workflow, /repository: BrainVI-AI\/carefloor-release-authority/);
  assert.match(workflow, /ref: edad04074c5c506f0a162b3889f0a44446388994/);
  assert.match(workflow, /npm ci --ignore-scripts --omit=dev/);
  assert.doesNotMatch(workflow, /npm install|pnpm exec|pnpm dlx/);
  assert.match(workflow, /secrets\.CAREFLOOR_VERCEL_AUTOMATION_BYPASS_SECRET/);
  assert.match(workflow, /x-vercel-protection-bypass/);
  assert.match(lock, /"vercel": "59\.10\.0"/);
});
