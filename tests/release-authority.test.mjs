import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { approvedReviewers, createApprovalReceipt, environmentApprover, validateEvidence, verifyApprovalReceipt } from "../scripts/release-authority.mjs";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const fields = {
  sourceSha: "a".repeat(40), candidateManifestSha256: "b".repeat(64), vercelArtifactSha256: "c".repeat(64), releaseEnvelopeSha256: "d".repeat(64),
  deploymentUrl: "https://candidate.vercel.app", initiatedBy: "author", approvedBy: "reviewer", codeReviewers: ["reviewer"], triggeringActor: "reviewer",
  callerRepository: "BrainVI-AI/brainvi-monorepo", callerWorkflowRef: "BrainVI-AI/brainvi-monorepo/.github/workflows/carefloor-production-release.yml@refs/heads/main", callerWorkflowSha: "e".repeat(40), callerRunId: "123", callerRunAttempt: "1",
  authorityWorkflowRef: "BrainVI-AI/carefloor-release-authority/.github/workflows/approve-carefloor.yml@abc", authorityWorkflowSha: "f".repeat(40), approvalReference: "https://github.com/BrainVI-AI/brainvi-monorepo/pull/1",
};

test("approval is exact-run bound and rejects replay", () => {
  const now = new Date("2026-08-30T12:00:00Z");
  const receipt = createApprovalReceipt(fields, now);
  const raw = Buffer.from(JSON.stringify(receipt));
  const signature = sign(null, raw, privateKey);
  assert.equal(verifyApprovalReceipt(raw, signature, publicKey, { callerRunId: "123", callerRunAttempt: "1", releaseEnvelopeSha256: "d".repeat(64), triggeringActor: "reviewer" }, now).approvedBy, "reviewer");
  assert.throws(() => verifyApprovalReceipt(raw, signature, publicKey, { callerRunId: "124" }, now), /binding mismatch/);
  assert.throws(() => verifyApprovalReceipt(raw, signature, publicKey, { triggeringActor: "attacker" }, now), /binding mismatch/);
  assert.throws(() => verifyApprovalReceipt(raw, signature, publicKey, { callerRunId: "123" }, new Date("2026-08-30T13:00:00Z")), /validity window/);
});

test("approval identities reject stale reviews and self approval", () => {
  const reviews = [
    { user: { login: "reviewer" }, state: "APPROVED", commit_id: "old", submitted_at: "2026-08-30T10:00:00Z" },
    { user: { login: "fresh" }, state: "APPROVED", commit_id: "head", submitted_at: "2026-08-30T10:01:00Z" },
  ];
  assert.deepEqual(approvedReviewers(reviews, "head", "author"), ["fresh"]);
  assert.equal(environmentApprover([{ state: "approved", environments: [{ name: "carefloor-production-approval" }], user: { login: "human" } }], "carefloor-production-approval", "author"), "human");
  assert.throws(() => environmentApprover([{ state: "approved", environments: [{ name: "carefloor-production-approval" }], user: { login: "author" } }], "carefloor-production-approval", "author"), /independent/);
});

test("rollback marker precedes the production mutation and approval is consumed first", () => {
  const script = fs.readFileSync(new URL("../scripts/release-authority.mjs", import.meta.url), "utf8");
  assert.ok(script.indexOf('fs.writeFileSync("authority/promotion-started"') < script.indexOf("/promote/${encodeURIComponent(staged.id)}"));
  assert.match(script, /"x-vercel-protection-bypass": process\.env\.VERCEL_AUTOMATION_BYPASS_SECRET/);
  const workflow = fs.readFileSync(new URL("../.github/workflows/promote-carefloor.yml", import.meta.url), "utf8");
  assert.ok(workflow.indexOf("release-authority.mjs consume") < workflow.indexOf("release-authority.mjs promote"));
  assert.match(workflow, /carefloor-approval-consumed-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/);
});

test("evidence validation rejects a mutated source receipt", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "carefloor-authority-"));
  const sha = (value) => createHash("sha256").update(value).digest("hex");
  const receipts = { "control-plane.json": "control", "migration.json": "migration", "transaction.json": "transaction", "jackson-cost-receipt.json": "cost" };
  for (const [file, value] of Object.entries(receipts)) fs.writeFileSync(path.join(root, file), value);
  const artifact = { sourceSha: "a".repeat(40), sha256: "c".repeat(64) };
  fs.writeFileSync(path.join(root, "vercel-artifact.json"), JSON.stringify(artifact));
  const candidate = { sourceSha: artifact.sourceSha, browserCandidateManifestSha256: "b".repeat(64), vercelArtifactSha256: artifact.sha256, controlPlaneReceiptSha256: sha("control"), migrationReceiptSha256: sha("migration"), transactionReceiptSha256: sha("transaction"), jacksonCostReceiptSha256: sha("cost") };
  fs.writeFileSync(path.join(root, "candidate.json"), JSON.stringify(candidate));
  const expected = { sourceSha: artifact.sourceSha, candidateManifestSha256: candidate.browserCandidateManifestSha256, vercelArtifactSha256: artifact.sha256, releaseEnvelopeSha256: sha(JSON.stringify(candidate)) };
  assert.equal(validateEvidence(root, expected).sourceSha, artifact.sourceSha);
  fs.writeFileSync(path.join(root, "migration.json"), "tampered");
  assert.throws(() => validateEvidence(root, expected), /migrationReceiptSha256/);
});

test("worker evidence is verified and signed only by the release authority", () => {
  const workflow = fs.readFileSync(
    new URL("../.github/workflows/authorize-carefloor-worker.yml", import.meta.url),
    "utf8",
  );
  assert.match(workflow, /gh attestation verify/);
  assert.match(workflow, /CAREFLOOR_WORKER_ATTESTATION_PRIVATE_KEY_PEM/);
  assert.match(workflow, /evidence_signature_base64/);
});
