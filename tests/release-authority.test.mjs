import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { createApprovalReceipt, verifyApprovalReceipt } from "../scripts/release-authority.mjs";

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
