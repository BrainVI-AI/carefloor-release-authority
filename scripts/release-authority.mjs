import fs from "node:fs";
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import path from "node:path";

const hex = (value, length) => new RegExp(`^[a-f0-9]{${length}}$`).test(value ?? "");
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const fileSha256 = (file) => sha256(fs.readFileSync(file));
const required = (name) => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing ${name}`);
  return value;
};
const writeJson = (file, value) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + "\n");
};

export function validateEvidence(root, expected) {
  for (const [key, length] of [["sourceSha", 40], ["candidateManifestSha256", 64], ["vercelArtifactSha256", 64], ["releaseEnvelopeSha256", 64]]) {
    if (!hex(expected[key], length)) throw new Error(`Invalid ${key}`);
  }
  const candidateFile = path.join(root, "candidate.json");
  if (fileSha256(candidateFile) !== expected.releaseEnvelopeSha256) throw new Error("Release envelope hash mismatch");
  const candidate = JSON.parse(fs.readFileSync(candidateFile, "utf8"));
  const artifact = JSON.parse(fs.readFileSync(path.join(root, "vercel-artifact.json"), "utf8"));
  if (candidate.sourceSha !== expected.sourceSha || candidate.browserCandidateManifestSha256 !== expected.candidateManifestSha256 || candidate.vercelArtifactSha256 !== expected.vercelArtifactSha256 || artifact.sourceSha !== expected.sourceSha || artifact.sha256 !== expected.vercelArtifactSha256) throw new Error("Release envelope identity mismatch");
  for (const [field, file] of [["controlPlaneReceiptSha256", "control-plane.json"], ["migrationReceiptSha256", "migration.json"], ["transactionReceiptSha256", "transaction.json"], ["jacksonCostReceiptSha256", "jackson-cost-receipt.json"], ["gaOperationsValidationSha256", "ga-operations-validation.json"]]) {
    if (candidate[field] !== fileSha256(path.join(root, file))) throw new Error(`Release receipt mismatch: ${field}`);
  }
  return candidate;
}

export function createApprovalReceipt(fields, now = new Date()) {
  return {
    schema: "brainvi.carefloor.release-approval.v2",
    ...fields,
    nonce: `${fields.callerRunId}:${fields.callerRunAttempt}:${fields.releaseEnvelopeSha256}`,
    approvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 30 * 60_000).toISOString(),
  };
}

export function createPreflightReceipt(fields, now = new Date()) {
  return {
    schema: "brainvi.carefloor.release-preflight.v2",
    ...fields,
    nonce: `${fields.callerRunId}:${fields.callerRunAttempt}:${fields.candidateManifestSha256}`,
    authorizedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 30 * 60_000).toISOString(),
  };
}

export function validateMigrationEvidence(root, expected) {
  for (const [key, length] of [["sourceSha", 40], ["candidateManifestSha256", 64], ["vercelArtifactSha256", 64], ["migrationAuthorizationSha256", 64]]) if (!hex(expected[key], length)) throw new Error(`Invalid ${key}`);
  const file = path.join(root, "pre-migration.json");
  if (fileSha256(file) !== expected.migrationAuthorizationSha256) throw new Error("Migration authorization hash mismatch");
  const evidence = JSON.parse(fs.readFileSync(file, "utf8"));
  if (evidence.schema !== "brainvi.carefloor.pre-migration.v1" || evidence.sourceSha !== expected.sourceSha || evidence.candidateManifestSha256 !== expected.candidateManifestSha256 || evidence.vercelArtifactSha256 !== expected.vercelArtifactSha256 || evidence.deploymentUrl !== expected.deploymentUrl) throw new Error("Migration authorization identity mismatch");
  return evidence;
}

export function createMigrationReceipt(fields, now = new Date()) {
  return {
    schema: "brainvi.carefloor.migration-authorization.v1",
    ...fields,
    nonce: `${fields.callerRunId}:${fields.callerRunAttempt}:${fields.migrationAuthorizationSha256}`,
    authorizedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 30 * 60_000).toISOString(),
  };
}

export function verifyMigrationReceipt(raw, signature, publicKey, expected, now = new Date()) {
  if (!verify(null, raw, publicKey, signature)) throw new Error("Migration authorization signature is invalid");
  const receipt = JSON.parse(raw);
  if (receipt.schema !== "brainvi.carefloor.migration-authorization.v1") throw new Error("Unsupported migration authorization schema");
  for (const [field, value] of Object.entries(expected)) if (String(receipt[field]) !== String(value)) throw new Error(`Migration authorization binding mismatch: ${field}`);
  if (receipt.nonce !== `${receipt.callerRunId}:${receipt.callerRunAttempt}:${receipt.migrationAuthorizationSha256}`) throw new Error("Migration authorization nonce mismatch");
  const authorizedAt = Date.parse(receipt.authorizedAt);
  const expiresAt = Date.parse(receipt.expiresAt);
  if (!Number.isFinite(authorizedAt) || !Number.isFinite(expiresAt) || expiresAt - authorizedAt !== 30 * 60_000 || now.getTime() < authorizedAt - 60_000 || now.getTime() > expiresAt) throw new Error("Migration authorization is outside its validity window");
  if (!receipt.approvedBy || receipt.approvedBy === receipt.initiatedBy || !Array.isArray(receipt.codeReviewers) || !receipt.codeReviewers.length) throw new Error("Migration authorization lacks independent human review");
  return receipt;
}

export function verifyPreflightReceipt(raw, signature, publicKey, expected, now = new Date()) {
  if (!verify(null, raw, publicKey, signature)) throw new Error("Release preflight signature is invalid");
  const receipt = JSON.parse(raw);
  if (receipt.schema !== "brainvi.carefloor.release-preflight.v2") throw new Error("Unsupported release preflight schema");
  for (const [field, value] of Object.entries(expected)) if (String(receipt[field]) !== String(value)) throw new Error(`Release preflight binding mismatch: ${field}`);
  if (receipt.nonce !== `${receipt.callerRunId}:${receipt.callerRunAttempt}:${receipt.candidateManifestSha256}`) throw new Error("Release preflight nonce mismatch");
  const authorizedAt = Date.parse(receipt.authorizedAt);
  const expiresAt = Date.parse(receipt.expiresAt);
  if (!Number.isFinite(authorizedAt) || !Number.isFinite(expiresAt) || expiresAt - authorizedAt !== 30 * 60_000 || now.getTime() < authorizedAt - 60_000 || now.getTime() > expiresAt) throw new Error("Release preflight is outside its validity window");
  if (!receipt.approvedBy || receipt.approvedBy === receipt.initiatedBy || !Array.isArray(receipt.codeReviewers) || !receipt.codeReviewers.length) throw new Error("Release preflight lacks independent human review");
  return receipt;
}

export function verifyApprovalReceipt(raw, signature, publicKey, expected, now = new Date()) {
  if (!verify(null, raw, publicKey, signature)) throw new Error("Release approval signature is invalid");
  const receipt = JSON.parse(raw);
  if (receipt.schema !== "brainvi.carefloor.release-approval.v2") throw new Error("Unsupported release approval schema");
  for (const [field, value] of Object.entries(expected)) if (String(receipt[field]) !== String(value)) throw new Error(`Release approval binding mismatch: ${field}`);
  if (receipt.nonce !== `${receipt.callerRunId}:${receipt.callerRunAttempt}:${receipt.releaseEnvelopeSha256}`) throw new Error("Release approval nonce mismatch");
  const approvedAt = Date.parse(receipt.approvedAt);
  const expiresAt = Date.parse(receipt.expiresAt);
  if (!Number.isFinite(approvedAt) || !Number.isFinite(expiresAt) || expiresAt - approvedAt !== 30 * 60_000 || now.getTime() < approvedAt - 60_000 || now.getTime() > expiresAt) throw new Error("Release approval is outside its validity window");
  if (!receipt.approvedBy || receipt.approvedBy === receipt.initiatedBy || !Array.isArray(receipt.codeReviewers) || !receipt.codeReviewers.length) throw new Error("Release approval lacks independent human review");
  return receipt;
}

export function approvedReviewers(reviews, headSha, author) {
  const latest = new Map();
  for (const review of [...reviews].sort((a, b) => String(a.submitted_at).localeCompare(String(b.submitted_at)))) if (review.user?.login) latest.set(review.user.login, review);
  return [...latest.values()].filter((review) => review.state === "APPROVED" && review.commit_id === headSha && review.user.login !== author).map((review) => review.user.login).sort();
}

export function environmentApprover(records, environment, author) {
  const approvals = records.filter((record) => record.state === "approved" && record.environments?.some(({ name }) => name === environment) && record.user?.login && record.user.login !== author);
  if (!approvals.length) throw new Error("Release lacks an independent protected-environment approval");
  return approvals.at(-1).user.login;
}

async function request(url, { token, ...init } = {}) {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(15_000), headers: { Accept: "application/vnd.github+json", ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(init.headers ?? {}) } });
  const text = await response.text();
  if (!response.ok) throw new Error(`Request failed (${response.status}): ${url}`);
  return text ? JSON.parse(text) : {};
}

async function sourceApproval(repository, sourceSha, token) {
  const pulls = await request(`https://api.github.com/repos/${repository}/commits/${sourceSha}/pulls`, { token });
  const pr = pulls.find((item) => item.merged_at && item.base?.ref === "main" && item.merge_commit_sha === sourceSha);
  if (!pr) throw new Error("Release source is not an immutable merged pull-request commit on main");
  const reviews = await request(`https://api.github.com/repos/${repository}/pulls/${pr.number}/reviews?per_page=100`, { token });
  const reviewers = approvedReviewers(reviews, pr.head.sha, pr.user.login);
  if (!reviewers.length) throw new Error("Release source lacks an independent approved pull-request review");
  return { initiatedBy: pr.user.login, codeReviewers: reviewers, approvalReference: pr.html_url };
}

function expectedEvidence() {
  return {
    sourceSha: required("SOURCE_SHA"),
    candidateManifestSha256: required("CANDIDATE_SHA256"),
    vercelArtifactSha256: required("ARTIFACT_SHA256"),
    releaseEnvelopeSha256: required("ENVELOPE_SHA256"),
  };
}

async function approve() {
  if (required("GITHUB_REPOSITORY") !== "BrainVI-AI/brainvi-monorepo" || required("GITHUB_EVENT_NAME") !== "workflow_dispatch" || required("GITHUB_REF") !== "refs/heads/main") throw new Error("Untrusted Carefloor approval caller");
  const evidence = expectedEvidence();
  validateEvidence(required("EVIDENCE_DIR"), evidence);
  const source = await sourceApproval(process.env.GITHUB_REPOSITORY, evidence.sourceSha, required("GH_TOKEN"));
  const approvalHistory = await request(`https://api.github.com/repos/${process.env.GITHUB_REPOSITORY}/actions/runs/${required("GITHUB_RUN_ID")}/approvals`, { token: process.env.GH_TOKEN });
  const approvedBy = environmentApprover(approvalHistory, "carefloor-production-approval", source.initiatedBy);
  const privateKey = createPrivateKey(required("PRIVATE_KEY_PEM"));
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Invalid release approval key");
  const publicKey = createPublicKey(privateKey);
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  const publicKeySha256 = sha256(publicDer);
  if (publicKeySha256 !== required("EXPECTED_PUBLIC_KEY_SHA256")) throw new Error("Release approval trust root mismatch");
  const receipt = createApprovalReceipt({
    ...evidence,
    deploymentUrl: required("DEPLOYMENT_URL"),
    ...source,
    approvedBy,
    dispatchedBy: required("GITHUB_ACTOR"),
    triggeringActor: required("GITHUB_TRIGGERING_ACTOR"),
    callerRepository: process.env.GITHUB_REPOSITORY,
    callerWorkflowRef: required("GITHUB_WORKFLOW_REF"),
    callerWorkflowSha: required("GITHUB_WORKFLOW_SHA"),
    callerRunId: required("GITHUB_RUN_ID"),
    callerRunAttempt: required("GITHUB_RUN_ATTEMPT"),
    authorityWorkflowRef: required("AUTHORITY_WORKFLOW_REF"),
    authorityWorkflowSha: required("AUTHORITY_WORKFLOW_SHA"),
  });
  const raw = Buffer.from(JSON.stringify(receipt));
  const values = {
    receipt_base64: raw.toString("base64"),
    signature_base64: sign(null, raw, privateKey).toString("base64"),
    public_key_pem_base64: Buffer.from(publicKey.export({ type: "spki", format: "pem" })).toString("base64"),
    public_key_sha256: publicKeySha256,
    approved_by: receipt.approvedBy,
    approval_sha256: sha256(raw),
  };
  writeJson("authority/approval-receipt.json", receipt);
  fs.writeFileSync("authority/approval-signature.base64", values.signature_base64 + "\n");
  fs.appendFileSync(required("GITHUB_OUTPUT"), Object.entries(values).map(([key, value]) => `${key}=${value}`).join("\n") + "\n");
}

async function preflight() {
  if (required("GITHUB_REPOSITORY") !== "BrainVI-AI/brainvi-monorepo" || required("GITHUB_EVENT_NAME") !== "workflow_dispatch" || required("GITHUB_REF") !== "refs/heads/main") throw new Error("Untrusted Carefloor preflight caller");
  const sourceSha = required("SOURCE_SHA");
  const candidateManifestSha256 = required("CANDIDATE_SHA256");
  if (!hex(sourceSha, 40) || !hex(candidateManifestSha256, 64)) throw new Error("Invalid Carefloor preflight identity");
  const source = await sourceApproval(process.env.GITHUB_REPOSITORY, sourceSha, required("GH_TOKEN"));
  const approvalHistory = await request(`https://api.github.com/repos/${process.env.GITHUB_REPOSITORY}/actions/runs/${required("GITHUB_RUN_ID")}/approvals`, { token: process.env.GH_TOKEN });
  const approvedBy = environmentApprover(approvalHistory, "carefloor-production-approval", source.initiatedBy);
  const privateKey = createPrivateKey(required("PRIVATE_KEY_PEM"));
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Invalid release preflight key");
  const publicKey = createPublicKey(privateKey);
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  if (sha256(publicDer) !== required("EXPECTED_PUBLIC_KEY_SHA256")) throw new Error("Release preflight trust root mismatch");
  const receipt = createPreflightReceipt({
    sourceSha,
    candidateManifestSha256,
    ...source,
    approvedBy,
    dispatchedBy: required("GITHUB_ACTOR"),
    triggeringActor: required("GITHUB_TRIGGERING_ACTOR"),
    callerRepository: process.env.GITHUB_REPOSITORY,
    callerWorkflowRef: required("GITHUB_WORKFLOW_REF"),
    callerWorkflowSha: required("GITHUB_WORKFLOW_SHA"),
    callerRunId: required("GITHUB_RUN_ID"),
    callerRunAttempt: required("GITHUB_RUN_ATTEMPT"),
    authorityWorkflowRef: required("AUTHORITY_WORKFLOW_REF"),
    authorityWorkflowSha: required("AUTHORITY_WORKFLOW_SHA"),
  });
  const raw = Buffer.from(JSON.stringify(receipt));
  const values = {
    receipt_base64: raw.toString("base64"),
    signature_base64: sign(null, raw, privateKey).toString("base64"),
    public_key_pem_base64: Buffer.from(publicKey.export({ type: "spki", format: "pem" })).toString("base64"),
    approved_by: receipt.approvedBy,
  };
  writeJson("authority/preflight-receipt.json", receipt);
  fs.writeFileSync("authority/preflight-signature.base64", values.signature_base64 + "\n");
  fs.appendFileSync(required("GITHUB_OUTPUT"), Object.entries(values).map(([key, value]) => `${key}=${value}`).join("\n") + "\n");
}

async function migration() {
  if (required("GITHUB_REPOSITORY") !== "BrainVI-AI/brainvi-monorepo" || required("GITHUB_EVENT_NAME") !== "workflow_dispatch" || required("GITHUB_REF") !== "refs/heads/main") throw new Error("Untrusted Carefloor migration caller");
  const evidence = {
    sourceSha: required("SOURCE_SHA"),
    candidateManifestSha256: required("CANDIDATE_SHA256"),
    vercelArtifactSha256: required("ARTIFACT_SHA256"),
    migrationAuthorizationSha256: required("MIGRATION_AUTHORIZATION_SHA256"),
    deploymentUrl: new URL(required("DEPLOYMENT_URL")).href.replace(/\/$/, ""),
  };
  validateMigrationEvidence(required("EVIDENCE_DIR"), evidence);
  const source = await sourceApproval(process.env.GITHUB_REPOSITORY, evidence.sourceSha, required("GH_TOKEN"));
  const approvals = await request(`https://api.github.com/repos/${process.env.GITHUB_REPOSITORY}/actions/runs/${required("GITHUB_RUN_ID")}/approvals`, { token: process.env.GH_TOKEN });
  const approvedBy = environmentApprover(approvals, "carefloor-production-approval", source.initiatedBy);
  const privateKey = createPrivateKey(required("PRIVATE_KEY_PEM"));
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Invalid migration authorization key");
  const publicKey = createPublicKey(privateKey);
  const publicKeySha256 = sha256(publicKey.export({ type: "spki", format: "der" }));
  if (publicKeySha256 !== required("EXPECTED_PUBLIC_KEY_SHA256")) throw new Error("Migration authorization trust root mismatch");
  const receipt = createMigrationReceipt({ ...evidence, ...source, approvedBy, triggeringActor: required("GITHUB_TRIGGERING_ACTOR"), callerRepository: process.env.GITHUB_REPOSITORY, callerWorkflowRef: required("GITHUB_WORKFLOW_REF"), callerWorkflowSha: required("GITHUB_WORKFLOW_SHA"), callerRunId: required("GITHUB_RUN_ID"), callerRunAttempt: required("GITHUB_RUN_ATTEMPT"), authorityWorkflowRef: required("AUTHORITY_WORKFLOW_REF"), authorityWorkflowSha: required("AUTHORITY_WORKFLOW_SHA") });
  const raw = Buffer.from(JSON.stringify(receipt));
  const values = { receipt_base64: raw.toString("base64"), signature_base64: sign(null, raw, privateKey).toString("base64"), public_key_pem_base64: Buffer.from(publicKey.export({ type: "spki", format: "pem" })).toString("base64"), approved_by: receipt.approvedBy };
  writeJson("authority/migration-authorization-receipt.json", receipt);
  fs.writeFileSync("authority/migration-authorization-signature.base64", values.signature_base64 + "\n");
  fs.appendFileSync(required("GITHUB_OUTPUT"), Object.entries(values).map(([key, value]) => `${key}=${value}`).join("\n") + "\n");
}

async function vercelRequest(url, init = {}) {
  return request(url, { ...init, token: required("VERCEL_TOKEN"), headers: { "Content-Type": "application/json", ...(init.headers ?? {}) } });
}

async function version(origin) {
  const response = await fetch(`${origin}/api/version`, { cache: "no-store", signal: AbortSignal.timeout(15_000), headers: process.env.VERCEL_AUTOMATION_BYPASS_SECRET ? { "x-vercel-protection-bypass": process.env.VERCEL_AUTOMATION_BYPASS_SECRET } : {} });
  if (!response.ok) throw new Error(`Carefloor version unavailable: ${origin}`);
  return response.json();
}

async function promote() {
  if (required("GITHUB_REPOSITORY") !== "BrainVI-AI/brainvi-monorepo") throw new Error("Untrusted Carefloor promotion caller");
  const evidence = expectedEvidence();
  validateEvidence(required("EVIDENCE_DIR"), evidence);
  const raw = Buffer.from(required("APPROVAL_RECEIPT_BASE64"), "base64");
  const signature = Buffer.from(required("APPROVAL_SIGNATURE_BASE64"), "base64");
  const publicKey = createPublicKey(Buffer.from(required("APPROVAL_PUBLIC_KEY_PEM_BASE64"), "base64"));
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  if (sha256(publicDer) !== required("EXPECTED_PUBLIC_KEY_SHA256")) throw new Error("Release approval trust root mismatch");
  const deploymentUrl = new URL(required("DEPLOYMENT_URL"));
  const canonicalUrl = new URL(required("CANONICAL_URL"));
  if (deploymentUrl.protocol !== "https:" || !deploymentUrl.hostname.endsWith(".vercel.app") || canonicalUrl.href !== "https://brainvi-carefloor.vercel.app/") throw new Error("Invalid Carefloor deployment binding");
  const approval = verifyApprovalReceipt(raw, signature, publicKey, {
    ...evidence,
    deploymentUrl: deploymentUrl.href.replace(/\/$/, ""),
    callerRepository: process.env.GITHUB_REPOSITORY,
    callerWorkflowRef: required("GITHUB_WORKFLOW_REF"),
    callerWorkflowSha: required("GITHUB_WORKFLOW_SHA"),
    callerRunId: required("GITHUB_RUN_ID"),
    callerRunAttempt: required("GITHUB_RUN_ATTEMPT"),
    triggeringActor: required("GITHUB_TRIGGERING_ACTOR"),
  });
  const orgId = required("VERCEL_ORG_ID");
  const projectId = required("VERCEL_PROJECT_ID");
  if (!/^team_[A-Za-z0-9]+$/.test(orgId) || !/^prj_[A-Za-z0-9]+$/.test(projectId)) throw new Error("Promotion authority is not configured");
  const staged = await vercelRequest(`https://api.vercel.com/v13/deployments/${encodeURIComponent(deploymentUrl.hostname)}?teamId=${encodeURIComponent(orgId)}`);
  if ((staged.projectId ?? staged.project?.id) !== projectId || staged.ownerId !== orgId || staged.target !== "production" || staged.readyState !== "READY" || staged.meta?.carefloorSourceSha !== evidence.sourceSha || staged.meta?.carefloorArtifactSha256 !== evidence.vercelArtifactSha256) throw new Error("Staged Vercel deployment is not the admitted artifact");
  const stagedVersion = await version(deploymentUrl.origin);
  if (stagedVersion.gitHead !== evidence.sourceSha || stagedVersion.candidateManifestSha256 !== evidence.candidateManifestSha256) throw new Error("Staged Carefloor source binding mismatch");
  const previous = await vercelRequest(`https://api.vercel.com/v13/deployments/${encodeURIComponent(canonicalUrl.hostname)}?teamId=${encodeURIComponent(orgId)}`);
  const previousVersion = await version(canonicalUrl.origin);
  writeJson("authority/rollback.json", { projectId, previousDeploymentId: previous.id, previousVersion, stagedDeploymentId: staged.id, canonicalUrl: canonicalUrl.href });
  if (previous.id !== staged.id) {
    fs.writeFileSync("authority/promotion-started", `${staged.id}\n`);
    await vercelRequest(`https://api.vercel.com/v10/projects/${encodeURIComponent(projectId)}/promote/${encodeURIComponent(staged.id)}?teamId=${encodeURIComponent(orgId)}`, { method: "POST", body: "{}" });
  }
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const current = await version(canonicalUrl.origin).catch(() => null);
    if (current?.gitHead === evidence.sourceSha && current?.candidateManifestSha256 === evidence.candidateManifestSha256) {
      writeJson("authority/promotion-receipt.json", { schema: "brainvi.carefloor.external-promotion.v2", ...evidence, deploymentId: staged.id, previousDeploymentId: previous.id, approvalReceiptSha256: sha256(raw), approvedBy: approval.approvedBy, callerRunId: process.env.GITHUB_RUN_ID, callerRunAttempt: process.env.GITHUB_RUN_ATTEMPT, authorityWorkflowRef: required("AUTHORITY_WORKFLOW_REF"), authorityWorkflowSha: required("AUTHORITY_WORKFLOW_SHA"), promotedAt: new Date().toISOString() });
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 5_000));
  }
  throw new Error("Canonical Carefloor promotion did not converge");
}

async function consume() {
  const evidence = expectedEvidence();
  validateEvidence(required("EVIDENCE_DIR"), evidence);
  const raw = Buffer.from(required("APPROVAL_RECEIPT_BASE64"), "base64");
  const signature = Buffer.from(required("APPROVAL_SIGNATURE_BASE64"), "base64");
  const publicKey = createPublicKey(Buffer.from(required("APPROVAL_PUBLIC_KEY_PEM_BASE64"), "base64"));
  if (sha256(publicKey.export({ type: "spki", format: "der" })) !== required("EXPECTED_PUBLIC_KEY_SHA256")) throw new Error("Release approval trust root mismatch");
  const receipt = verifyApprovalReceipt(raw, signature, publicKey, { ...evidence, deploymentUrl: new URL(required("DEPLOYMENT_URL")).href.replace(/\/$/, ""), callerRepository: required("GITHUB_REPOSITORY"), callerWorkflowRef: required("GITHUB_WORKFLOW_REF"), callerWorkflowSha: required("GITHUB_WORKFLOW_SHA"), callerRunId: required("GITHUB_RUN_ID"), callerRunAttempt: required("GITHUB_RUN_ATTEMPT"), triggeringActor: required("GITHUB_TRIGGERING_ACTOR") });
  writeJson("authority/approval-consumption.json", { schema: "brainvi.carefloor.approval-consumption.v1", approvalReceiptSha256: sha256(raw), nonce: receipt.nonce, consumedAt: new Date().toISOString() });
}

async function rollback() {
  if (!fs.existsSync("authority/promotion-started")) return;
  const state = JSON.parse(fs.readFileSync("authority/rollback.json", "utf8"));
  const orgId = required("VERCEL_ORG_ID");
  await vercelRequest(`https://api.vercel.com/v10/projects/${encodeURIComponent(state.projectId)}/promote/${encodeURIComponent(state.previousDeploymentId)}?teamId=${encodeURIComponent(orgId)}`, { method: "POST", body: "{}" });
  const origin = new URL(state.canonicalUrl).origin;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const current = await version(origin).catch(() => null);
    if (current?.gitHead === state.previousVersion.gitHead && current?.candidateManifestSha256 === state.previousVersion.candidateManifestSha256) {
      writeJson("authority/rollback-receipt.json", { schema: "brainvi.carefloor.external-rollback.v1", restoredDeploymentId: state.previousDeploymentId, failedDeploymentId: state.stagedDeploymentId, restoredAt: new Date().toISOString() });
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 5_000));
  }
  throw new Error("Carefloor rollback did not converge");
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const command = process.argv[2];
  ({ approve, preflight, migration, consume, promote, rollback }[command]?.() ?? Promise.reject(new Error("Usage: release-authority.mjs approve|preflight|migration|consume|promote|rollback"))).catch((error) => { console.error(error.message); process.exitCode = 1; });
}
