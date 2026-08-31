import assert from "node:assert/strict";
import test from "node:test";

import { createHash } from "node:crypto";
import {
  canonicalSha256,
  runpodConfigurationSha256,
  verifyControlPlane,
} from "../.github/actions/verify-control-plane/verify-control-plane.mjs";

test("hashes the exact bounded RunPod configuration deterministically", () => {
  const endpoint = { id: "ignored", templateId: "template-1", workersMin: 0, workersMax: 0, computeType: "GPU", gpuCount: 1 };
  const template = { imageName: "image@sha256:ignored", isServerless: true, isPublic: false, env: { B: "2", A: "1" } };
  assert.equal(runpodConfigurationSha256(endpoint, template), runpodConfigurationSha256({ ...endpoint, extra: "ignored" }, { ...template, extra: "ignored" }));
  assert.match(runpodConfigurationSha256(endpoint, template), /^[a-f0-9]{64}$/);
});

test("canonical hashing rejects malformed values", () => {
  assert.throws(() => canonicalSha256(Number.POSITIVE_INFINITY), /canonical numbers/);
  assert.throws(() => canonicalSha256("\ud800"), /canonical Unicode/);
});

const digest = (value) => createHash("sha256").update(value).digest("hex");

const controlPlaneFixture = () => {
  const maryImage = `ghcr.io/brainvi-ai/brainvi-watchfloor-perception@sha256:${"1".repeat(64)}`;
  const jacksonDigest = "2".repeat(64);
  const jacksonImage = `ghcr.io/brainvi-ai/brainvi-carefloor-jackson@sha256:${jacksonDigest}`;
  const publicKey = "test-public-key";
  const modelRevision = "3".repeat(40);
  const modelSha256 = "4".repeat(64);
  const runtimeSha256 = jacksonDigest;
  const rightsArtifactSha256 = "5".repeat(64);
  const networkVolumeManifestSha256 = "6".repeat(64);
  const privateKeyReference = "{{ RUNPOD_SECRET_JACKSON_KEY }}";
  const configSha256 = digest(JSON.stringify(Object.fromEntries(Object.entries({
    endpointId: "jackson-endpoint",
    executionPrivateKeyReference: privateKeyReference,
    executionPublicKeySha256: digest(publicKey),
    hfHome: "/runpod-volume/carefloor-jackson/model",
    hfHubOffline: "1",
    imageDigest: `sha256:${jacksonDigest}`,
    model: "Qwen/Qwen3-8B",
    modelRevision,
    modelSha256,
    modelVolumeManifestPath: "/runpod-volume/carefloor-jackson/brainvi-model-manifest.json",
    networkVolumeManifestSha256,
    rightsArtifactSha256,
    runtimeSha256,
  }).sort(([left], [right]) => left.localeCompare(right)))));
  const endpoints = [
    { id: "mary-endpoint", templateId: "mary-template", workersMin: 0, workersMax: 0, computeType: "GPU", gpuCount: 1 },
    { id: "jackson-endpoint", templateId: "jackson-template", networkVolumeId: "volume-1", workersMin: 0, workersMax: 0, computeType: "GPU", gpuCount: 1 },
  ];
  const templates = {
    "mary-template": { imageName: maryImage, isServerless: true, isPublic: false, env: {} },
    "jackson-template": {
      imageName: jacksonImage,
      isServerless: true,
      isPublic: false,
      env: {
        BRAINVI_JACKSON_ENDPOINT_ID: "jackson-endpoint",
        BRAINVI_WORKER_IMAGE_DIGEST: `sha256:${jacksonDigest}`,
        BRAINVI_JACKSON_EXECUTION_PUBLIC_KEY_PEM: publicKey,
        BRAINVI_JACKSON_EXECUTION_PRIVATE_KEY_PEM: privateKeyReference,
        MODEL_NAME: "Qwen/Qwen3-8B",
        MODEL_REVISION: modelRevision,
        BRAINVI_MODEL_SHA256: modelSha256,
        BRAINVI_RUNTIME_SHA256: runtimeSha256,
        BRAINVI_CONFIG_SHA256: configSha256,
        BRAINVI_RIGHTS_ARTIFACT_SHA256: rightsArtifactSha256,
        BRAINVI_MODEL_VOLUME_MANIFEST_SHA256: networkVolumeManifestSha256,
        BRAINVI_MODEL_VOLUME_MANIFEST_PATH: "/runpod-volume/carefloor-jackson/brainvi-model-manifest.json",
        HF_HOME: "/runpod-volume/carefloor-jackson/model",
        HF_HUB_OFFLINE: "1",
      },
    },
  };
  const environment = {
    CAREFLOOR_RELEASE_SOURCE_SHA: "a".repeat(40),
    CAREFLOOR_RELEASE_APPROVED_BY: "protected-authority",
    CAREFLOOR_TENANT_ID: "facility-a",
    CAREFLOOR_RUNPOD_CONTROL_API_KEY: "runpod-key",
    CAREFLOOR_RUNPOD_ENDPOINT_ID: "mary-endpoint",
    CAREFLOOR_RUNPOD_IMAGE: maryImage,
    CAREFLOOR_RUNPOD_CONFIGURATION_SHA256: runpodConfigurationSha256(endpoints[0], templates["mary-template"]),
    CAREFLOOR_JACKSON_RUNPOD_ENDPOINT_ID: "jackson-endpoint",
    CAREFLOOR_JACKSON_RUNPOD_IMAGE: jacksonImage,
    CAREFLOOR_JACKSON_RUNPOD_CONFIGURATION_SHA256: runpodConfigurationSha256(endpoints[1], templates["jackson-template"]),
    CAREFLOOR_JACKSON_WORKER_EXECUTION_PUBLIC_KEY_PEM: publicKey,
    CAREFLOOR_JACKSON_MODEL: "Qwen/Qwen3-8B",
    CAREFLOOR_JACKSON_MODEL_REVISION: modelRevision,
    CAREFLOOR_JACKSON_MODEL_SHA256: modelSha256,
    CAREFLOOR_JACKSON_RUNTIME_SHA256: runtimeSha256,
    CAREFLOOR_JACKSON_CONFIG_SHA256: configSha256,
    CAREFLOOR_JACKSON_RIGHTS_ARTIFACT_SHA256: rightsArtifactSha256,
    CAREFLOOR_JACKSON_NETWORK_VOLUME_MANIFEST_SHA256: networkVolumeManifestSha256,
    CAREFLOOR_NEON_PROJECT_ID: "orange-tree-123",
    CAREFLOOR_NEON_API_KEY: "neon-key",
    CAREFLOOR_BACKUP_RETENTION_DAYS: "7",
    CAREFLOOR_DATABASE_URL: "postgresql://role:secret@orange-tree-123-pooler.us-east-1.aws.neon.tech/db?sslmode=verify-full",
  };
  const fetcher = async (url) => {
    const path = new URL(url).pathname;
    if (path === "/v1/endpoints") return Response.json(endpoints);
    if (path.startsWith("/v1/templates/")) return Response.json(templates[path.split("/").at(-1)]);
    return Response.json({
      project: { id: "orange-tree-123", history_retention_seconds: 604800 },
      connection_uris: [{ connection_parameters: { pooler_host: "orange-tree-123-pooler.us-east-1.aws.neon.tech" } }],
    });
  };
  return { endpoints, environment, fetcher };
};

test("admits only the exact zero-capacity control plane", async () => {
  const fixture = controlPlaneFixture();
  const receipt = await verifyControlPlane(fixture.environment, fixture.fetcher, new Date("2026-08-30T12:00:00.000Z"));
  assert.equal(receipt.schema, "brainvi.carefloor.control-plane-release.v1");
  assert.deepEqual(receipt.runpod.map(({ kind }) => kind), ["mary", "jackson"]);

  fixture.endpoints[0].workersMax = 1;
  await assert.rejects(
    verifyControlPlane(fixture.environment, fixture.fetcher),
    /runtime boundary is invalid/,
  );
});

test("admits the exact bounded GA serving configuration against the standby hash", async () => {
  const fixture = controlPlaneFixture();
  fixture.environment.CAREFLOOR_RUNPOD_EXPECTED_WORKERS_MAX = "1";
  fixture.endpoints.forEach((endpoint) => { endpoint.workersMax = 1; });
  const receipt = await verifyControlPlane(fixture.environment, fixture.fetcher);
  assert.ok(receipt.runpod.every(({ workersMax }) => workersMax === 1));
});

test("rejects an inference key that can manage the RunPod account", async () => {
  const fixture = controlPlaneFixture();
  Object.assign(fixture.environment, {
    CAREFLOOR_RUNPOD_API_KEY: "mary-inference",
    CAREFLOOR_JACKSON_RUNPOD_API_KEY: "jackson-inference",
  });
  const fetcher = async (url, init) => {
    const parsed = new URL(url);
    if (parsed.origin === "https://api.runpod.ai") return Response.json({ idle: 1 });
    if (
      parsed.origin === "https://rest.runpod.io" &&
      init?.headers?.authorization !== "Bearer runpod-key"
    ) return Response.json([]);
    return fixture.fetcher(url, init);
  };
  await assert.rejects(
    verifyControlPlane(fixture.environment, fetcher),
    /management authority/,
  );
});
