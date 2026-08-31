import assert from "node:assert/strict";
import test from "node:test";

import { runReleaseCanary } from "../.github/actions/run-release-canary/run-release-canary.mjs";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import {
  canonicalSha256,
  runpodConfigurationSha256,
} from "../.github/actions/verify-control-plane/verify-control-plane.mjs";

const executionKeys = generateKeyPairSync("ed25519");
const jacksonExecutionKeys = generateKeyPairSync("ed25519");
const releaseModels = [
  { id: "pose", capability: "person_pose_tracking" },
  { id: "mask", capability: "scene_segmentation" },
  { id: "gait", capability: "gait_motion" },
  { id: "body", capability: "body_affect" },
  { id: "t1", capability: "facial_affect" },
  { id: "forecast", capability: "action_forecast" },
];

const jacksonImage = `ghcr.io/brainvi-ai/brainvi-carefloor-jackson@sha256:${"c".repeat(64)}`;
const maryImage = `ghcr.io/brainvi-ai/brainvi-watchfloor-perception@sha256:${"d".repeat(64)}`;
const t1Image = `ghcr.io/brainvi-ai/brainvi-watchfloor-t1@sha256:${"e".repeat(64)}`;
const templates = {
  "jackson-template": { imageName: jacksonImage },
  "mary-template": { imageName: maryImage },
  "t1-template": { imageName: t1Image },
};
const jacksonEndpoint = {
  id: "jackson-endpoint",
  name: "brainvi-carefloor-jackson",
  templateId: "jackson-template",
  workersMin: 0,
  workersMax: 0,
};
const maryEndpoint = {
  id: "mary-endpoint",
  name: "brainvi-carefloor-mary",
  templateId: "mary-template",
  workersMin: 0,
  workersMax: 0,
};
const t1Endpoint = {
  id: "t1-endpoint",
  name: "brainvi-carefloor-t1",
  templateId: "t1-template",
  workersMin: 0,
  workersMax: 0,
};

const environment = () => ({
  CAREFLOOR_DEPLOYMENT_URL: "https://brainvi-carefloor-test.vercel.app",
  CAREFLOOR_RELEASE_CANARY_SECRET: "canary-secret-with-32-byte-minimum",
  CAREFLOOR_RELEASE_SOURCE_SHA: "a".repeat(40),
  WATCHFLOOR_CANDIDATE_MANIFEST_SHA256: "b".repeat(64),
  CAREFLOOR_RUNPOD_CONTROL_API_KEY: "control-key",
  CAREFLOOR_WORKER_EXECUTION_PUBLIC_KEY_PEM: executionKeys.publicKey.export({ type: "spki", format: "pem" }),
  CAREFLOOR_RUNPOD_API_KEY: "mary-inference-key",
  CAREFLOOR_RUNPOD_ENDPOINT_ID: "mary-endpoint",
  CAREFLOOR_RUNPOD_IMAGE: maryImage,
  CAREFLOOR_RUNPOD_CONFIGURATION_SHA256: runpodConfigurationSha256(
    maryEndpoint,
    templates["mary-template"],
  ),
  CAREFLOOR_JACKSON_RUNPOD_API_KEY: "jackson-inference-key",
  CAREFLOOR_JACKSON_RUNPOD_ENDPOINT_ID: "jackson-endpoint",
  CAREFLOOR_JACKSON_RUNPOD_IMAGE: jacksonImage,
  CAREFLOOR_JACKSON_RUNPOD_CONFIGURATION_SHA256: runpodConfigurationSha256(
    jacksonEndpoint,
    templates["jackson-template"],
  ),
  CAREFLOOR_JACKSON_WORKER_EXECUTION_PUBLIC_KEY_PEM:
    jacksonExecutionKeys.publicKey.export({ type: "spki", format: "pem" }),
  CAREFLOOR_JACKSON_MODEL: "brainvi-jackson",
  CAREFLOOR_JACKSON_MODEL_REVISION: "f".repeat(40),
  CAREFLOOR_JACKSON_MODEL_SHA256: "1".repeat(64),
  CAREFLOOR_JACKSON_RUNTIME_SHA256: "2".repeat(64),
  CAREFLOOR_JACKSON_CONFIG_SHA256: "3".repeat(64),
  CAREFLOOR_JACKSON_RIGHTS_ARTIFACT_SHA256: "4".repeat(64),
  CAREFLOOR_JACKSON_NETWORK_VOLUME_MANIFEST_SHA256: "5".repeat(64),
  CAREFLOOR_T1_RUNPOD_API_KEY: "t1-inference-key",
  CAREFLOOR_T1_RUNPOD_ENDPOINT_ID: "t1-endpoint",
  CAREFLOOR_T1_RUNPOD_IMAGE: t1Image,
  CAREFLOOR_T1_RUNPOD_CONFIGURATION_SHA256: runpodConfigurationSha256(
    t1Endpoint,
    templates["t1-template"],
  ),
  CAREFLOOR_RELEASE_CANARY_MAX_COST_USD: "1",
  RUNNER_TEMP: "/tmp",
});

function fixture({
  canaryStatus = 200,
  invalidReceipt = false,
  invalidExecution = false,
  invalidJacksonExecution = false,
  invalidT1Evidence = false,
} = {}) {
  const endpoints = [structuredClone(maryEndpoint), structuredClone(jacksonEndpoint), structuredClone(t1Endpoint)];
  const calls = [];
  const fetcher = async (input, init = {}) => {
    const url = new URL(input);
    calls.push([init.method ?? "GET", url.href, init.body]);
    if (url.origin === "https://rest.runpod.io") {
      if (url.pathname === "/v1/endpoints") return Response.json(endpoints);
      const templateId = url.pathname.match(/^\/v1\/templates\/(.+)$/)?.[1];
      if (templateId) return Response.json(templates[templateId]);
      const endpointId = url.pathname.match(/^\/v1\/endpoints\/(.+)$/)?.[1];
      const endpoint = endpoints.find(({ id }) => id === endpointId);
      if (!endpoint) throw new Error(`unexpected RunPod URL ${url}`);
      if (init.method === "PATCH") Object.assign(endpoint, JSON.parse(init.body));
      return Response.json(endpoint);
    }
    if (url.pathname.endsWith("/status/mary-job")) {
      const output = {
        subjectTrackId: "release-track",
        annotations: invalidT1Evidence
          ? []
          : [
              {
                id: "facial-affect",
                family: "displayed_affect",
                label: "facial_valence_arousal",
                state: "provisional",
                sourceTrackIds: ["release-track"],
                confidence: 0.8,
                measurement: {
                  unit: "normalized_affect_axis",
                  values: { valence: 0.2, arousal: 0.4 },
                },
              },
            ],
        frame: {
          outputs: [
            {
              modelRelease: releaseModels.find(
                ({ capability }) => capability === "facial_affect",
              ),
              capability: "facial_affect",
              annotationIds: ["facial-affect"],
              quality: invalidT1Evidence ? "unavailable" : "provisional",
            },
          ],
        },
      };
      const receipt = {
        schema: "brainvi.carefloor.worker-execution-receipt.v1",
        attestationAuthority: "worker_origin",
        requestSha256: "1".repeat(64),
        workerImageDigest: `sha256:${"d".repeat(64)}`,
        modelReleases: releaseModels,
        jobId: "mary-job",
        completedAt: new Date().toISOString(),
        outputSha256: canonicalSha256(output),
      };
      return Response.json({
        id: "mary-job",
        status: "COMPLETED",
        output: {
          ...output,
          executionReceipt: {
            ...receipt,
            signature: invalidExecution
              ? Buffer.alloc(64).toString("base64")
              : sign(null, Buffer.from(JSON.stringify(receipt)), executionKeys.privateKey).toString("base64"),
          },
        },
      });
    }
    if (url.pathname.endsWith("/openai/v1/chat/completions")) {
      const request = JSON.parse(init.body);
      const requestRaw = Buffer.from(request.brainviRequestBase64, "base64");
      const output = {
        choices: [{ message: { content: "{}" } }],
      };
      const outputRaw = Buffer.from(JSON.stringify(output));
      const receipt = {
        schema: "brainvi.carefloor.jackson-execution-receipt.v1",
        attestationAuthority: "worker_origin",
        endpointId: "jackson-endpoint",
        workerImageDigest: `sha256:${"c".repeat(64)}`,
        model: "brainvi-jackson",
        modelRevision: "f".repeat(40),
        modelSha256: "1".repeat(64),
        runtimeSha256: "2".repeat(64),
        configSha256: "3".repeat(64),
        rightsArtifactSha256: "4".repeat(64),
        networkVolumeManifestSha256: "5".repeat(64),
        requestSha256: createHash("sha256").update(requestRaw).digest("hex"),
        outputSha256: createHash("sha256").update(outputRaw).digest("hex"),
        completedAt: new Date().toISOString(),
      };
      return Response.json({
        ...output,
        brainviOutputBase64: outputRaw.toString("base64"),
        executionReceipt: {
          ...receipt,
          signature: invalidJacksonExecution
            ? Buffer.alloc(64).toString("base64")
            : sign(
                null,
                Buffer.from(JSON.stringify(receipt)),
                jacksonExecutionKeys.privateKey,
              ).toString("base64"),
        },
      });
    }
    if (url.pathname.endsWith("/purge-queue")) return Response.json({ status: "completed" });
    if (url.pathname.endsWith("/health"))
      return Response.json({ workers: { idle: 0, running: 0 }, jobs: { inQueue: 0, inProgress: 0 } });
    if (url.pathname === "/api/version")
      return Response.json({
        gitHead: "a".repeat(40),
        candidateManifestSha256: "b".repeat(64),
      });
    if (url.pathname === "/api/internal/carefloor-release-canary") {
      const request = JSON.parse(init.body);
      return Response.json(
        {
          transaction: {
            schema: "brainvi.carefloor.release-transaction.v1",
            ...(invalidReceipt
              ? {}
              : {
                  sourceSha: "a".repeat(40),
                  candidateManifestSha256: "b".repeat(64),
                  releaseCanaryNonce: request.releaseCanaryNonce,
                  maryState: "source_bound_admitted",
                  t1State: "source_bound_provisional",
                  queryState: "jackson_verified",
                  dispatchState: "confirmed",
                  fhirState: "confirmed",
                  documentationState: "clinical_assessment_complete",
                  maryJobId: "mary-job",
                  maryRequestSha256: "1".repeat(64),
                  maryOutputSha256: canonicalSha256({
                    subjectTrackId: "release-track",
                    annotations: invalidT1Evidence
                      ? []
                      : [
                          {
                            id: "facial-affect",
                            family: "displayed_affect",
                            label: "facial_valence_arousal",
                            state: "provisional",
                            sourceTrackIds: ["release-track"],
                            confidence: 0.8,
                            measurement: {
                              unit: "normalized_affect_axis",
                              values: { valence: 0.2, arousal: 0.4 },
                            },
                          },
                        ],
                    frame: {
                      outputs: [
                        {
                          modelRelease: releaseModels.find(
                            ({ capability }) =>
                              capability === "facial_affect",
                          ),
                          capability: "facial_affect",
                          annotationIds: ["facial-affect"],
                          quality: invalidT1Evidence
                            ? "unavailable"
                            : "provisional",
                        },
                      ],
                    },
                  }),
                  jacksonReceiptId: "3".repeat(64),
                  fhirTransactionSha256: "4".repeat(64),
                  maryModelReleaseIds: releaseModels.map(({ id }) => id),
                  completedAt: new Date().toISOString(),
                }),
          },
          gaOperationsValidation: {
            schema: "brainvi.carefloor.ga-release-validation.v1",
            sourceSha: "a".repeat(40),
            candidateManifestSha256: "b".repeat(64),
            releaseCanaryNonce: request.releaseCanaryNonce,
            tenantId: "tenant",
            siteId: "site",
            intendedUseId: "intended-use",
            modelEvidenceSha256: "5".repeat(64),
            gaOperationsEvidenceSha256: "6".repeat(64),
          },
        },
        { status: canaryStatus },
      );
    }
    throw new Error(`unexpected URL ${url}`);
  };
  return { calls, endpoints, fetcher };
}

test("opens bounded MARY, T1, and Jackson capacity and leaves the admitted release live", async () => {
  const { calls, endpoints, fetcher } = fixture();
  const result = await runReleaseCanary(environment(), fetcher, async () => {});
  assert.equal(result.transaction.schema, "brainvi.carefloor.release-transaction.v1");
  assert.equal(result.cost.state, "validated_live");
  assert.ok(endpoints.every(({ workersMin, workersMax }) => workersMin === 0 && workersMax === 1));
  assert.ok(calls.some(([method, url, body]) => method === "PATCH" && url.endsWith("/mary-endpoint") && JSON.parse(body).workersMax === 1));
  assert.ok(calls.some(([method, url, body]) => method === "PATCH" && url.endsWith("/jackson-endpoint") && JSON.parse(body).workersMax === 1));
  assert.ok(calls.some(([method, url]) => method === "POST" && url.endsWith("/api/internal/carefloor-release-canary")));
  assert.ok(!calls.some(([method, url]) => method === "POST" && url.endsWith("/purge-queue")));
});

test("revalidates an already-live release without requiring a zero-capacity outage", async () => {
  const { calls, endpoints, fetcher } = fixture();
  endpoints.forEach((endpoint) => { endpoint.workersMax = 1; });
  const result = await runReleaseCanary(environment(), fetcher, async () => {});
  assert.equal(result.cost.state, "validated_live");
  assert.ok(endpoints.every(({ workersMax }) => workersMax === 1));
  assert.ok(!calls.some(([method, url]) => method === "PATCH" && url.includes("/v1/endpoints/")));
});

test("returns Jackson to exact zero when the deployed canary fails", async () => {
  const { endpoints, fetcher } = fixture({ canaryStatus: 500 });
  await assert.rejects(runReleaseCanary(environment(), fetcher, async () => {}), /canary failed/);
  assert.ok(endpoints.every(({ workersMin, workersMax }) => workersMin === 0 && workersMax === 0));
});

test("rejects candidate schema-only self-attestation and closes capacity", async () => {
  const { endpoints, fetcher } = fixture({ invalidReceipt: true });
  await assert.rejects(runReleaseCanary(environment(), fetcher, async () => {}), /receipt is invalid/);
  assert.ok(endpoints.every(({ workersMin, workersMax }) => workersMin === 0 && workersMax === 0));
});

test("rejects an unverified MARY execution and closes capacity", async () => {
  const { endpoints, fetcher } = fixture({ invalidExecution: true });
  await assert.rejects(runReleaseCanary(environment(), fetcher, async () => {}), /execution receipt is invalid/);
  assert.ok(endpoints.every(({ workersMin, workersMax }) => workersMin === 0 && workersMax === 0));
});

test("rejects a signed MARY result without source-bound T1 evidence", async () => {
  const { endpoints, fetcher } = fixture({ invalidT1Evidence: true });
  await assert.rejects(
    runReleaseCanary(environment(), fetcher, async () => {}),
    /T1 evidence is invalid/,
  );
  assert.ok(
    endpoints.every(
      ({ workersMin, workersMax }) => workersMin === 0 && workersMax === 0,
    ),
  );
});

test("rejects an unverified independent Jackson execution", async () => {
  const { endpoints, fetcher } = fixture({ invalidJacksonExecution: true });
  await assert.rejects(
    runReleaseCanary(environment(), fetcher, async () => {}),
    /Jackson canary execution receipt is invalid/,
  );
  assert.ok(
    endpoints.every(
      ({ workersMin, workersMax }) => workersMin === 0 && workersMax === 0,
    ),
  );
});

test("restores already-live capacity when a repeat-release canary fails", async () => {
  const { endpoints, fetcher } = fixture({ canaryStatus: 500 });
  endpoints.forEach((endpoint) => { endpoint.workersMax = 1; });
  await assert.rejects(runReleaseCanary(environment(), fetcher, async () => {}), /canary failed/);
  assert.ok(endpoints.every(({ workersMax }) => workersMax === 1));
});
