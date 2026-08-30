import assert from "node:assert/strict";
import test from "node:test";

import { runReleaseCanary } from "../.github/actions/run-release-canary/run-release-canary.mjs";
import { runpodConfigurationSha256 } from "../.github/actions/verify-control-plane/verify-control-plane.mjs";

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

function fixture({ canaryStatus = 200 } = {}) {
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
    if (url.pathname.endsWith("/purge-queue")) return Response.json({ status: "completed" });
    if (url.pathname.endsWith("/health"))
      return Response.json({ workers: { idle: 0, running: 0 }, jobs: { inQueue: 0, inProgress: 0 } });
    if (url.pathname === "/api/version")
      return Response.json({
        gitHead: "a".repeat(40),
        candidateManifestSha256: "b".repeat(64),
      });
    if (url.pathname === "/api/internal/carefloor-release-canary")
      return Response.json(
        {
          transaction: { schema: "brainvi.carefloor.release-transaction.v1" },
          gaOperationsValidation: { schema: "brainvi.carefloor.ga-release-validation.v1" },
        },
        { status: canaryStatus },
      );
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

test("returns Jackson to exact zero when the deployed canary fails", async () => {
  const { endpoints, fetcher } = fixture({ canaryStatus: 500 });
  await assert.rejects(runReleaseCanary(environment(), fetcher, async () => {}), /canary failed/);
  assert.ok(endpoints.every(({ workersMin, workersMax }) => workersMin === 0 && workersMax === 0));
});

test("refuses an endpoint that is not exact-zero Carefloor capacity", async () => {
  const { endpoints, fetcher } = fixture();
  endpoints[0].workersMax = 1;
  await assert.rejects(runReleaseCanary(environment(), fetcher, async () => {}), /standby boundary/);
});
