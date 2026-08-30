import assert from "node:assert/strict";
import test from "node:test";

import { runReleaseCanary } from "../.github/actions/run-release-canary/run-release-canary.mjs";
import { runpodConfigurationSha256 } from "../.github/actions/verify-control-plane/verify-control-plane.mjs";

const image = `ghcr.io/brainvi-ai/brainvi-carefloor-jackson@sha256:${"c".repeat(64)}`;
const template = { imageName: image };
const admittedEndpoint = {
  id: "jackson-endpoint",
  name: "brainvi-carefloor-jackson",
  templateId: "jackson-template",
  workersMin: 0,
  workersMax: 0,
};

const environment = () => ({
  CAREFLOOR_DEPLOYMENT_URL: "https://brainvi-carefloor-test.vercel.app",
  CAREFLOOR_RELEASE_CANARY_SECRET: "canary-secret-with-32-byte-minimum",
  CAREFLOOR_RELEASE_SOURCE_SHA: "a".repeat(40),
  WATCHFLOOR_CANDIDATE_MANIFEST_SHA256: "b".repeat(64),
  CAREFLOOR_RUNPOD_CONTROL_API_KEY: "control-key",
  CAREFLOOR_JACKSON_RUNPOD_API_KEY: "jackson-inference-key",
  CAREFLOOR_JACKSON_RUNPOD_ENDPOINT_ID: "jackson-endpoint",
  CAREFLOOR_JACKSON_RUNPOD_IMAGE: image,
  CAREFLOOR_JACKSON_RUNPOD_CONFIGURATION_SHA256: runpodConfigurationSha256(
    admittedEndpoint,
    template,
  ),
  CAREFLOOR_RELEASE_CANARY_MAX_COST_USD: "1",
  RUNNER_TEMP: "/tmp",
});

function fixture({ canaryStatus = 200 } = {}) {
  const endpoint = { ...admittedEndpoint };
  const calls = [];
  const fetcher = async (input, init = {}) => {
    const url = new URL(input);
    calls.push([init.method ?? "GET", url.href, init.body]);
    if (url.origin === "https://rest.runpod.io") {
      if (init.method === "PATCH") Object.assign(endpoint, JSON.parse(init.body));
      if (url.pathname === "/v1/endpoints") return Response.json([endpoint]);
      if (url.pathname === "/v1/templates/jackson-template") return Response.json(template);
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
  return { calls, endpoint, fetcher };
}

test("opens only bounded Jackson capacity, runs the bound canary, and returns exact zero", async () => {
  const { calls, endpoint, fetcher } = fixture();
  const result = await runReleaseCanary(environment(), fetcher, async () => {});
  assert.equal(result.transaction.schema, "brainvi.carefloor.release-transaction.v1");
  assert.equal(result.cost.exactZero, true);
  assert.equal(endpoint.workersMin, 0);
  assert.equal(endpoint.workersMax, 0);
  assert.ok(calls.some(([method, url, body]) => method === "PATCH" && url.endsWith("/jackson-endpoint") && JSON.parse(body).workersMax === 1));
  assert.ok(calls.some(([method, url]) => method === "POST" && url.endsWith("/api/internal/carefloor-release-canary")));
  assert.ok(calls.some(([method, url]) => method === "POST" && url.endsWith("/purge-queue")));
});

test("returns Jackson to exact zero when the deployed canary fails", async () => {
  const { endpoint, fetcher } = fixture({ canaryStatus: 500 });
  await assert.rejects(runReleaseCanary(environment(), fetcher, async () => {}), /canary failed/);
  assert.equal(endpoint.workersMin, 0);
  assert.equal(endpoint.workersMax, 0);
});

test("refuses an endpoint that is not exact-zero Carefloor capacity", async () => {
  const { endpoint, fetcher } = fixture();
  endpoint.workersMax = 1;
  await assert.rejects(runReleaseCanary(environment(), fetcher, async () => {}), /standby boundary/);
});
