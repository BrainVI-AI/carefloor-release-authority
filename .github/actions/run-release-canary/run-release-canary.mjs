import { appendFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const GIT_SHA = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const SAFE_ID = /^[A-Za-z0-9_-]{1,128}$/;

const required = (environment, name) => {
  const value = environment[name]?.trim();
  if (!value) throw new Error(`Carefloor release canary requires ${name}`);
  return value;
};

const readJson = async (response, label) => {
  const text = await response.text();
  if (Buffer.byteLength(text) > 1_000_000)
    throw new Error(`${label} response is too large`);
  let value;
  try {
    value = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`${label} returned invalid JSON`);
  }
  if (!response.ok) throw new Error(`${label} failed (${response.status})`);
  return value;
};

const runpodRequest = async (fetcher, controlKey, method, path, body) =>
  readJson(
    await fetcher(`https://rest.runpod.io/v1/${path}`, {
      method,
      headers: {
        accept: "application/json",
        authorization: `Bearer ${controlKey}`,
        ...(body ? { "content-type": "application/json" } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    }),
    "RunPod management request",
  );

const endpointFromInventory = (inventory, endpointId) => {
  const endpoints = Array.isArray(inventory)
    ? inventory
    : inventory?.items ?? inventory?.data ?? inventory?.endpoints;
  if (!Array.isArray(endpoints) || endpoints.length > 10_000)
    throw new Error("RunPod endpoint inventory is invalid");
  const endpoint = endpoints.find(({ id }) => id === endpointId);
  if (!endpoint || !String(endpoint.name ?? "").toLowerCase().includes("carefloor"))
    throw new Error("Jackson endpoint is not Carefloor-owned");
  return endpoint;
};

const assertCapacity = (endpoint, workersMax, label) => {
  if (endpoint.workersMin !== 0 || endpoint.workersMax !== workersMax)
    throw new Error(`Jackson ${label} boundary is invalid`);
};

async function verifyExactZero(fetcher, controlKey, endpointId, inferenceKey, wait) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const endpoint = await runpodRequest(fetcher, controlKey, "GET", `endpoints/${endpointId}`);
    assertCapacity(endpoint, 0, "teardown");
    const health = await readJson(
      await fetcher(`https://api.runpod.ai/v2/${endpointId}/health`, {
        headers: { authorization: `Bearer ${inferenceKey}` },
        cache: "no-store",
        redirect: "error",
        signal: AbortSignal.timeout(30_000),
      }),
      "RunPod health request",
    );
    const workers = health?.workers;
    const jobs = health?.jobs;
    if (!workers || !jobs || Object.values(workers).some((value) => !Number.isInteger(value) || value < 0))
      throw new Error("RunPod health payload is invalid");
    if (
      Object.values(workers).every((value) => value === 0) &&
      [jobs.inQueue ?? 0, jobs.inProgress ?? 0].every((value) => value === 0)
    ) return;
    if (attempt < 29) await wait(2_000);
  }
  throw new Error("Jackson capacity did not return to exact zero");
}

export async function runReleaseCanary(environment, fetcher = fetch, wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms))) {
  const deploymentUrl = new URL(required(environment, "CAREFLOOR_DEPLOYMENT_URL"));
  if (deploymentUrl.protocol !== "https:" || !deploymentUrl.hostname.endsWith(".vercel.app") || deploymentUrl.pathname !== "/")
    throw new Error("Carefloor release deployment URL is invalid");
  const sourceSha = required(environment, "CAREFLOOR_RELEASE_SOURCE_SHA");
  const candidateManifestSha256 = required(environment, "WATCHFLOOR_CANDIDATE_MANIFEST_SHA256");
  const endpointId = required(environment, "CAREFLOOR_JACKSON_RUNPOD_ENDPOINT_ID");
  const controlKey = required(environment, "CAREFLOOR_RUNPOD_CONTROL_API_KEY");
  const inferenceKey = required(environment, "CAREFLOOR_JACKSON_RUNPOD_API_KEY");
  const canarySecret = required(environment, "CAREFLOOR_RELEASE_CANARY_SECRET");
  const maxCostUsd = Number(required(environment, "CAREFLOOR_RELEASE_CANARY_MAX_COST_USD"));
  if (!GIT_SHA.test(sourceSha) || !SHA256.test(candidateManifestSha256) || !SAFE_ID.test(endpointId) || canarySecret.length < 32 || controlKey === inferenceKey || !Number.isFinite(maxCostUsd) || maxCostUsd <= 0 || maxCostUsd > 1)
    throw new Error("Carefloor release canary binding is invalid");

  const version = await readJson(
    await fetcher(new URL("/api/version", deploymentUrl), {
      headers: environment.VERCEL_AUTOMATION_BYPASS_SECRET
        ? { "x-vercel-protection-bypass": environment.VERCEL_AUTOMATION_BYPASS_SECRET }
        : {},
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    }),
    "Carefloor version",
  );
  if (version?.gitHead !== sourceSha || version?.candidateManifestSha256 !== candidateManifestSha256)
    throw new Error("Carefloor deployed candidate binding mismatch");

  const standby = endpointFromInventory(
    await runpodRequest(fetcher, controlKey, "GET", "endpoints"),
    endpointId,
  );
  assertCapacity(standby, 0, "standby");
  const startedAt = new Date();
  let opened = false;
  let result;
  let failure;
  try {
    await runpodRequest(fetcher, controlKey, "PATCH", `endpoints/${endpointId}`, {
      workersMin: 0,
      workersMax: 1,
    });
    opened = true;
    assertCapacity(
      await runpodRequest(fetcher, controlKey, "GET", `endpoints/${endpointId}`),
      1,
      "bounded canary",
    );
    result = await readJson(
      await fetcher(new URL("/api/internal/carefloor-release-canary", deploymentUrl), {
        method: "POST",
        headers: {
          authorization: `Bearer ${canarySecret}`,
          "content-type": "application/json",
          ...(environment.VERCEL_AUTOMATION_BYPASS_SECRET
            ? { "x-vercel-protection-bypass": environment.VERCEL_AUTOMATION_BYPASS_SECRET }
            : {}),
        },
        body: JSON.stringify({ sourceSha, candidateManifestSha256 }),
        cache: "no-store",
        redirect: "error",
        signal: AbortSignal.timeout(300_000),
      }),
      "Carefloor release canary",
    );
    if (
      result?.transaction?.schema !== "brainvi.carefloor.release-transaction.v1" ||
      result?.gaOperationsValidation?.schema !== "brainvi.carefloor.ga-release-validation.v1"
    ) throw new Error("Carefloor release canary receipt is invalid");
  } catch (error) {
    failure = error;
  } finally {
    if (opened) {
      try {
        await readJson(
          await fetcher(`https://api.runpod.ai/v2/${endpointId}/purge-queue`, {
            method: "POST",
            headers: { authorization: `Bearer ${inferenceKey}` },
            cache: "no-store",
            redirect: "error",
            signal: AbortSignal.timeout(30_000),
          }),
          "RunPod queue purge",
        );
        await runpodRequest(fetcher, controlKey, "PATCH", `endpoints/${endpointId}`, {
          workersMin: 0,
          workersMax: 0,
        });
        await verifyExactZero(fetcher, controlKey, endpointId, inferenceKey, wait);
      } catch (error) {
        failure = failure ?? error;
      }
    }
  }
  if (failure) throw failure;
  return {
    ...result,
    cost: {
      schema: "brainvi.carefloor.runpod-canary-cost.v1",
      endpointId,
      sourceSha,
      startedAt: startedAt.toISOString(),
      completedAt: new Date().toISOString(),
      maxCostUsd,
      workersMin: 0,
      workersMax: 0,
      exactZero: true,
    },
  };
}

async function main() {
  const result = await runReleaseCanary(process.env);
  const directory = required(process.env, "RUNNER_TEMP");
  const paths = {
    transaction: join(directory, "carefloor-release-transaction.json"),
    cost: join(directory, "carefloor-jackson-cost.json"),
    ga: join(directory, "carefloor-ga-validation.json"),
  };
  await Promise.all([
    writeFile(paths.transaction, `${JSON.stringify(result.transaction)}\n`, { mode: 0o600 }),
    writeFile(paths.cost, `${JSON.stringify(result.cost)}\n`, { mode: 0o600 }),
    writeFile(paths.ga, `${JSON.stringify(result.gaOperationsValidation)}\n`, { mode: 0o600 }),
  ]);
  await appendFile(required(process.env, "GITHUB_OUTPUT"), [
    `transaction-path=${paths.transaction}`,
    `cost-path=${paths.cost}`,
    `ga-validation-path=${paths.ga}`,
    "",
  ].join("\n"));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : "Carefloor release canary failed");
    process.exitCode = 1;
  });
