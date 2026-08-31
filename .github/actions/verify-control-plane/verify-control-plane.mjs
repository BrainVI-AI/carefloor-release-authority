import { appendFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const SHA256 = /^[a-f0-9]{64}$/;
const IMAGE = Object.freeze({
  mary: /^ghcr\.io\/brainvi-ai\/brainvi-watchfloor-perception@sha256:[a-f0-9]{64}$/,
  t1: /^ghcr\.io\/brainvi-ai\/brainvi-watchfloor-t1@sha256:[a-f0-9]{64}$/,
  jackson: /^ghcr\.io\/brainvi-ai\/brainvi-carefloor-jackson@sha256:[a-f0-9]{64}$/,
});
const RUNPOD_SECRET_REFERENCE = /^\{\{ RUNPOD_SECRET_[A-Za-z0-9_-]{1,128} \}\}$/;

const required = (environment, name) => {
  const result = environment[name]?.trim();
  if (!result) throw new Error(`Carefloor release operations requires ${name}`);
  return result;
};

const canonical = (value) => {
  if (typeof value === "string") {
    for (let index = 0; index < value.length; index += 1) {
      const code = value.charCodeAt(index);
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = value.charCodeAt(++index);
        if (!(next >= 0xdc00 && next <= 0xdfff))
          throw new Error("canonical Unicode must be well-formed");
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        throw new Error("canonical Unicode must be well-formed");
      }
    }
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value)))
      throw new Error("canonical numbers must be finite IEEE-754 values");
    const bytes = new ArrayBuffer(8);
    new DataView(bytes).setFloat64(0, value);
    return `n:${Buffer.from(bytes).toString("hex")}`;
  }
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, item]) => item !== undefined)
        .sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right)))
        .map(([key, item]) => [key, canonical(item)]),
    );
  return value;
};

export const canonicalSha256 = (value) =>
  createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");

export const runpodConfigurationSha256 = (endpoint, template) =>
  canonicalSha256({
    endpoint: {
      allowedCudaVersions: endpoint.allowedCudaVersions,
      computeType: endpoint.computeType,
      dataCenterIds: endpoint.dataCenterIds,
      executionTimeoutMs: endpoint.executionTimeoutMs,
      flashboot: endpoint.flashboot,
      gpuCount: endpoint.gpuCount,
      gpuTypeIds: endpoint.gpuTypeIds,
      idleTimeout: endpoint.idleTimeout,
      minCudaVersion: endpoint.minCudaVersion,
      networkVolumeId: endpoint.networkVolumeId,
      networkVolumeIds: endpoint.networkVolumeIds,
      scalerType: endpoint.scalerType,
      scalerValue: endpoint.scalerValue,
      templateId: endpoint.templateId,
      vcpuCount: endpoint.vcpuCount,
      workersMax: endpoint.workersMax,
      workersMin: endpoint.workersMin,
    },
    template: {
      containerDiskInGb: template.containerDiskInGb,
      containerRegistryAuthId: template.containerRegistryAuthId,
      dockerEntrypoint: template.dockerEntrypoint,
      dockerStartCmd: template.dockerStartCmd,
      env: template.env,
      imageName: template.imageName,
      isPublic: template.isPublic,
      isRunpod: template.isRunpod,
      isServerless: template.isServerless,
      ports: template.ports,
      runtimeInMin: template.runtimeInMin,
      volumeInGb: template.volumeInGb,
      volumeMountPath: template.volumeMountPath,
    },
  });

const fetchJson = async (url, origin, token, fetcher) => {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" || parsed.origin !== origin)
    throw new Error("Carefloor authority connector origin is invalid");
  const response = await fetcher(parsed, {
    headers: { accept: "application/json", authorization: `Bearer ${token}` },
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`Carefloor authority connector failed: ${response.status}`);
  const text = await response.text();
  if (Buffer.byteLength(text) > 1_000_000)
    throw new Error("Carefloor authority connector response is too large");
  return JSON.parse(text);
};

const assertCapacity = (kind, endpoint, template, workersMax) => {
  if (
    endpoint.workersMin !== 0 ||
    endpoint.workersMax !== workersMax ||
    endpoint.computeType !== "GPU" ||
    endpoint.gpuCount !== 1 ||
    template.isServerless !== true ||
    template.isPublic !== false
  ) throw new Error(`Carefloor ${kind} RunPod runtime boundary is invalid`);
};

const verifyJacksonCustody = (environment, endpoint, template, image) => {
  const imageDigest = image.split("@sha256:")[1];
  const publicKey = required(environment, "CAREFLOOR_JACKSON_WORKER_EXECUTION_PUBLIC_KEY_PEM");
  const custody = {
    model: required(environment, "CAREFLOOR_JACKSON_MODEL"),
    modelRevision: required(environment, "CAREFLOOR_JACKSON_MODEL_REVISION"),
    modelSha256: required(environment, "CAREFLOOR_JACKSON_MODEL_SHA256"),
    runtimeSha256: required(environment, "CAREFLOOR_JACKSON_RUNTIME_SHA256"),
    configSha256: required(environment, "CAREFLOOR_JACKSON_CONFIG_SHA256"),
    rightsArtifactSha256: required(environment, "CAREFLOOR_JACKSON_RIGHTS_ARTIFACT_SHA256"),
    networkVolumeManifestSha256: required(environment, "CAREFLOOR_JACKSON_NETWORK_VOLUME_MANIFEST_SHA256"),
    executionPublicKeySha256: createHash("sha256").update(publicKey).digest("hex"),
  };
  if (
    !/^[A-Za-z0-9_-]{1,128}$/.test(endpoint.networkVolumeId ?? "") ||
    custody.model.length > 256 ||
    !/^[a-f0-9]{40,64}$/.test(custody.modelRevision) ||
    Object.entries(custody).filter(([name]) => name.endsWith("Sha256")).some(([, digest]) => !SHA256.test(digest)) ||
    !template.env || typeof template.env !== "object" || Array.isArray(template.env)
  ) throw new Error("Carefloor Jackson model custody is invalid");
  const configured = template.env;
  const privateKeyReference = configured.BRAINVI_JACKSON_EXECUTION_PRIVATE_KEY_PEM;
  const measuredConfigSha256 = createHash("sha256")
    .update(JSON.stringify(Object.fromEntries(Object.entries({
      endpointId: endpoint.id,
      executionPrivateKeyReference: privateKeyReference,
      executionPublicKeySha256: custody.executionPublicKeySha256,
      hfHome: "/runpod-volume/carefloor-jackson/model",
      hfHubOffline: "1",
      imageDigest: `sha256:${imageDigest}`,
      model: custody.model,
      modelRevision: custody.modelRevision,
      modelSha256: custody.modelSha256,
      modelVolumeManifestPath: "/runpod-volume/carefloor-jackson/brainvi-model-manifest.json",
      networkVolumeManifestSha256: custody.networkVolumeManifestSha256,
      rightsArtifactSha256: custody.rightsArtifactSha256,
      runtimeSha256: custody.runtimeSha256,
    }).sort(([left], [right]) => left.localeCompare(right)))))
    .digest("hex");
  const expected = {
    BRAINVI_JACKSON_ENDPOINT_ID: endpoint.id,
    BRAINVI_WORKER_IMAGE_DIGEST: `sha256:${imageDigest}`,
    BRAINVI_JACKSON_EXECUTION_PUBLIC_KEY_PEM: publicKey,
    MODEL_NAME: custody.model,
    MODEL_REVISION: custody.modelRevision,
    BRAINVI_MODEL_SHA256: custody.modelSha256,
    BRAINVI_RUNTIME_SHA256: custody.runtimeSha256,
    BRAINVI_CONFIG_SHA256: custody.configSha256,
    BRAINVI_RIGHTS_ARTIFACT_SHA256: custody.rightsArtifactSha256,
    BRAINVI_MODEL_VOLUME_MANIFEST_SHA256: custody.networkVolumeManifestSha256,
    BRAINVI_MODEL_VOLUME_MANIFEST_PATH: "/runpod-volume/carefloor-jackson/brainvi-model-manifest.json",
    HF_HOME: "/runpod-volume/carefloor-jackson/model",
    HF_HUB_OFFLINE: "1",
  };
  const keys = [...Object.keys(expected), "BRAINVI_JACKSON_EXECUTION_PRIVATE_KEY_PEM"].sort();
  if (
    !RUNPOD_SECRET_REFERENCE.test(privateKeyReference ?? "") ||
    custody.runtimeSha256 !== imageDigest ||
    custody.configSha256 !== measuredConfigSha256 ||
    JSON.stringify(Object.keys(configured).sort()) !== JSON.stringify(keys) ||
    Object.entries(expected).some(([name, expectedValue]) => configured[name] !== expectedValue)
  ) throw new Error("Carefloor Jackson model custody is invalid");
  return custody;
};

const verifyNeon = async (environment, fetcher) => {
  const projectId = required(environment, "CAREFLOOR_NEON_PROJECT_ID");
  const apiKey = required(environment, "CAREFLOOR_NEON_API_KEY");
  const approvedDays = Number(required(environment, "CAREFLOOR_BACKUP_RETENTION_DAYS"));
  const databaseHost = new URL(required(environment, "CAREFLOOR_DATABASE_URL")).hostname.toLowerCase();
  if (!/^[a-z0-9-]{1,60}$/.test(projectId) || !Number.isInteger(approvedDays) || approvedDays < 1 || approvedDays > 365)
    throw new Error("Carefloor Neon retention configuration is invalid");
  const result = await fetchJson(
    `https://console.neon.tech/api/v2/projects/${projectId}`,
    "https://console.neon.tech",
    apiKey,
    fetcher,
  );
  const hosts = new Set();
  for (const connection of Array.isArray(result.connection_uris) ? result.connection_uris.slice(0, 101) : []) {
    if (result.connection_uris.length > 100) throw new Error("Carefloor Neon inventory is invalid");
    const parameters = connection?.connection_parameters;
    for (const key of ["host", "pooler_host"])
      if (typeof parameters?.[key] === "string") hosts.add(parameters[key].toLowerCase());
    if (typeof connection?.connection_uri === "string" && URL.canParse(connection.connection_uri))
      hosts.add(new URL(connection.connection_uri).hostname.toLowerCase());
  }
  const seconds = result.project?.history_retention_seconds;
  if (result.project?.id !== projectId || !hosts.has(databaseHost) || seconds !== approvedDays * 86_400)
    throw new Error("Carefloor Neon project, database, or retention is invalid");
  return seconds;
};

export async function verifyControlPlane(environment, fetcher = fetch, now = new Date()) {
  const sourceSha = required(environment, "CAREFLOOR_RELEASE_SOURCE_SHA");
  const tenantId = required(environment, "CAREFLOOR_TENANT_ID");
  if (!/^[a-f0-9]{40}$/.test(sourceSha)) throw new Error("Carefloor release source SHA is invalid");
  const controlKey = required(environment, "CAREFLOOR_RUNPOD_CONTROL_API_KEY");
  const workersMax = Number(environment.CAREFLOOR_RUNPOD_EXPECTED_WORKERS_MAX ?? "0");
  if (![0, 1].includes(workersMax))
    throw new Error("Carefloor RunPod serving capacity is invalid");
  const endpoints = await fetchJson("https://rest.runpod.io/v1/endpoints", "https://rest.runpod.io", controlKey, fetcher);
  if (!Array.isArray(endpoints) || endpoints.length > 10_000)
    throw new Error("Carefloor RunPod endpoint inventory is invalid");
  const runpod = [];
  for (const kind of ["mary", "t1", "jackson"]) {
    const prefix = kind === "mary" ? "CAREFLOOR_RUNPOD" : `CAREFLOOR_${kind.toUpperCase()}_RUNPOD`;
    if (kind === "t1" && !environment[`${prefix}_ENDPOINT_ID`]?.trim() && !environment[`${prefix}_IMAGE`]?.trim()) continue;
    const endpointId = required(environment, `${prefix}_ENDPOINT_ID`);
    const image = required(environment, `${prefix}_IMAGE`);
    if (!IMAGE[kind].test(image)) throw new Error(`Carefloor ${kind} image is invalid`);
    const endpoint = endpoints.find((candidate) => candidate?.id === endpointId);
    if (!endpoint || !/^[A-Za-z0-9_-]{1,128}$/.test(endpoint.templateId ?? ""))
      throw new Error(`Carefloor ${kind} endpoint is not bound`);
    const template = await fetchJson(`https://rest.runpod.io/v1/templates/${endpoint.templateId}`, "https://rest.runpod.io", controlKey, fetcher);
    if (template.imageName !== image) throw new Error(`Carefloor ${kind} image binding is invalid`);
    assertCapacity(kind, endpoint, template, workersMax);
    const configurationSha256 = runpodConfigurationSha256(
      { ...endpoint, workersMin: 0, workersMax: 0 },
      template,
    );
    if (configurationSha256 !== required(environment, `${prefix}_CONFIGURATION_SHA256`))
      throw new Error(`Carefloor ${kind} configuration hash mismatch`);
    if (kind === "mary" && environment.CAREFLOOR_T1_RUNPOD_ENDPOINT_ID?.trim()) {
      const configured = template.env;
      if (
        !configured ||
        typeof configured !== "object" ||
        Array.isArray(configured) ||
        configured.CAREFLOOR_T1_RUNPOD_ENDPOINT_ID !== environment.CAREFLOOR_T1_RUNPOD_ENDPOINT_ID.trim() ||
        !RUNPOD_SECRET_REFERENCE.test(configured.CAREFLOOR_T1_RUNPOD_API_KEY ?? "")
      ) throw new Error("Carefloor Mary-to-T1 credential binding is invalid");
    }
    runpod.push(Object.freeze({
      kind,
      endpointId,
      templateId: endpoint.templateId,
      image,
      configurationSha256,
      workersMin: 0,
      workersMax,
      ...(kind === "jackson" ? { networkVolumeId: endpoint.networkVolumeId, ...verifyJacksonCustody(environment, endpoint, template, image) } : {}),
    }));
  }
  const historyRetentionSeconds = await verifyNeon(environment, fetcher);
  const inferenceKeys = {
    mary: environment.CAREFLOOR_RUNPOD_API_KEY?.trim(),
    t1: environment.CAREFLOOR_T1_RUNPOD_API_KEY?.trim(),
    jackson: environment.CAREFLOOR_JACKSON_RUNPOD_API_KEY?.trim(),
  };
  if (Object.values(inferenceKeys).some(Boolean)) {
    const bindings = runpod.map(({ kind, endpointId }) => [
      inferenceKeys[kind],
      endpointId,
    ]);
    if (
      bindings.some(([key]) => !key || key === controlKey) ||
      new Set(bindings.map(([key]) => key)).size !== bindings.length
    ) throw new Error("Carefloor RunPod inference credentials are not isolated");
    for (const [key, endpointId] of bindings) {
      const headers = { authorization: `Bearer ${key}` };
      const health = await fetcher(`https://api.runpod.ai/v2/${endpointId}/health`, {
        headers,
        cache: "no-store",
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
      if (!health.ok) throw new Error("Carefloor RunPod inference credential cannot invoke its endpoint");
      const management = await fetcher("https://rest.runpod.io/v1/endpoints", {
        headers,
        cache: "no-store",
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
      if (![401, 403].includes(management.status))
        throw new Error("Carefloor RunPod inference credential has management authority");
    }
  }
  return Object.freeze({
    schema: "brainvi.carefloor.control-plane-release.v1",
    sourceSha,
    tenantId,
    verifiedAt: now.toISOString(),
    validUntil: new Date(now.getTime() + 3_600_000).toISOString(),
    approvedBy: required(environment, "CAREFLOOR_RELEASE_APPROVED_BY"),
    neon: Object.freeze({ projectId: required(environment, "CAREFLOOR_NEON_PROJECT_ID"), historyRetentionSeconds }),
    runpod: Object.freeze(runpod),
  });
}

async function main() {
  const receipt = await verifyControlPlane(process.env);
  const output = join(required(process.env, "RUNNER_TEMP"), "carefloor-control-plane.json");
  await writeFile(output, `${JSON.stringify(receipt)}\n`, { mode: 0o600 });
  await appendFile(required(process.env, "GITHUB_OUTPUT"), `receipt-path=${output}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : "Carefloor authority verification failed");
    process.exitCode = 1;
  });
