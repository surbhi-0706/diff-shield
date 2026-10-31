export interface ThreatFinding {
  id: string;
  title: string;
  repository: string;
  description: string;
  severity: string;
  detectedAt: string;
  cve_cwe?: string;
  file_path?: string;
  prUrl?: string;
}

export interface LatestScan {
  status: string;
  scannedAt: string;
  prUrl: string;
  error?: string;
  repository?: string;
  prNumber?: number;
  riskScore?: number;
  finding?: ThreatFinding | null;
}

export type QuarantineState =
  | "SCANNING"
  | "CLEAN"
  | "QUARANTINED"
  | "REVIEW_REQUIRED"
  | "ESCALATED"
  | "RESOLVED"
  | "REJECTED"
  | "ERROR";

export interface QuarantineRecord {
  finding_id: string;
  repository: string;
  pr_number: number;
  pr_url: string;
  pr_title?: string | null;
  pr_author?: string | null;
  head_sha?: string | null;
  base_sha?: string | null;
  finding: Record<string, unknown>;
  severity: string;
  risk_score: number;
  confidence?: number | null;
  detected_at: string;
  quarantine_started_at?: string | null;
  review_deadline?: string | null;
  state: QuarantineState;
  review_history: Array<Record<string, unknown>>;
  reviewer_identity?: string | null;
  resolution_reason?: string | null;
  check_run_id?: number | null;
}

export interface QuarantineListResponse {
  items: QuarantineRecord[];
  merge_protection: {
    status: string;
    reason?: string;
  };
}

export interface GitHubStatus {
  app_configured: boolean;
  installed: boolean | null;
  required_check_configured: boolean | null;
  merge_protection: string;
  reason: string;
}

interface RuntimeResponse<T> {
  ok: boolean;
  result?: T;
  error?: string;
}

interface ChromeExtensionApi {
  runtime?: {
    lastError?: { message?: string };
    sendMessage<T>(
      message: { type: string; repository?: string },
      callback: (response?: RuntimeResponse<T>) => void,
    ): void;
  };
  storage?: {
    local: {
      get(
        key: string,
        callback: (items: Record<string, unknown>) => void,
      ): void;
      remove(key: string, callback: () => void): void;
    };
    onChanged: {
      addListener(
        listener: (
          changes: Record<string, { newValue?: unknown }>,
          areaName: string,
        ) => void,
      ): void;
      removeListener(
        listener: (
          changes: Record<string, { newValue?: unknown }>,
          areaName: string,
        ) => void,
      ): void;
    };
  };
}

const extensionApi = (
  globalThis as typeof globalThis & { chrome?: ChromeExtensionApi }
).chrome;
const BACKEND_HEALTH_URL = "http://127.0.0.1:8000/health";
const QUARANTINE_API_URL = "http://127.0.0.1:8000/api/quarantines";

export function isThreatFinding(value: unknown): value is ThreatFinding {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const finding = value as Record<string, unknown>;

  return (
    typeof finding.id === "string" &&
    typeof finding.title === "string" &&
    typeof finding.repository === "string" &&
    typeof finding.description === "string" &&
    typeof finding.severity === "string" &&
    typeof finding.detectedAt === "string"
  );
}

function isLatestScan(value: unknown): value is LatestScan {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const scan = value as Record<string, unknown>;
  return (
    typeof scan.status === "string" &&
    typeof scan.scannedAt === "string" &&
    typeof scan.prUrl === "string"
  );
}

function isQuarantineRecord(value: unknown): value is QuarantineRecord {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record.finding_id === "string" &&
    typeof record.repository === "string" &&
    typeof record.pr_number === "number" &&
    typeof record.pr_url === "string" &&
    typeof record.state === "string" &&
    typeof record.detected_at === "string" &&
    typeof record.risk_score === "number" &&
    typeof record.finding === "object" &&
    record.finding !== null
  );
}

function isQuarantineListResponse(
  value: unknown,
): value is QuarantineListResponse {
  if (typeof value !== "object" || value === null) return false;
  const result = value as Record<string, unknown>;
  return (
    Array.isArray(result.items) &&
    result.items.every(isQuarantineRecord) &&
    typeof result.merge_protection === "object" &&
    result.merge_protection !== null
  );
}

export function listQuarantines(): Promise<QuarantineListResponse> {
  const runtime = extensionApi?.runtime;
  if (typeof runtime?.sendMessage === "function") {
    return new Promise((resolve, reject) => {
      runtime.sendMessage<unknown>(
        { type: "DIFF_SHIELD_LIST_QUARANTINES" },
        (response) => {
          const error = extensionApi?.runtime?.lastError?.message;
          if (error) {
            reject(new Error(error));
            return;
          }
          if (!response?.ok || !isQuarantineListResponse(response.result)) {
            reject(new Error(response?.error ?? "Invalid quarantine data from backend."));
            return;
          }
          resolve(response.result);
        },
      );
    });
  }

  return fetch(QUARANTINE_API_URL, {
    headers: { Accept: "application/json" },
  }).then(async (response) => {
    if (!response.ok) {
      throw new Error(`Could not load quarantines (${response.status}).`);
    }
    const data: unknown = await response.json();
    if (!isQuarantineListResponse(data)) {
      throw new Error("The backend returned invalid quarantine data.");
    }
    return data;
  });
}

function isGitHubStatus(value: unknown): value is GitHubStatus {
  if (typeof value !== "object" || value === null) return false;
  const status = value as Record<string, unknown>;
  return (
    typeof status.app_configured === "boolean" &&
    (typeof status.installed === "boolean" || status.installed === null) &&
    (typeof status.required_check_configured === "boolean" ||
      status.required_check_configured === null) &&
    typeof status.merge_protection === "string" &&
    typeof status.reason === "string"
  );
}

export function getGitHubStatus(repository?: string): Promise<GitHubStatus> {
  const runtime = extensionApi?.runtime;
  if (typeof runtime?.sendMessage === "function") {
    return new Promise((resolve, reject) => {
      runtime.sendMessage<unknown>(
        { type: "DIFF_SHIELD_GITHUB_STATUS", repository },
        (response) => {
          const error = extensionApi?.runtime?.lastError?.message;
          if (error) {
            reject(new Error(error));
            return;
          }
          if (!response?.ok || !isGitHubStatus(response.result)) {
            reject(new Error(response?.error ?? "Invalid GitHub integration status."));
            return;
          }
          resolve(response.result);
        },
      );
    });
  }

  const suffix = repository ? `?repository=${encodeURIComponent(repository)}` : "";
  return fetch(`http://127.0.0.1:8000/api/github/status${suffix}`, {
    headers: { Accept: "application/json" },
  }).then(async (response) => {
    if (!response.ok) {
      throw new Error(`Could not load GitHub integration status (${response.status}).`);
    }
    const data: unknown = await response.json();
    if (!isGitHubStatus(data)) {
      throw new Error("The backend returned invalid GitHub integration status.");
    }
    return data;
  });
}

export function loadCachedQuarantines(): Promise<QuarantineListResponse | null> {
  const storage = extensionApi?.storage;
  if (!storage) return Promise.resolve(null);
  return new Promise((resolve, reject) => {
    storage.local.get("quarantineData", (items) => {
      const error = extensionApi?.runtime?.lastError;
      if (error) {
        reject(new Error(error.message));
        return;
      }
      const cached = items.quarantineData;
      resolve(isQuarantineListResponse(cached) ? cached : null);
    });
  });
}

export function subscribeToLatestThreat(
  onFinding: (finding: ThreatFinding | null) => void,
): () => void {
  return subscribeToStoredValue("latestThreat", isThreatFinding, onFinding);
}

export function subscribeToLatestScan(
  onScan: (scan: LatestScan | null) => void,
): () => void {
  return subscribeToStoredValue("latestScan", isLatestScan, onScan);
}

function subscribeToStoredValue<T>(
  key: string,
  isValue: (value: unknown) => value is T,
  onValue: (value: T | null) => void,
): () => void {
  const storage = extensionApi?.storage;
  if (!storage) {
    return () => {};
  }

  let storageChanged = false;
  const listener = (
    changes: Record<string, { newValue?: unknown }>,
    areaName: string,
  ) => {
    if (areaName !== "local" || !Object.hasOwn(changes, key)) {
      return;
    }

    storageChanged = true;
    const value = changes[key].newValue;
    onValue(isValue(value) ? value : null);
  };

  storage.onChanged.addListener(listener);
  storage.local.get(key, (items) => {
    const error = extensionApi?.runtime?.lastError;
    if (error) {
      console.error(`Could not load ${key}:`, error.message);
      return;
    }

    if (!storageChanged) {
      const value = items[key];
      onValue(isValue(value) ? value : null);
    }
  });

  return () => storage.onChanged.removeListener(listener);
}

export function dismissLatestThreat(): boolean {
  const storage = extensionApi?.storage;
  if (!storage) {
    return false;
  }

  storage.local.remove("latestThreat", () => {
    const error = extensionApi?.runtime?.lastError;
    if (error) {
      console.error(
        "Could not dismiss the security finding:",
        error.message,
      );
    }
  });

  return true;
}

export function checkBackendHealth(): Promise<{
  connected: boolean;
  error?: string;
}> {
  const runtime = extensionApi?.runtime;
  if (typeof runtime?.sendMessage !== "function") {
    return fetchBackendHealthDirectly();
  }

  return new Promise((resolve) => {
    try {
      runtime.sendMessage<{ status: string }>(
        { type: "DIFF_SHIELD_BACKEND_HEALTH" },
        (response) => {
          const error = extensionApi?.runtime?.lastError?.message;
          if (error) {
            resolve({ connected: false, error });
            return;
          }

          if (!response?.ok || response.result?.status !== "ok") {
            resolve({
              connected: false,
              error:
                response?.error ??
                "The backend did not respond as healthy.",
            });
            return;
          }

          resolve({ connected: true });
        },
      );
    } catch (error) {
      resolve({
        connected: false,
        error:
          error instanceof Error
            ? error.message
            : "Could not check the backend connection.",
      });
    }

  });
}

async function fetchBackendHealthDirectly(): Promise<{
  connected: boolean;
  error?: string;
}> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);

  try {
    const response = await fetch(BACKEND_HEALTH_URL, {
      headers: { Accept: "application/json" },
      signal: controller.signal,
    });
    if (!response.ok) {
      return {
        connected: false,
        error: `Backend health check failed (${response.status}).`,
      };
    }

    const health: unknown = await response.json();
    if (
      typeof health !== "object" ||
      health === null ||
      !("status" in health) ||
      health.status !== "ok"
    ) {
      return {
        connected: false,
        error: "The backend did not respond as healthy.",
      };
    }

    return { connected: true };
  } catch (error) {
    return {
      connected: false,
      error:
        error instanceof Error && error.name === "AbortError"
          ? "Backend health check timed out."
          : error instanceof Error
            ? error.message
            : "Could not check the backend connection.",
    };
  } finally {
    clearTimeout(timeout);
  }
}
