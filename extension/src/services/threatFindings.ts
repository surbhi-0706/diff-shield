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

interface RuntimeResponse<T> {
  ok: boolean;
  result?: T;
  error?: string;
}

interface ChromeExtensionApi {
  runtime?: {
    lastError?: { message?: string };
    sendMessage<T>(
      message: { type: string },
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
  if (!runtime) {
    return Promise.resolve({
      connected: false,
      error: "Open the popup from the installed browser extension.",
    });
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
