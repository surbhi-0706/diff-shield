
export interface ThreatFinding {
  id: string;
  title: string;
  repository: string;
  description: string;
  detectedAt: string;
  prUrl?: string;
  severity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  riskScore?: number;
  status?: string;
  reviewDeadline?: string;
  filePath?: string;
}

interface ChromeExtensionApi {
  runtime?: {
    lastError?: { message?: string };
  };
  storage?: {
    local: {
      get(
        keys: string | string[],
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
  globalThis as typeof globalThis & {
    chrome?: ChromeExtensionApi;
  }
).chrome;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export function isThreatFinding(
  value: unknown,
): value is ThreatFinding {
  if (!isRecord(value)) return false;

  return (
    typeof value.id === "string" &&
    typeof value.title === "string" &&
    typeof value.repository === "string" &&
    typeof value.description === "string" &&
    typeof value.detectedAt === "string"
  );
}

function readFinding(value: unknown): ThreatFinding | null {
  if (!isThreatFinding(value)) return null;

  return {
    id: value.id,
    title: value.title,
    repository: value.repository,
    description: value.description,
    detectedAt: value.detectedAt,
    ...(typeof value.prUrl === "string"
      ? { prUrl: value.prUrl }
      : {}),
    ...(typeof value.severity === "string"
      ? {
          severity: value.severity as ThreatFinding["severity"],
        }
      : {}),
    ...(typeof value.riskScore === "number"
      ? { riskScore: value.riskScore }
      : {}),
    ...(typeof value.status === "string"
      ? { status: value.status }
      : {}),
    ...(typeof value.reviewDeadline === "string"
      ? { reviewDeadline: value.reviewDeadline }
      : {}),
    ...(typeof value.filePath === "string"
      ? { filePath: value.filePath }
      : {}),
  };
}

export function subscribeToLatestThreat(
  onFinding: (finding: ThreatFinding | null) => void,
): () => void {
  const storage = extensionApi?.storage;

  if (!storage) {
    console.warn(
      "[DiffShield] Chrome storage is unavailable. Open the installed extension.",
    );
    onFinding(null);
    return () => {};
  }

  let disposed = false;
  let storageChanged = false;

  const listener = (
    changes: Record<string, { newValue?: unknown }>,
    areaName: string,
  ) => {
    if (
      areaName !== "local" ||
      !Object.hasOwn(changes, "latestThreat")
    ) {
      return;
    }

    storageChanged = true;

    if (!disposed) {
      onFinding(readFinding(changes.latestThreat.newValue));
    }
  };

  storage.onChanged.addListener(listener);

  storage.local.get("latestThreat", (items) => {
    if (disposed) return;

    const error = extensionApi?.runtime?.lastError;

    if (error) {
      console.error(
        "[DiffShield] Could not load the latest finding:",
        error.message,
      );
      return;
    }

    if (!storageChanged) {
      onFinding(readFinding(items.latestThreat));
    }
  });

  return () => {
    disposed = true;
    storage.onChanged.removeListener(listener);
  };
}

/**
 * Security findings must not be dismissed by deleting their
 * persistent storage record.
 *
 * Resolution must happen through an authorized backend review.
 */
export function dismissLatestThreat(): boolean {
  console.warn(
    "[DiffShield] Security findings cannot be dismissed locally. Resolve them through an authorized review.",
  );

  return false;
}
