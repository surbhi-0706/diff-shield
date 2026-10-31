export interface ThreatFinding {
  id: string;
  title: string;
  repository: string;
  description: string;
  detectedAt: string;
}

interface ChromeExtensionApi {
  runtime?: {
    lastError?: { message?: string };
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
    typeof finding.detectedAt === "string"
  );
}

export function subscribeToLatestThreat(
  onFinding: (finding: ThreatFinding | null) => void,
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
    if (areaName !== "local" || !Object.hasOwn(changes, "latestThreat")) {
      return;
    }

    storageChanged = true;
    const value = changes.latestThreat.newValue;
    onFinding(isThreatFinding(value) ? value : null);
  };

  storage.onChanged.addListener(listener);
  storage.local.get("latestThreat", (items) => {
    const error = extensionApi?.runtime?.lastError;
    if (error) {
      console.error(
        "Could not load the latest security finding:",
        error.message,
      );
      return;
    }

    if (!storageChanged) {
      const value = items.latestThreat;
      onFinding(isThreatFinding(value) ? value : null);
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
