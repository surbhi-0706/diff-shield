const API_BASE_URL = "http://127.0.0.1:8000";
let latestAnalysisRequest = 0;

function isGitHubPullRequestUrl(value) {
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.hostname === "github.com" &&
      url.username === "" &&
      url.password === "" &&
      (url.port === "" || url.port === "443") &&
      /^\/[^/]+\/[^/]+\/pull\/\d+(?:\/|$)/.test(url.pathname)
    );
  } catch {
    return false;
  }
}

function refersToSamePullRequest(first, second) {
  try {
    const firstUrl = new URL(first);
    const secondUrl = new URL(second);
    return (
      isGitHubPullRequestUrl(first) &&
      isGitHubPullRequestUrl(second) &&
      firstUrl.origin === secondUrl.origin &&
      firstUrl.pathname.match(/^\/[^/]+\/[^/]+\/pull\/\d+/)?.[0] ===
        secondUrl.pathname.match(/^\/[^/]+\/[^/]+\/pull\/\d+/)?.[0]
    );
  } catch {
    return false;
  }
}

async function requestBackend(path, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20_000);

  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...options.headers,
      },
    });

    let data;
    try {
      data = await response.json();
    } catch {
      throw new Error("The DiffShield backend returned invalid JSON.");
    }

    if (!response.ok) {
      const detail =
        typeof data?.detail === "string"
          ? data.detail
          : `Backend request failed (${response.status}).`;
      throw new Error(detail);
    }

    return data;
  } finally {
    clearTimeout(timeout);
  }
}

function storeValues(values) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.set(values, () => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }

      resolve();
    });
  });
}

function removeStoredValue(key) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.remove(key, () => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }

      resolve();
    });
  });
}

async function checkBackendHealth() {
  const health = await requestBackend("/health");
  if (health.status !== "ok") {
    throw new Error("The DiffShield backend did not report a healthy status.");
  }

  return health;
}

async function analyzePullRequest(prUrl, requestId) {
  if (!isGitHubPullRequestUrl(prUrl)) {
    throw new Error("Only GitHub pull request URLs can be analyzed.");
  }

  const result = await requestBackend("/api/analyze-pr", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pr_url: prUrl }),
  });

  if (typeof result.status !== "string") {
    throw new Error("The DiffShield backend returned an invalid scan result.");
  }
  if (result.status !== "PASSED" && result.status !== "QUARANTINE_HOLD") {
    throw new Error("The DiffShield backend returned an unknown scan status.");
  }
  if (requestId !== latestAnalysisRequest) return result;

  const scannedAt = new Date().toISOString();
  const values = {
    latestScan: {
      status: result.status,
      scannedAt,
      prUrl,
      repository: result.repository,
      prNumber: result.pr_number,
      riskScore: result.risk_score,
      finding: result.finding,
    },
  };

  const hasFinding =
    result.status === "QUARANTINE_HOLD" &&
    result.finding &&
    typeof result.finding.id === "string" &&
    typeof result.finding.title === "string" &&
    typeof result.finding.repository === "string" &&
    typeof result.finding.description === "string";

  if (hasFinding) {
    values.latestThreat = {
      ...result.finding,
      detectedAt: scannedAt,
      prUrl,
    };
  }

  await storeValues(values);
  if (!hasFinding) {
    await removeStoredValue("latestThreat");
  }
  return result;
}

async function recordScanFailure(prUrl, error) {
  if (!isGitHubPullRequestUrl(prUrl)) return;

  await storeValues({
    latestScan: {
      status: "ERROR",
      scannedAt: new Date().toISOString(),
      prUrl,
      error,
    },
  });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (typeof message !== "object" || message === null) {
    return false;
  }

  let task;
  let analysisRequestId;
  if (message.type === "DIFF_SHIELD_BACKEND_HEALTH") {
    task = checkBackendHealth();
  } else if (message.type === "DIFF_SHIELD_ANALYZE_PR") {
    const senderUrl = sender.url || sender.tab?.url;
    if (!refersToSamePullRequest(message.prUrl, senderUrl)) {
      sendResponse({ ok: false, error: "Analysis requests must come from a GitHub pull request." });
      return false;
    }

    analysisRequestId = ++latestAnalysisRequest;
    task = analyzePullRequest(message.prUrl, analysisRequestId);
  } else {
    return false;
  }

  task.then(
    (result) => sendResponse({ ok: true, result }),
    async (error) => {
      const errorMessage =
        error instanceof Error
          ? error.message
          : "Could not communicate with the DiffShield backend.";
      if (
        message.type === "DIFF_SHIELD_ANALYZE_PR" &&
        analysisRequestId === latestAnalysisRequest
      ) {
        try {
          await recordScanFailure(message.prUrl, errorMessage);
        } catch (storageError) {
          console.error("[DiffShield] Could not store the failed scan:", storageError);
        }
      }

      console.error("[DiffShield] Backend request failed:", error);
      sendResponse({
        ok: false,
        error: errorMessage,
      });
    },
  );

  return true;
});
