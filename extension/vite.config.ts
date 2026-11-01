import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const manifest = {
  manifest_version: 3,
  name: "DIFF SHIELD",
  version: "0.1.0",
  description:
    "Detect suspicious security changes in open-source pull requests and dependency updates.",
  action: {
    default_popup: "index.html",
  },
  background: {
    service_worker: "background.js",
  },
  permissions: ["storage"],
  host_permissions: [
    "https://github.com/*",
    "http://127.0.0.1:8000/*",
  ],
  content_scripts: [
    {
      matches: ["https://github.com/*/*/pull/*"],
      js: ["content.js"],
      run_at: "document_idle",
    },
  ],
};

const backgroundScript = `
"use strict";

const API = "http://127.0.0.1:8000";

async function request(path, options = {}) {
  const response = await fetch(API + path, {
    ...options,
    headers: {
      Accept: "application/json",
      ...options.headers
    }
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.detail || "Backend HTTP " + response.status);
  }

  return data;
}

function validPR(url) {
  try {
    const parsed = new URL(url);

    if (parsed.hostname !== "github.com") return null;

    const match = parsed.pathname.match(
      /^\\/([^/]+)\\/([^/]+)\\/pull\\/(\\d+)(?:\\/|$)/
    );

    if (!match) return null;

    return {
      url: "https://github.com/" + match[1] + "/" +
        match[2] + "/pull/" + match[3],
      repository: match[1] + "/" + match[2],
      number: Number(match[3])
    };
  } catch {
    return null;
  }
}

async function analyzePR(prUrl, senderUrl) {
  const pr = validPR(prUrl);
  const senderPR = validPR(senderUrl || "");

  if (!pr || !senderPR || pr.url !== senderPR.url) {
    throw new Error("Invalid pull request sender.");
  }

  const result = await request("/api/analyze-pr", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pr_url: pr.url })
  });

  const scannedAt = new Date().toISOString();

  await chrome.storage.local.set({
    latestScan: {
      ...result,
      prUrl: pr.url,
      repository: result.repository || pr.repository,
      prNumber: result.pr_number || pr.number,
      scannedAt
    }
  });

  if (
    result.status === "QUARANTINE_HOLD" &&
    result.finding
  ) {
    await chrome.storage.local.set({
      latestThreat: {
        ...result.finding,
        repository: result.finding.repository || pr.repository,
        detectedAt: scannedAt,
        prUrl: pr.url,
        status: result.status
      }
    });
  } else if (
    result.status === "PASSED" ||
    result.status === "RESOLVED"
  ) {
    const stored = await chrome.storage.local.get("latestThreat");

    if (stored.latestThreat?.prUrl === pr.url) {
      await chrome.storage.local.remove("latestThreat");
    }
  }

  return result;
}

async function listQuarantines(activeOnly = false) {
  const query = activeOnly ? "?active_only=true" : "";
  const result = await request("/api/quarantines" + query);

  const items = Array.isArray(result.items) ? result.items : [];

  await chrome.storage.local.set({
    quarantines: items,
    mergeProtection: result.merge_protection || null,
    quarantinesUpdatedAt: new Date().toISOString()
  });

  return result;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.type !== "string") {
    return false;
  }

  let task;

  switch (message.type) {
    case "DIFF_SHIELD_BACKEND_HEALTH":
      task = request("/health");
      break;

    case "DIFF_SHIELD_ANALYZE_PR":
      task = analyzePR(
        message.prUrl,
        sender.url || sender.tab?.url
      );
      break;

    case "DIFF_SHIELD_LIST_QUARANTINES":
      task = listQuarantines(Boolean(message.activeOnly));
      break;

    default:
      return false;
  }

  task.then(
    result => sendResponse({ ok: true, result }),
    error => {
      console.error("[DiffShield] Request failed:", error);
      sendResponse({
        ok: false,
        error: error.message || "Backend request failed."
      });
    }
  );

  return true;
});

console.info("[DiffShield] Background worker ready.");
`;

const contentScript = `
(() => {
  if (window.__DIFF_SHIELD_STARTED__) return;
  window.__DIFF_SHIELD_STARTED__ = true;

  let lastScanned = "";
  let timer;

  function detectPR() {
    if (location.hostname !== "github.com") return null;

    const match = location.pathname.match(
      /^\\\\/([^/]+)\\\\/([^/]+)\\\\/pull\\\\/(\\\\d+)(?:\\\\/|$)/
    );

    if (!match) return null;

    return "https://github.com/" +
      match[1] + "/" + match[2] + "/pull/" + match[3];
  }

  function showMessage(message, error = false) {
    let banner = document.getElementById("diff-shield-status");

    if (!banner) {
      banner = document.createElement("div");
      banner.id = "diff-shield-status";
      banner.style.cssText =
        "position:relative;z-index:999999;padding:12px 18px;" +
        "background:#211014;color:white;border-left:4px solid #e5484d;" +
        "font:14px Arial,sans-serif;";
      document.body.prepend(banner);
    }

    banner.textContent = message;
    banner.style.borderLeftColor = error ? "#e5484d" : "#238636";
  }

  async function scan() {
    const prUrl = detectPR();
    if (!prUrl) return;

    if (prUrl === lastScanned) return;
    lastScanned = prUrl;

    showMessage("DIFF SHIELD: scanning pull request...");

    try {
      const response = await chrome.runtime.sendMessage({
        type: "DIFF_SHIELD_ANALYZE_PR",
        prUrl
      });

      if (!response?.ok) {
        throw new Error(response?.error || "Scan failed.");
      }

      const result = response.result;

      if (result.status === "QUARANTINE_HOLD") {
        showMessage(
          "DIFF SHIELD: SECURITY QUARANTINE — maintainer review required.",
          true
        );
      } else if (result.status === "PASSED") {
        showMessage(
          "DIFF SHIELD: scan completed. No regression detected."
        );
      } else if (result.status === "RESOLVED") {
        showMessage(
          "DIFF SHIELD: finding resolved. Review status confirmed."
        );
      } else {
        showMessage(
          "DIFF SHIELD: scan result requires verification.",
          true
        );
      }
    } catch (error) {
      lastScanned = "";

      showMessage(
        "DIFF SHIELD: scan unavailable — " +
          (error.message || "Unknown error"),
        true
      );
    }
  }

  function scheduleScan() {
    clearTimeout(timer);
    timer = setTimeout(scan, 700);
  }

  scheduleScan();

  window.addEventListener("popstate", scheduleScan);
  window.addEventListener("hashchange", scheduleScan);

  document.addEventListener("turbo:render", scheduleScan);
  document.addEventListener("pjax:end", scheduleScan);

  new MutationObserver(() => {
    if (detectPR()) scheduleScan();
  }).observe(document.documentElement, {
    childList: true,
    subtree: true
  });

  setInterval(scheduleScan, 3000);
})();
`;

export default defineConfig({
  plugins: [
    react(),
    {
      name: "diff-shield-extension-files",

      generateBundle() {
        this.emitFile({
          type: "asset",
          fileName: "manifest.json",
          source: JSON.stringify(manifest, null, 2),
        });

        this.emitFile({
          type: "asset",
          fileName: "background.js",
          source: backgroundScript,
        });

        this.emitFile({
          type: "asset",
          fileName: "content.js",
          source: contentScript,
        });
      },
    },
  ],
});
