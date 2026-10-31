/**
 * content.js – DiffShield GitHub PR content script.
 *
 * Automatically fires on every GitHub pull-request page, sends the PR URL
 * to the local DiffShield analysis API, and – if a security regression is
 * found – injects a prominent quarantine banner into the GitHub DOM and
 * notifies the background service worker so the popup can surface the finding.
 */

(function diffShieldContentScript() {
  "use strict";

  // -------------------------------------------------------------------------
  // Guard: only run on GitHub PR pages
  // -------------------------------------------------------------------------
  const PR_PATTERN = /^https:\/\/github\.com\/[^/]+\/[^/]+\/pull\/\d+/;
  const SENTINEL_ID = "diffshield-sentinel";
  const BANNER_ID = "diffshield-quarantine-banner";
  const STATUS_ID = "diffshield-status-chip";

  const navigationState =
    window.__diffShieldNavigationState ||
    (window.__diffShieldNavigationState = {
      href: window.location.href,
      headSha: null,
      timer: null,
      scanningKey: null,
      scannedKeys: new Set(),
      observer: null,
    });

  function currentHeadSha() {
    for (const link of document.querySelectorAll('a[href*="/commit/"]')) {
      let path;
      try {
        path = new URL(link.href).pathname;
      } catch {
        continue;
      }
      const match = path.match(/\/commit\/([0-9a-f]{7,40})(?:\/|$)/i);
      if (match) return match[1].toLowerCase();
    }
    return null;
  }

  function samePullRequest(first, second) {
    const pattern = /^https:\/\/github\.com\/[^/]+\/[^/]+\/pull\/\d+/;
    return pattern.test(first) && pattern.test(second) &&
      first.match(pattern)?.[0] === second.match(pattern)?.[0];
  }

  const listenerFlag = "__diffShieldNavigationListenersInstalled";
  if (!window[listenerFlag]) {
    window[listenerFlag] = true;
    navigationState.headSha = currentHeadSha();
    const handleNavigation = () => {
      const currentUrl = window.location.href;
      const headSha = currentHeadSha();
      if (currentUrl === navigationState.href && headSha === navigationState.headSha) {
        return;
      }

      window.clearTimeout(navigationState.timer);
      navigationState.timer = window.setTimeout(() => {
        const previousUrl = navigationState.href;
        navigationState.href = window.location.href;
        navigationState.headSha = currentHeadSha();
        document.getElementById(SENTINEL_ID)?.remove();
        if (!samePullRequest(previousUrl, navigationState.href)) {
          clearPageAlert();
        }
        diffShieldContentScript();
      }, 100);
    };

    window.addEventListener("popstate", handleNavigation);
    window.addEventListener("hashchange", handleNavigation);
    document.addEventListener("pjax:end", handleNavigation);
    document.addEventListener("turbo:render", handleNavigation);
    navigationState.observer = new MutationObserver(handleNavigation);
    navigationState.observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });
    window.setInterval(handleNavigation, 1000);
  }

  if (!PR_PATTERN.test(window.location.href)) {
    clearPageAlert();
    return;
  }

  // Prevent double-injection on same-page navigations (pjax / turbo)
  if (document.getElementById(SENTINEL_ID)) return;
  const sentinel = document.createElement("meta");
  sentinel.id = SENTINEL_ID;
  document.head.appendChild(sentinel);

  // -------------------------------------------------------------------------
  // Remove any stale banner from a previous navigation
  // -------------------------------------------------------------------------
  function removeExistingBanner() {
    const existing = document.getElementById(BANNER_ID);
    if (existing) {
      if (existing.dataset.countdownTimer) {
        window.clearInterval(Number(existing.dataset.countdownTimer));
      }
      if (existing.dataset.quarantinePollTimer) {
        window.clearInterval(Number(existing.dataset.quarantinePollTimer));
      }
      existing.remove();
    }
  }

  function removeStatusChip() {
    document.getElementById(STATUS_ID)?.remove();
  }

  function clearPageAlert() {
    removeExistingBanner();
    removeStatusChip();
    document.documentElement.style.scrollPaddingTop = "";
  }

  function placeOnPage(element) {
    const anchor =
      document.getElementById("partial-discussion-header") ||
      document.querySelector(".repository-content") ||
      document.querySelector("main") ||
      document.body;

    if (anchor === document.body) {
      document.body.prepend(element);
    } else {
      anchor.insertAdjacentElement("beforebegin", element);
    }
  }

  function injectStatusChip(message, retry = false) {
    removeStatusChip();

    const chip = document.createElement("div");
    chip.id = STATUS_ID;
    chip.setAttribute("role", "status");
    chip.style.cssText = [
      "position:fixed",
      "top:12px",
      "right:12px",
      "z-index:99998",
      "display:flex",
      "align-items:center",
      "gap:10px",
      "max-width:min(460px,calc(100vw - 24px))",
      "padding:9px 12px",
      "border:1px solid #57606a",
      "border-radius:8px",
      "background:#f6f8fa",
      "color:#24292f",
      "box-shadow:0 2px 12px rgba(31,35,40,.2)",
      "font:12px/1.45 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif",
    ].join(";");

    const label = document.createElement("span");
    label.textContent = message;
    chip.appendChild(label);

    if (retry) {
      const retryButton = document.createElement("button");
      retryButton.type = "button";
      retryButton.textContent = "Retry";
      retryButton.style.cssText =
        "flex:none;border:1px solid #cf222e;border-radius:6px;padding:4px 8px;background:#fff;color:#cf222e;font:inherit;font-weight:600;cursor:pointer";
      retryButton.addEventListener("click", () => void runAnalysis());
      chip.appendChild(retryButton);
    }

    document.body.appendChild(chip);
    return chip;
  }

  function analyzeWithBackend(prUrl) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(
        { type: "DIFF_SHIELD_ANALYZE_PR", prUrl },
        (response) => {
          const runtimeError = chrome.runtime.lastError;
          if (runtimeError) {
            reject(new Error(runtimeError.message));
            return;
          }

          if (!response?.ok) {
            reject(new Error(response?.error || "Backend analysis failed."));
            return;
          }

          resolve(response.result);
        },
      );
    });
  }

  function getCachedQuarantines() {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(
        { type: "DIFF_SHIELD_CACHED_QUARANTINES" },
        (response) => {
          const runtimeError = chrome.runtime.lastError;
          if (runtimeError) {
            reject(new Error(runtimeError.message));
            return;
          }
          if (!response?.ok) {
            reject(new Error(response?.error || "Could not restore saved quarantine state."));
            return;
          }
          resolve(response.result);
        },
      );
    });
  }

  function isTemporaryFailure(error) {
    const message = error instanceof Error ? error.message : String(error);
    return /failed to fetch|network|timed out|timeout|could not establish connection|receiving end does not exist/i.test(
      message,
    );
  }

  async function analyzeWithRetry(prUrl, scanPath) {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        return await analyzeWithBackend(prUrl);
      } catch (error) {
        if (attempt === 2 || !isTemporaryFailure(error)) throw error;
        await new Promise((resolve) =>
          window.setTimeout(resolve, 1000 * 2 ** attempt),
        );
        const currentPath = new URL(window.location.href).pathname.match(
          /^\/[^/]+\/[^/]+\/pull\/\d+/,
        )?.[0];
        if (currentPath !== scanPath) throw error;
      }
    }
    throw new Error("The scan could not be completed.");
  }

  // -------------------------------------------------------------------------
  // Inject the quarantine alert banner into the GitHub PR page
  // -------------------------------------------------------------------------
  function injectQuarantineBanner(quarantine) {
    removeExistingBanner();
    removeStatusChip();

    const finding = quarantine.finding || {};
    const banner = document.createElement("div");
    banner.id = BANNER_ID;
    banner.setAttribute("role", "alert");
    banner.setAttribute("aria-live", "assertive");

    const severity = quarantine.severity || finding.severity || "UNKNOWN";
    const colors = { bg: "#2d0a0a", border: "#ff2222", accent: "#ff4444" };
    const content = document.createElement("div");
    content.style.cssText =
      "max-width:1280px;margin:0 auto;display:flex;align-items:flex-start;gap:14px;padding:14px 20px;max-height:45vh;overflow:auto";
    const icon = document.createElement("span");
    icon.textContent = "!";
    icon.style.cssText =
      `flex:none;width:38px;height:38px;border-radius:8px;background:${colors.border};display:grid;place-items:center;color:#fff;font-size:24px;font-weight:800`;

    const details = document.createElement("div");
    details.style.cssText = "flex:1;min-width:0";
    const heading = document.createElement("div");
    heading.textContent = "DIFF SHIELD QUARANTINE ACTIVE";
    heading.style.cssText =
      `font-weight:700;font-size:13px;letter-spacing:.05em;color:${colors.accent};text-transform:uppercase;margin-bottom:4px`;

    const risk = document.createElement("div");
    risk.textContent = `${severity} RISK · Score ${quarantine.risk_score}/100`;
    risk.style.cssText =
      `display:inline-block;background:${colors.border};color:#fff;font-size:10px;font-weight:700;padding:2px 8px;border-radius:20px;margin-bottom:5px`;

    const title = document.createElement("div");
    title.textContent = finding.title || "Security regression finding";
    title.style.cssText =
      "font-weight:600;font-size:13px;color:#f0f0f0;margin-bottom:3px";

    const description = document.createElement("div");
    description.textContent =
      finding.description ||
      "The backend flagged this pull request for security review.";
    description.style.cssText =
      "color:#c0c0c0;font-size:12px;line-height:1.5;overflow-wrap:anywhere";

    const metadata = document.createElement("div");
    metadata.style.cssText =
      "display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:3px 14px;margin-top:8px;font-size:11px;color:#ccc";
    const metadataItems = [
      `Repository: ${quarantine.repository || "Unknown"}`,
      `PR #${quarantine.pr_number || "?"}: ${quarantine.pr_title || document.title}`,
      `Author: ${quarantine.pr_author || "Unknown"}`,
      `Commit: ${quarantine.head_sha || "Unavailable"}`,
      `Status: ${quarantine.state || "QUARANTINED"}`,
      `Detected: ${quarantine.detected_at || "Unavailable"}`,
      `Review deadline: ${quarantine.review_deadline || "Unavailable"}`,
      `Affected file: ${finding.file_path || "Unavailable"}`,
      `Changed lines: ${
        Array.isArray(finding.line_numbers) && finding.line_numbers.length
          ? finding.line_numbers.join(", ")
          : "not provided by the current analyzer"
      }`,
    ];
    for (const value of metadataItems) {
      const item = document.createElement("div");
      item.textContent = value;
      metadata.appendChild(item);
    }

    const countdown = document.createElement("div");
    countdown.setAttribute("aria-live", "off");
    countdown.style.cssText =
      "margin-top:7px;font-size:12px;font-weight:700;color:#ff8a8a";
    const deadlineMs = Date.parse(quarantine.review_deadline);
    const updateCountdown = () => {
      if (!Number.isFinite(deadlineMs)) {
        countdown.textContent = "Review countdown unavailable";
        return;
      }
      const remaining = Math.max(0, deadlineMs - Date.now());
      const hours = Math.floor(remaining / 3_600_000);
      const minutes = Math.floor((remaining % 3_600_000) / 60_000);
      const seconds = Math.floor((remaining % 60_000) / 1000);
      countdown.textContent =
        remaining === 0
          ? "Review deadline passed · quarantine remains active pending authorized review"
          : `Review deadline countdown: ${hours}h ${minutes}m ${seconds}s`;
    };
    updateCountdown();
    banner.dataset.countdownTimer = String(
      window.setInterval(updateCountdown, 1000),
    );

    const detailsLink = document.createElement("a");
    detailsLink.textContent = "Open finding details";
    detailsLink.href = `http://127.0.0.1:8000/api/quarantines/${encodeURIComponent(
      quarantine.finding_id || finding.id || "",
    )}`;
    detailsLink.target = "_blank";
    detailsLink.rel = "noreferrer";
    detailsLink.style.cssText = "display:inline-block;margin-top:6px;font-size:11px";

    details.append(heading, risk, title, description, metadata, countdown, detailsLink);
    content.append(icon, details);
    banner.appendChild(content);
    let pollInFlight = false;
    const pollState = () => {
      if (pollInFlight) return;
      pollInFlight = true;
      chrome.runtime.sendMessage(
        {
          type: "DIFF_SHIELD_GET_QUARANTINE",
          findingId: quarantine.finding_id || finding.id,
        },
        (response) => {
          pollInFlight = false;
          if (chrome.runtime.lastError || !response?.ok) {
            injectStatusChip(
              "DiffShield: backend offline. Quarantine state could not be refreshed.",
              true,
            );
            return;
          }
          const current = response.result;
          if (current.state === "RESOLVED") {
            removeExistingBanner();
            document.documentElement.style.scrollPaddingTop = "";
            injectStatusChip(
              "DiffShield: a reviewer resolved this finding. The scan is not a guarantee of safety.",
            );
            return;
          }
          if (
            ["QUARANTINED", "REVIEW_REQUIRED", "ESCALATED", "REJECTED"].includes(
              current.state,
            )
          ) {
            injectQuarantineBanner(current);
          }
        },
      );
    };
    banner.dataset.quarantinePollTimer = String(
      window.setInterval(pollState, 30_000),
    );

    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 99999;
      background: ${colors.bg};
      border-bottom: 3px solid ${colors.border};
      color: #f0f0f0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      font-size: 13px;
      padding: 0;
      box-shadow: 0 4px 24px rgba(0,0,0,0.6);
      animation: diffshield-slide-in 0.35s cubic-bezier(0.16,1,0.3,1) both;
    `;

    // Inject keyframe animation
    if (!document.getElementById("diffshield-styles")) {
      const style = document.createElement("style");
      style.id = "diffshield-styles";
      style.textContent = `
        @keyframes diffshield-slide-in {
          from { transform: translateY(-100%); opacity: 0; }
          to   { transform: translateY(0);    opacity: 1; }
        }
        #diffshield-quarantine-banner a {
          color: ${colors.accent};
          text-decoration: underline;
        }
        #diffshield-quarantine-banner:hover {
          filter: brightness(1.05);
        }
      `;
      document.head.appendChild(style);
    }
    placeOnPage(banner);

    // Offset page content so banner doesn't overlap it
    const bannerHeight = banner.getBoundingClientRect().height || 80;
    document.documentElement.style.scrollPaddingTop = bannerHeight + "px";
  }

  // -------------------------------------------------------------------------
  // Main: call the DiffShield API and handle the response
  // -------------------------------------------------------------------------
  async function runAnalysis() {
    const prUrl = window.location.href;
    const scanPath = new URL(prUrl).pathname.match(
      /^\/[^/]+\/[^/]+\/pull\/\d+/,
    )?.[0];
    if (!scanPath) return;

    const headSha = currentHeadSha();
    const scanKey = `${scanPath}:${headSha || ""}`;
    const alreadyScanned = headSha
      ? [...navigationState.scannedKeys].some((key) => {
          const [path, scannedSha] = key.split(":");
          return (
            path === scanPath &&
            (scannedSha.startsWith(headSha) || headSha.startsWith(scannedSha))
          );
        })
      : false;
    if (
      alreadyScanned ||
      navigationState.scanningKey === scanKey
    ) {
      return;
    }
    navigationState.scanningKey = scanKey;
    injectStatusChip("DiffShield: scanning...");

    let data;
    try {
      data = await analyzeWithRetry(prUrl, scanPath);
    } catch (err) {
      console.warn(
        "[DiffShield] Could not analyze this pull request:",
        err instanceof Error ? err.message : err,
      );
      const currentPath = new URL(window.location.href).pathname.match(
        /^\/[^/]+\/[^/]+\/pull\/\d+/,
      )?.[0];
      if (currentPath === scanPath) {
        try {
          const cached = await getCachedQuarantines();
          const activeFinding = Array.isArray(cached?.items)
            ? cached.items.find(
                (item) =>
                  ["QUARANTINED", "REVIEW_REQUIRED", "ESCALATED", "REJECTED"].includes(
                    item.state,
                  ) &&
                  samePullRequest(item.pr_url || "", window.location.href),
              )
            : null;
          if (activeFinding) injectQuarantineBanner(activeFinding);
        } catch (restoreError) {
          console.warn(
            "[DiffShield] Could not restore cached quarantine state:",
            restoreError instanceof Error ? restoreError.message : restoreError,
          );
        }
        injectStatusChip(
          "DiffShield: backend offline. Start it with: python -m uvicorn main:app --port 8000",
          true,
        );
      }
      if (navigationState.scanningKey === scanKey) {
        navigationState.scanningKey = null;
      }
      return;
    }

    const currentPath = new URL(window.location.href).pathname.match(
      /^\/[^/]+\/[^/]+\/pull\/\d+/,
    )?.[0];
    const latestHeadSha = currentHeadSha();
    const responseHeadSha = data.quarantine?.head_sha;
    if (
      !scanPath ||
      currentPath !== scanPath ||
      (headSha && latestHeadSha && !headSha.startsWith(latestHeadSha) &&
        !latestHeadSha.startsWith(headSha)) ||
      (latestHeadSha && responseHeadSha &&
        !responseHeadSha.startsWith(latestHeadSha) &&
        !latestHeadSha.startsWith(responseHeadSha))
    ) {
      if (navigationState.scanningKey === scanKey) {
        navigationState.scanningKey = null;
      }
      return;
    }
    if (responseHeadSha) {
      navigationState.scannedKeys.add(`${scanPath}:${responseHeadSha}`);
    } else if (headSha) {
      navigationState.scannedKeys.add(scanKey);
    }
    if (navigationState.scanningKey === scanKey) {
      navigationState.scanningKey = null;
    }

    console.info("[DiffShield] Analysis result:", data.status, "| risk:", data.risk_score);

    if (
      data.status === "QUARANTINE_HOLD" &&
      data.finding &&
      data.quarantine?.state
    ) {
      // Inject the in-page banner
      injectQuarantineBanner(data.quarantine);
    } else if (data.status === "RESOLVED") {
      removeExistingBanner();
      document.documentElement.style.scrollPaddingTop = "";
      injectStatusChip(
        "DiffShield: a reviewer resolved this finding. The scan is not a guarantee of safety.",
      );
    } else if (data.status === "PASSED") {
      removeExistingBanner();
      document.documentElement.style.scrollPaddingTop = "";
      injectStatusChip(`DiffShield: no regression found (risk ${data.risk_score})`);
    } else {
      injectStatusChip(
        "DiffShield: backend offline. Start it with: python -m uvicorn main:app --port 8000",
        true,
      );
    }
  }

  runAnalysis();
})();
