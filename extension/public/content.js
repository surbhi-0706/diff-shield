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
  if (!PR_PATTERN.test(window.location.href)) return;

  // Prevent double-injection on same-page navigations (pjax / turbo)
  const SENTINEL_ID = "diffshield-sentinel";
  if (document.getElementById(SENTINEL_ID)) return;
  const sentinel = document.createElement("meta");
  sentinel.id = SENTINEL_ID;
  document.head.appendChild(sentinel);

  const API_ENDPOINT = "http://127.0.0.1:8000/api/analyze-pr";
  const BANNER_ID = "diffshield-quarantine-banner";

  // -------------------------------------------------------------------------
  // Remove any stale banner from a previous navigation
  // -------------------------------------------------------------------------
  function removeExistingBanner() {
    const existing = document.getElementById(BANNER_ID);
    if (existing) existing.remove();
  }

  // -------------------------------------------------------------------------
  // Inject the quarantine alert banner into the GitHub PR page
  // -------------------------------------------------------------------------
  function injectQuarantineBanner(finding, riskScore, holdHours) {
    removeExistingBanner();

    const banner = document.createElement("div");
    banner.id = BANNER_ID;
    banner.setAttribute("role", "alert");
    banner.setAttribute("aria-live", "assertive");

    const severity = finding.severity || "HIGH";
    const severityColors = {
      CRITICAL: { bg: "#2d0a0a", border: "#ff2222", accent: "#ff4444" },
      HIGH:     { bg: "#2d1a0a", border: "#ff6b00", accent: "#ff8c00" },
      MEDIUM:   { bg: "#2d280a", border: "#ffc107", accent: "#ffdd55" },
    };
    const colors = severityColors[severity] || severityColors.HIGH;

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

    const cveRef = finding.cve_cwe ? `&nbsp;·&nbsp;<code style="background:rgba(255,255,255,0.1);padding:1px 5px;border-radius:3px;font-size:11px;">${finding.cve_cwe}</code>` : "";

    banner.innerHTML = `
      <div style="max-width:1280px;margin:0 auto;display:flex;align-items:flex-start;gap:14px;padding:14px 20px;">
        <!-- Shield icon -->
        <div style="flex-shrink:0;width:38px;height:38px;border-radius:8px;background:${colors.border};display:flex;align-items:center;justify-content:center;margin-top:2px;">
          <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
        </div>

        <!-- Content -->
        <div style="flex:1;min-width:0;">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:4px;">
            <span style="font-weight:700;font-size:13px;letter-spacing:0.05em;color:${colors.accent};text-transform:uppercase;">
              ⛔ DiffShield: ${holdHours}h Quarantine Hold
            </span>
            <span style="background:${colors.border};color:#fff;font-size:10px;font-weight:700;padding:2px 8px;border-radius:20px;text-transform:uppercase;letter-spacing:0.08em;">
              ${severity} RISK · Score ${riskScore}/100
            </span>
            ${cveRef}
          </div>

          <div style="font-weight:600;font-size:13px;color:#f0f0f0;margin-bottom:3px;">
            ${finding.title || "Security Guard Regression Detected"}
          </div>

          <div style="color:#c0c0c0;font-size:12px;line-height:1.5;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:900px;">
            ${finding.description || "A critical security boundary has been removed in this pull request."}
          </div>

          <div style="margin-top:6px;font-size:11px;color:#888;">
            Finding ID: <code style="background:rgba(255,255,255,0.08);padding:1px 5px;border-radius:3px;">${finding.id || "DS-UNKNOWN"}</code>
            &nbsp;·&nbsp; Repository: <strong style="color:#aaa;">${finding.repository || ""}</strong>
            &nbsp;·&nbsp; Detected by <strong style="color:${colors.accent};">DiffShield</strong>
          </div>
        </div>

        <!-- Dismiss button -->
        <button
          id="diffshield-dismiss"
          aria-label="Dismiss DiffShield quarantine alert"
          style="flex-shrink:0;background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.15);color:#ccc;border-radius:6px;padding:6px 12px;font-size:12px;cursor:pointer;margin-top:2px;transition:background 0.2s;"
          onmouseover="this.style.background='rgba(255,255,255,0.18)'"
          onmouseout="this.style.background='rgba(255,255,255,0.08)'"
        >
          Dismiss
        </button>
      </div>
    `;

    // Dismiss handler
    banner.querySelector("#diffshield-dismiss").addEventListener("click", () => {
      banner.style.animation = "none";
      banner.style.opacity = "0";
      banner.style.transform = "translateY(-100%)";
      banner.style.transition = "opacity 0.25s, transform 0.25s";
      setTimeout(() => banner.remove(), 300);
    });

    // Inject above the PR discussion header or page content
    const anchor =
      document.getElementById("partial-discussion-header") ||
      document.querySelector(".repository-content") ||
      document.querySelector("main") ||
      document.body;

    if (anchor === document.body) {
      document.body.prepend(banner);
    } else {
      anchor.insertAdjacentElement("beforebegin", banner);
    }

    // Offset page content so banner doesn't overlap it
    const bannerHeight = banner.getBoundingClientRect().height || 80;
    document.documentElement.style.scrollPaddingTop = bannerHeight + "px";
  }

  // -------------------------------------------------------------------------
  // Main: call the DiffShield API and handle the response
  // -------------------------------------------------------------------------
  async function runAnalysis() {
    const prUrl = window.location.href;

    let data;
    try {
      const response = await fetch(API_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pr_url: prUrl }),
      });

      if (!response.ok) {
        console.warn("[DiffShield] API returned", response.status, "– skipping.");
        return;
      }

      data = await response.json();
    } catch (err) {
      // Backend not running or network error – fail silently
      console.info("[DiffShield] Backend unreachable. Start with: uvicorn main:app --reload");
      return;
    }

    console.info("[DiffShield] Analysis result:", data.status, "| risk:", data.risk_score);

    if (data.status === "QUARANTINE_HOLD" && data.finding) {
      // Notify background service worker → updates chrome.storage.local
      try {
        chrome.runtime.sendMessage({
          type: "DIFF_SHIELD_MALICIOUS_CHANGE",
          finding: data.finding,
        });
      } catch (msgErr) {
        console.warn("[DiffShield] Could not message background:", msgErr);
      }

      // Inject the in-page banner
      injectQuarantineBanner(data.finding, data.risk_score, data.hold_hours);
    }
  }

  // Run immediately then also listen for GitHub's pjax/turbo navigations
  runAnalysis();

  // Re-run on GitHub's internal navigation events (pjax and turbo)
  document.addEventListener("pjax:end", () => {
    document.getElementById(SENTINEL_ID)?.remove();
    diffShieldContentScript();
  });
  document.addEventListener("turbo:render", () => {
    document.getElementById(SENTINEL_ID)?.remove();
    diffShieldContentScript();
  });
})();
