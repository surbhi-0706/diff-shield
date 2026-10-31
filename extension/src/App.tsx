import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Bell,
  Check,
  ChevronRight,
  Clock3,
  GitBranch,
  GitPullRequest,
  Package,
  RefreshCw,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";

import {
  dismissLatestThreat,
  checkBackendHealth,
  getGitHubStatus,
  listQuarantines,
  loadCachedQuarantines,
  subscribeToLatestScan,
  subscribeToLatestThreat,
  type LatestScan,
  type GitHubStatus,
  type QuarantineRecord,
  type ThreatFinding,
} from "./services/threatFindings";
import "./App.css";

const features = [
  {
    id: "patch-comparison",
    icon: Search,
    title: "Patch comparison",
    description: "Compare changes against historical fixes.",
    heading: "Patch comparison",
    summary:
      "The local backend analyzes GitHub pull request diffs for removed security guards and known vulnerability patterns.",
    steps: [
      "Open a GitHub pull request while the backend is running.",
      "The backend fetches and parses the pull request diff.",
      "Review any removed security guard reported by the analysis.",
    ],
  },
  {
    id: "pull-request-analysis",
    icon: GitPullRequest,
    title: "Pull request analysis",
    description: "Inspect suspicious repository changes.",
    heading: "Pull request analysis",
    summary:
      "When you open a GitHub pull request, the extension sends its URL to your local DiffShield backend for analysis.",
    steps: [
      "Open a GitHub pull request while the backend is running.",
      "The backend fetches and analyzes the pull request diff.",
      "Review any security regression finding on GitHub and in this popup.",
    ],
  },
  {
    id: "security-notifications",
    icon: Bell,
    title: "Security notifications",
    description: "Bring important findings to your attention.",
    heading: "Security notifications",
    summary:
      "Security findings returned by the backend are stored locally and shown in the popup and on the pull request page.",
    steps: [
      "The extension saves the latest pull request scan result.",
      "Detected regressions appear as a red alert banner.",
      "Dismiss the alert after reviewing the finding.",
    ],
  },
] as const;

type FeatureId = (typeof features)[number]["id"];
type Page = "overview" | "settings" | FeatureId;
type Severity = "HIGH" | "MEDIUM";

function App() {
  const [page, setPage] = useState<Page>("overview");
  const [latestThreat, setLatestThreat] = useState<ThreatFinding | null>(null);
  const [latestScan, setLatestScan] = useState<LatestScan | null>(null);
  const [quarantines, setQuarantines] = useState<QuarantineRecord[]>([]);
  const [quarantineSource, setQuarantineSource] = useState<
    "loading" | "backend" | "cached" | "unavailable"
  >("loading");
  const [quarantineError, setQuarantineError] = useState<string | null>(null);
  const [githubAppStatus, setGithubAppStatus] = useState<GitHubStatus | null>(
    null,
  );
  const [githubAppError, setGithubAppError] = useState<string | null>(null);
  const [mergeProtection, setMergeProtection] = useState<{
    status: string;
    reason?: string;
  }>({
    status: "UNKNOWN",
    reason: "Checking GitHub enforcement configuration.",
  });
  const [currentTime, setCurrentTime] = useState<number | null>(null);
  const [backendState, setBackendState] = useState<
    "checking" | "connected" | "offline"
  >("checking");
  const [backendError, setBackendError] = useState<string | null>(null);
  const [visibleSeverities, setVisibleSeverities] = useState<
    Record<Severity, boolean>
  >({ HIGH: true, MEDIUM: true });

  useEffect(() => {
    let active = true;
    const unsubscribeThreat = subscribeToLatestThreat(setLatestThreat);
    const unsubscribeScan = subscribeToLatestScan(setLatestScan);

    void checkBackendHealth().then((result) => {
      if (!active) return;
      setBackendState(result.connected ? "connected" : "offline");
      setBackendError(result.error ?? null);
    });
    void listQuarantines()
      .then((result) => {
        if (!active) return;
        setQuarantines(result.items);
        setQuarantineSource("backend");
        setQuarantineError(null);
      })
      .catch(async (error: unknown) => {
        if (!active) return;
        setQuarantineError(
          error instanceof Error ? error.message : "Could not load quarantine state.",
        );
        try {
          const cached = await loadCachedQuarantines();
          if (!active) return;
          if (cached) {
            setQuarantines(cached.items);
            setMergeProtection(cached.merge_protection);
            setQuarantineSource("cached");
          } else {
            setQuarantineSource("unavailable");
          }
        } catch (cacheError) {
          if (!active) return;
          setQuarantineSource("unavailable");
          setQuarantineError(
            cacheError instanceof Error
              ? cacheError.message
              : "Could not restore saved quarantine state.",
          );
        }
      });
    return () => {
      active = false;
      unsubscribeThreat();
      unsubscribeScan();
    };
  }, []);

  useEffect(() => {
    let active = true;
    void getGitHubStatus(latestScan?.repository)
      .then((result) => {
        if (!active) return;
        setGithubAppStatus(result);
        setMergeProtection({
          status: result.merge_protection,
          reason: result.reason,
        });
        setGithubAppError(null);
      })
      .catch((error: unknown) => {
        if (!active) return;
        setGithubAppError(
          error instanceof Error
            ? error.message
            : "Could not load GitHub App status.",
        );
      });
    return () => {
      active = false;
    };
  }, [latestScan?.repository]);

  useEffect(() => {
    const timer = window.setInterval(() => setCurrentTime(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const activeQuarantines = quarantines.filter((quarantine) =>
    ["QUARANTINED", "REVIEW_REQUIRED", "ESCALATED", "REJECTED"].includes(
      quarantine.state,
    ),
  );
  const latestThreatIsQuarantined = activeQuarantines.some(
    (quarantine) => quarantine.finding_id === latestThreat?.id,
  );
  const threatSeverity = latestThreat?.severity.toUpperCase();
  const threatFilter: Severity | null = threatSeverity
    ? threatSeverity === "CRITICAL" || threatSeverity === "HIGH"
      ? "HIGH"
      : "MEDIUM"
    : null;
  const visibleThreat =
    latestThreat && threatFilter && visibleSeverities[threatFilter]
      ? latestThreat
      : null;
  const activeFeature = features.find((feature) => feature.id === page);

  function refreshBackendStatus() {
    setBackendState("checking");
    setBackendError(null);
    void checkBackendHealth().then((result) => {
      setBackendState(result.connected ? "connected" : "offline");
      setBackendError(result.error ?? null);
    });
    void listQuarantines()
      .then((result) => {
        setQuarantines(result.items);
        setQuarantineSource("backend");
        setQuarantineError(null);
      })
      .catch((error: unknown) => {
        setQuarantineSource("unavailable");
        setQuarantineError(
          error instanceof Error ? error.message : "Could not load quarantine state.",
        );
      });
    void getGitHubStatus(latestScan?.repository)
      .then((result) => {
        setGithubAppStatus(result);
        setMergeProtection({
          status: result.merge_protection,
          reason: result.reason,
        });
        setGithubAppError(null);
      })
      .catch((error: unknown) => {
        setGithubAppError(
          error instanceof Error
            ? error.message
            : "Could not load GitHub App status.",
        );
      });
  }

  function formatCountdown(deadline: string | null | undefined) {
    if (!deadline) return "Review deadline unavailable";
    if (currentTime === null) return "Calculating review countdown…";
    const remaining = Date.parse(deadline) - currentTime;
    if (!Number.isFinite(remaining)) return "Review deadline unavailable";
    if (remaining <= 0) return "Deadline passed · quarantine remains active";
    const hours = Math.floor(remaining / 3_600_000);
    const minutes = Math.floor((remaining % 3_600_000) / 60_000);
    const seconds = Math.floor((remaining % 60_000) / 1000);
    return `${hours}h ${minutes}m ${seconds}s remaining`;
  }

  function toggleSeverity(severity: Severity) {
    setVisibleSeverities((current) => ({
      ...current,
      [severity]: !current[severity],
    }));
  }

  function dismissThreat() {
    if (!dismissLatestThreat()) {
      setLatestThreat(null);
    }
  }

  return (
    <main className="app ds-motion">
      <header className="header">
        <div className="brand">
          <div className="logo">
            <ShieldCheck size={25} />
          </div>

          <div>
            <h1>DIFF SHIELD</h1>
            <span>OPEN SOURCE SECURITY</span>
          </div>
        </div>

        <button
          className="icon-button"
          aria-label="Settings"
          title="Settings"
          onClick={() => setPage("settings")}
        >
          <Settings size={19} />
        </button>
      </header>

      {latestThreat && (
        <section className="threat-banner" role="alert" aria-live="assertive">
          <div className="threat-banner-icon">
            <AlertTriangle size={19} />
          </div>
          <div className="threat-banner-content">
            <strong>SECURITY REGRESSION FLAGGED</strong>
            <span>{latestThreat.title}</span>
            <small>
              {latestThreat.repository} ·{" "}
              {new Date(latestThreat.detectedAt).toLocaleString()}
            </small>
          </div>
          {!latestThreatIsQuarantined && (
            <button
              className="threat-dismiss"
              aria-label="Dismiss security alert"
              onClick={dismissThreat}
            >
              <X size={17} />
            </button>
          )}
        </section>
      )}

      {page === "overview" ? (
        <>
          <section className="welcome">
            <div className="eyebrow">
              <Activity size={13} />
              YOUR SECURITY DASHBOARD
            </div>

            <h2>
              Stay ahead of
              <br />
              risky changes.
            </h2>

            <p>
              See suspicious code changes and security findings in one place.
            </p>
          </section>

          <section className={`status-card backend-card ${backendState}`}>
            <div className="status-icon">
              {backendState === "offline" ? (
                <ShieldAlert size={26} />
              ) : (
                <ShieldCheck size={26} />
              )}
            </div>

            <div className="status-content">
              <span>DIFFSHIELD BACKEND</span>
              <h3>
                {backendState === "checking"
                  ? "Checking connection…"
                  : backendState === "connected"
                    ? "Backend connected"
                    : "Backend offline"}
              </h3>
              <p>
                {backendState === "offline"
                  ? backendError || "Start the backend at 127.0.0.1:8000"
                  : latestScan?.status === "ERROR"
                    ? `Last scan failed: ${latestScan.error ?? "Unknown backend error."}`
                    : latestScan
                      ? `Last scan: ${latestScan.repository ?? "GitHub PR"} · ${latestScan.status}`
                      : backendState === "connected"
                        ? "Open a GitHub pull request to scan it"
                        : "Checking backend connection"}
              </p>
            </div>

            <span className={`status-badge ${backendState}`}>
              {backendState === "checking"
                ? "CHECKING"
                : backendState === "connected"
                  ? "ONLINE"
                  : "OFFLINE"}
            </span>
            <button
              className="backend-refresh"
              type="button"
              aria-label="Check backend connection"
              title="Check backend connection"
              onClick={refreshBackendStatus}
              disabled={backendState === "checking"}
            >
              <RefreshCw size={15} />
            </button>
          </section>

          <section
            className={`status-card backend-card ${
              githubAppStatus?.merge_protection === "ENFORCED"
                ? "connected"
                : "offline"
            }`}
          >
            <div className="status-icon">
              {githubAppStatus?.merge_protection === "ENFORCED" ? (
                <ShieldCheck size={26} />
              ) : (
                <ShieldAlert size={26} />
              )}
            </div>
            <div className="status-content">
              <span>GITHUB APP · REQUIRED CHECK</span>
              <h3>
                {githubAppStatus
                  ? githubAppStatus.app_configured
                    ? githubAppStatus.installed
                      ? "GitHub App installation recorded"
                      : "GitHub App not verified as installed"
                    : "GitHub App not configured"
                  : "GitHub App status unavailable"}
              </h3>
              <p>
                {githubAppError ||
                  githubAppStatus?.reason ||
                  "Merge enforcement has not been verified."}
              </p>
            </div>
            <span
              className={`status-badge ${
                githubAppStatus?.merge_protection === "ENFORCED"
                  ? "connected"
                  : "offline"
              }`}
            >
              {githubAppStatus?.merge_protection ?? "UNKNOWN"}
            </span>
          </section>

          <section className="stats">
            <div className="stat-card">
              <GitPullRequest size={19} />
              <h2>{latestScan ? "1" : "—"}</h2>
              <p>Latest PR scan</p>
            </div>

            <div className="stat-card">
              <ShieldAlert size={19} />
              <h2>{activeQuarantines.length}</h2>
              <p>Active quarantines</p>
            </div>

            <div className="stat-card">
              <Package size={19} />
              <h2>{backendState === "connected" ? "ON" : "OFF"}</h2>
              <p>Backend</p>
            </div>
          </section>

          <section className="quarantine-section alerts-section">
            <div className="section-heading">
              <div>
                <h3>Persistent PR quarantines</h3>
                <p>
                  {quarantineSource === "cached"
                    ? "Showing saved data; backend refresh is unavailable."
                    : "Current state and deadline from the backend"}
                </p>
              </div>
              <span className="alert-count">
                {String(activeQuarantines.length).padStart(2, "0")}
              </span>
            </div>

            {quarantineError && (
              <p className="quarantine-warning" role="status">
                Backend quarantine state could not be refreshed: {quarantineError}
                {quarantineSource === "unavailable"
                  ? " Do not treat this PR as verified clean."
                  : ""}
              </p>
            )}

            {activeQuarantines.length > 0 ? (
              <div className="quarantine-list">
                {activeQuarantines.map((quarantine) => {
                  const [owner, repo] = quarantine.repository.split("/", 2);
                  const pullRequestUrl =
                    owner && repo
                      ? `https://github.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pull/${quarantine.pr_number}`
                      : null;
                  const findingTitle =
                    typeof quarantine.finding.title === "string"
                      ? quarantine.finding.title
                      : "Security finding";

                  return (
                    <article
                      className={`quarantine-card ${quarantine.state.toLowerCase()}`}
                      key={quarantine.finding_id}
                    >
                      <div className="quarantine-card-heading">
                        <span className="severity high">{quarantine.state}</span>
                        <span className="quarantine-risk">
                          {quarantine.severity} · risk {quarantine.risk_score}
                        </span>
                      </div>
                      <h4>{findingTitle}</h4>
                      <p>
                        {quarantine.repository} · PR #{quarantine.pr_number}
                        {quarantine.pr_author
                          ? ` · @${quarantine.pr_author}`
                          : ""}
                      </p>
                      <p className="quarantine-countdown">
                        {formatCountdown(quarantine.review_deadline)}
                      </p>
                      <p className="quarantine-commit">
                        Commit: {quarantine.head_sha || "unavailable"}
                      </p>
                      {pullRequestUrl && (
                        <a href={pullRequestUrl} target="_blank" rel="noreferrer">
                          Open pull request
                        </a>
                      )}
                    </article>
                  );
                })}
              </div>
            ) : quarantineSource === "loading" ? (
              <p className="empty-state">Loading backend quarantine records…</p>
            ) : quarantineSource === "unavailable" ? (
              <p className="empty-state">
                Quarantine state unavailable. A failed connection is not a clean
                scan.
              </p>
            ) : (
              <p className="empty-state">
                No active quarantine records were returned. This is not a
                guarantee that the pull request is safe.
              </p>
            )}

            <div
              className={`enforcement-notice ${
                mergeProtection.status === "ENFORCED" ? "enforced" : "not-enforced"
              }`}
              role="note"
            >
              <ShieldAlert size={16} />
              <div>
                <strong>
                  GitHub merge protection: {mergeProtection.status}
                </strong>
                <span>
                  {mergeProtection.reason ||
                    "Required branch protection has not been verified."}
                </span>
              </div>
            </div>
          </section>

          <section className="alerts-section" id="security-findings">
            <div className="section-heading">
              <div>
                <h3>Security findings</h3>
                <p>Latest finding from your PR scans</p>
              </div>

              <span className="alert-count">{visibleThreat ? "01" : "00"}</span>
            </div>

            {visibleThreat ? (
              <div className="alert-list">
                  <article className="alert-card" key={visibleThreat.id}>
                    <div className="alert-top">
                      <span
                        className={`severity ${visibleThreat.severity.toLowerCase()}`}
                      >
                        {visibleThreat.severity} RISK
                      </span>

                      <span className="alert-time">
                        <Clock3 size={11} />
                        {new Date(visibleThreat.detectedAt).toLocaleString()}
                      </span>
                    </div>

                    <h4>{visibleThreat.title}</h4>

                    <p>{visibleThreat.description}</p>

                    <div className="repository">
                      <GitBranch size={14} />
                      {visibleThreat.repository}
                    </div>

                    <div className="finding-id">
                      FINDING ID: {visibleThreat.id}
                    </div>
                  </article>
              </div>
            ) : (
              <p className="empty-state">
                {latestScan?.status === "ERROR"
                  ? `The latest scan failed: ${latestScan.error ?? "Unknown backend error."}`
                  : latestScan?.status === "PASSED"
                    ? "No security guard regressions found in the latest scan."
                    : latestThreat
                      ? "This finding is hidden by your current severity filters."
                      : "No backend finding yet. Open a GitHub pull request while the backend is running."}
              </p>
            )}
          </section>

          <section className="activity-section">
            <div className="section-heading">
              <div>
                <h3>Security intelligence</h3>
                <p>Our detection capabilities</p>
              </div>

              <Shield size={19} />
            </div>

            {features.map((feature) => {
              const Icon = feature.icon;

              return (
                <button
                  className="feature-row ds-motion-card"
                  key={feature.id}
                  onClick={() => setPage(feature.id)}
                  aria-label={`Learn about ${feature.title}`}
                >
                  <span className="feature-icon">
                    <Icon size={17} />
                  </span>

                  <span className="feature-description">
                    <span className="feature-title">{feature.title}</span>
                    <span className="feature-subtitle">{feature.description}</span>
                  </span>

                  <ChevronRight size={17} />
                </button>
              );
            })}
          </section>
        </>
      ) : (
        <section className="detail-page">
          <div className="page-header">
            <button
              className="back-button"
              onClick={() => setPage("overview")}
              aria-label="Back to security overview"
            >
              <ArrowLeft size={15} />
              Security overview
            </button>
            <h2>{page === "settings" ? "Settings" : activeFeature?.heading}</h2>
          </div>

          {page === "settings" ? (
            <div className="detail-section">
              <div className="detail-card">
                <h3>Finding filters</h3>
                <p>
                  Choose which finding severities appear on the security overview.
                </p>

                {(["HIGH", "MEDIUM"] as const).map((severity) => (
                  <label className="setting-row" key={severity}>
                    <div>
                      <h4>{severity === "HIGH" ? "High risk" : "Medium risk"}</h4>
                      <p>
                        {severity === "HIGH"
                          ? "Show high-risk findings"
                          : "Show medium-risk findings"}
                      </p>
                    </div>
                    <input
                      type="checkbox"
                      checked={visibleSeverities[severity]}
                      onChange={() => toggleSeverity(severity)}
                      aria-label={`Show ${severity.toLowerCase()} risk findings`}
                    />
                  </label>
                ))}
              </div>

              <button
                className="primary-button"
                onClick={() =>
                  setVisibleSeverities({ HIGH: true, MEDIUM: true })
                }
              >
                <Check size={15} />
                Reset finding filters
              </button>
            </div>
          ) : activeFeature ? (
            <div className="detail-section">
              <div className="detail-card">
                <p>{activeFeature.summary}</p>
                <span className="detail-label">HOW IT WORKS</span>

                {activeFeature.steps.map((step, index) => (
                  <div className="pipeline-step" key={step}>
                    <span>{String(index + 1).padStart(2, "0")}</span>
                    <p>{step}</p>
                  </div>
                ))}
              </div>

              <div className="demo-notice" role="note">
                <ShieldAlert size={15} />
                <span>
                  {page === "patch-comparison"
                    ? "The backend scans GitHub pull request diffs using its regression engine."
                    : "The backend must be running locally to analyze pull requests."}
                </span>
              </div>

              {page === "security-notifications" && (
                <button
                  className="primary-button"
                  onClick={() => setPage("settings")}
                >
                  Configure finding filters
                  <ChevronRight size={15} />
                </button>
              )}
            </div>
          ) : null}
        </section>
      )}

      <footer className="footer">
        <div>
          <ShieldCheck size={14} />
          DIFF SHIELD v0.1.0
        </div>

        <span>Built for safer open source.</span>
      </footer>
    </main>
  );
}

export default App;
