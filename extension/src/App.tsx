
import { useCallback, useEffect, useState } from "react";
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
  Search,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

import {
  subscribeToLatestThreat,
  type ThreatFinding,
} from "./services/threatFindings";

import "./App.css";

// --------------------------------------------------
// Types
// --------------------------------------------------

type QuarantineState =
  | "QUARANTINED"
  | "REVIEW_REQUIRED"
  | "ESCALATED"
  | "REJECTED"
  | "RESOLVED"
  | "CLEAN";

interface Quarantine {
  finding_id?: string;
  state: QuarantineState;
  repository?: string;
  pr_number?: number | string;
  pr_url?: string;
  pr_author?: string;
  head_sha?: string;
  severity?: string;
  risk_score?: number;
  detected_at?: string;
  review_deadline?: string;
  finding?: {
    id?: string;
    title?: string;
    description?: string;
    file_path?: string;
  };
}

interface ScanData {
  status?: string;
  scannedAt?: string;
  prUrl?: string;
  repository?: string;
  prNumber?: number | string;
  riskScore?: number;
  error?: string;
}

interface BackendResponse<T> {
  ok: boolean;
  result?: T;
  error?: string;
}

interface ChromeApi {
  runtime?: {
    lastError?: { message?: string };
    sendMessage(
      message: Record<string, unknown>,
      callback: (response: BackendResponse<unknown>) => void,
    ): void;
  };
}

const chromeApi = (
  globalThis as typeof globalThis & {
    chrome?: ChromeApi;
  }
).chrome;

const ACTIVE_STATES: QuarantineState[] = [
  "QUARANTINED",
  "REVIEW_REQUIRED",
  "ESCALATED",
  "REJECTED",
];

// --------------------------------------------------
// Features
// --------------------------------------------------

const features = [
  {
    id: "patch-comparison",
    icon: Search,
    title: "Patch comparison",
    description: "Compare changes against historical fixes.",
    heading: "Patch comparison",
    summary:
      "DIFF SHIELD analyzes incoming code changes against known security patterns and historical vulnerability fixes.",
    steps: [
      "Identify security fixes in project history.",
      "Compare incoming changes with historical patches.",
      "Highlight code that may reintroduce a known vulnerability.",
    ],
  },
  {
    id: "pull-request-analysis",
    icon: GitPullRequest,
    title: "Pull request analysis",
    description: "Inspect suspicious repository changes.",
    heading: "Pull request analysis",
    summary:
      "DIFF SHIELD monitors connected pull requests and displays the latest analysis results.",
    steps: [
      "Detect a GitHub pull request.",
      "Analyze changed code and dependencies.",
      "Display security findings and review status.",
    ],
  },
  {
    id: "security-notifications",
    icon: Bell,
    title: "Security notifications",
    description: "Bring important findings to your attention.",
    heading: "Security notifications",
    summary:
      "Security findings and quarantine states are retrieved from the DIFF SHIELD backend.",
    steps: [
      "Receive a security finding.",
      "Review its severity and supporting evidence.",
      "Follow the authorized review and resolution process.",
    ],
  },
] as const;

type FeatureId = (typeof features)[number]["id"];
type Page = "overview" | "settings" | FeatureId;
type Severity = "HIGH" | "MEDIUM" | "CRITICAL" | "LOW";

// --------------------------------------------------
// Chrome extension messaging
// --------------------------------------------------

function sendExtensionMessage<T>(
  message: Record<string, unknown>,
): Promise<T> {
  return new Promise((resolve, reject) => {
    if (!chromeApi?.runtime?.sendMessage) {
      reject(
        new Error(
          "DIFF SHIELD extension runtime is unavailable. Open the installed Chrome extension.",
        ),
      );
      return;
    }

    chromeApi.runtime.sendMessage(message, (response) => {
      const runtimeError = chromeApi.runtime?.lastError;

      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }

      if (!response?.ok) {
        reject(
          new Error(response?.error || "Backend request failed."),
        );
        return;
      }

      resolve(response.result as T);
    });
  });
}

function formatDate(value?: string): string {
  if (!value) return "Not available";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "Not available";
  }

  return date.toLocaleString();
}

function getRemainingTime(deadline: string | undefined, currentTime: number): string {
  if (!deadline) return "Deadline unavailable";

  const deadlineTime = new Date(deadline).getTime();
  const remaining = deadlineTime - currentTime;

  if (!Number.isFinite(deadlineTime) || !Number.isFinite(remaining)) {
    return "Deadline unavailable";
  }

  if (remaining <= 0) {
    return "Review deadline passed — quarantine remains active";
  }

  const hours = Math.floor(remaining / 3600000);
  const minutes = Math.floor((remaining % 3600000) / 60000);
  const seconds = Math.floor((remaining % 60000) / 1000);

  return `${hours}h ${minutes}m ${seconds}s remaining`;
}

// --------------------------------------------------
// Main application
// --------------------------------------------------

function App() {
  const [page, setPage] = useState<Page>("overview");

  const [latestThreat, setLatestThreat] =
    useState<ThreatFinding | null>(null);

  const [quarantines, setQuarantines] = useState<Quarantine[]>([]);

  const [latestScan, setLatestScan] =
    useState<ScanData | null>(null);

  const [backendConnected, setBackendConnected] = useState(false);

  const [loading, setLoading] = useState(true);

  const [backendError, setBackendError] = useState<string | null>(null);

  const [currentTime, setCurrentTime] = useState<number | null>(null);

  const [visibleSeverities, setVisibleSeverities] = useState<
    Record<Severity, boolean>
  >({
    CRITICAL: true,
    HIGH: true,
    MEDIUM: true,
    LOW: true,
  });

  // ------------------------------------------------
  // Backend health
  // ------------------------------------------------

  const checkBackend = useCallback(async () => {
    try {
      await sendExtensionMessage({
        type: "DIFF_SHIELD_BACKEND_HEALTH",
      });

      setBackendConnected(true);
      setBackendError(null);
    } catch (error) {
      setBackendConnected(false);
      setBackendError(
        error instanceof Error
          ? error.message
          : "Backend unavailable.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  // ------------------------------------------------
  // Load quarantines
  // ------------------------------------------------

  const loadQuarantines = useCallback(async () => {
    try {
      const result = await sendExtensionMessage<{
        items: Quarantine[];
      }>({
        type: "DIFF_SHIELD_LIST_QUARANTINES",
      });

      setQuarantines(
        Array.isArray(result?.items) ? result.items : [],
      );
    } catch (error) {
      console.error(
        "[DiffShield] Could not load quarantines:",
        error,
      );
    }
  }, []);

  // ------------------------------------------------
  // Load latest scan
  // ------------------------------------------------

  const loadLatestScan = useCallback(() => {
    const chromeStorage = (
      globalThis as typeof globalThis & {
        chrome?: {
          storage?: {
            local: {
              get(
                key: string,
                callback: (items: Record<string, unknown>) => void,
              ): void;
            };
          };
        };
      }
    ).chrome?.storage?.local;

    if (!chromeStorage) return;

    chromeStorage.get(
      "latestScan",
      (items) => {
        const stored = items.latestScan;

        if (
          typeof stored === "object" &&
          stored !== null
        ) {
          const scan = stored as ScanData;
          setLatestScan(scan);
        }
      },
    );
  }, []);

  // ------------------------------------------------
  // Initial setup and subscriptions
  // ------------------------------------------------

  useEffect(() => {
    const unsubscribe = subscribeToLatestThreat(setLatestThreat);

    const initialRefreshTimer = window.setTimeout(() => {
      void checkBackend();
      void loadQuarantines();
      loadLatestScan();
      setCurrentTime(Date.now());
    }, 0);

    const refreshTimer = window.setInterval(() => {
      void checkBackend();
      void loadQuarantines();
      loadLatestScan();
    }, 30000);

    const clockTimer = window.setInterval(() => {
      setCurrentTime(Date.now());
    }, 1000);

    return () => {
      unsubscribe();
      window.clearTimeout(initialRefreshTimer);
      window.clearInterval(refreshTimer);
      window.clearInterval(clockTimer);
    };
  }, [
    checkBackend,
    loadQuarantines,
    loadLatestScan,
  ]);

  // ------------------------------------------------
  // Filtering and counts
  // ------------------------------------------------

  const activeQuarantines = quarantines.filter((item) =>
    ACTIVE_STATES.includes(item.state),
  );

  const visibleQuarantines = activeQuarantines.filter((item) => {
    const severity = (item.severity || "MEDIUM").toUpperCase() as Severity;

    return visibleSeverities[severity] ?? true;
  });

  const activeFeature = features.find(
    (feature) => feature.id === page,
  );

  const latestThreatActive = Boolean(
    latestThreat &&
    (
      latestThreat.status === undefined ||
      ACTIVE_STATES.includes(
        latestThreat.status as QuarantineState,
      )
    ),
  );

  // ------------------------------------------------
  // Actions
  // ------------------------------------------------

  function toggleSeverity(severity: Severity) {
    setVisibleSeverities((current) => ({
      ...current,
      [severity]: !current[severity],
    }));
  }

  // ------------------------------------------------
  // Render
  // ------------------------------------------------

  return (
    <main className="app">
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

      {/* Real security finding banner */}

      {latestThreatActive && latestThreat && (
        <section
          className="threat-banner"
          role="alert"
          aria-live="assertive"
        >
          <div className="threat-banner-icon">
            <AlertTriangle size={19} />
          </div>

          <div className="threat-banner-content">
            <strong>SECURITY FINDING DETECTED</strong>

            <span>{latestThreat.title}</span>

            <small>
              {latestThreat.repository} ·{" "}
              {formatDate(latestThreat.detectedAt)}
            </small>

            {latestThreat.prUrl && (
              <a
                href={latestThreat.prUrl}
                target="_blank"
                rel="noopener noreferrer"
              >
                Open pull request
              </a>
            )}
          </div>
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

          {/* Backend connection status */}

          <section className="status-card">
            <div className="status-icon">
              {backendConnected ? (
                <ShieldCheck size={26} />
              ) : (
                <ShieldAlert size={26} />
              )}
            </div>

            <div className="status-content">
              <span>PROTECTION STATUS</span>

              <h3>
                {loading
                  ? "Checking connection..."
                  : backendConnected
                    ? "Backend connected"
                    : "Backend unavailable"}
              </h3>

              <p>
                {backendConnected
                  ? "Backend health check successful"
                  : backendError || "Security scanning is unavailable"}
              </p>
            </div>

            <span
              className="status-badge"
              style={{
                color: backendConnected ? "#3fb950" : "#ff5555",
              }}
            >
              {backendConnected ? "CONNECTED" : "OFFLINE"}
            </span>
          </section>

          {/* Real statistics */}

          <section className="stats">
            <div className="stat-card">
              <GitPullRequest size={19} />
              <h2>{new Set(
                quarantines.map(
                  (item) =>
                    `${item.repository}:${item.pr_number}`,
                ),
              ).size}</h2>
              <p>Tracked PRs</p>
            </div>

            <div className="stat-card">
              <ShieldAlert size={19} />
              <h2>{activeQuarantines.length}</h2>
              <p>Active quarantines</p>
            </div>

            <div className="stat-card">
              <Package size={19} />
              <h2>—</h2>
              <p>Dependencies</p>
            </div>
          </section>

          {/* Latest scan */}

          {latestScan && (
            <section className="alerts-section">
              <div className="section-heading">
                <div>
                  <h3>Latest scan</h3>
                  <p>Most recent pull request analysis</p>
                </div>

                <span className="alert-count">
                  {latestScan.status || "UNKNOWN"}
                </span>
              </div>

              <article className="alert-card">
                <h4>
                  {latestScan.repository || "Repository unavailable"}
                </h4>

                <p>
                  Pull request: #{latestScan.prNumber ?? "Unknown"}
                </p>

                <p>
                  Status: {latestScan.status || "Unknown"}
                </p>

                {typeof latestScan.riskScore === "number" && (
                  <p>Risk score: {latestScan.riskScore}/100</p>
                )}

                {latestScan.error && (
                  <p>{latestScan.error}</p>
                )}

                <small>
                  Last scanned: {formatDate(latestScan.scannedAt)}
                </small>

                {latestScan.prUrl && (
                  <div>
                    <a
                      href={latestScan.prUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      Open pull request
                    </a>
                  </div>
                )}
              </article>
            </section>
          )}

          {/* Real quarantine findings */}

          <section className="alerts-section" id="security-findings">
            <div className="section-heading">
              <div>
                <h3>Security findings</h3>
                <p>Findings received from DIFF SHIELD</p>
              </div>

              <span className="alert-count">
                {String(visibleQuarantines.length).padStart(2, "0")}
              </span>
            </div>

            {visibleQuarantines.length > 0 ? (
              <div className="alert-list">
                {visibleQuarantines.map((item, index) => {
                  const finding = item.finding || {};

                  const findingId =
                    item.finding_id ||
                    finding.id ||
                    `finding-${index}`;

                  const deadline = item.review_deadline;

                  return (
                    <article
                      className="alert-card"
                      key={findingId}
                    >
                      <div className="alert-top">
                        <span
                          className={`severity ${
                            (item.severity || "MEDIUM").toLowerCase()
                          }`}
                        >
                          {item.severity || "UNKNOWN"} RISK
                        </span>

                        <span className="alert-time">
                          <Clock3 size={11} />
                          {item.state}
                        </span>
                      </div>

                      <h4>
                        {finding.title || "Security review required"}
                      </h4>

                      <p>
                        {finding.description ||
                          "A security finding requires investigation."}
                      </p>

                      <div className="repository">
                        <GitBranch size={14} />
                        {item.repository || "Unknown repository"}
                      </div>

                      <div className="finding-id">
                        FINDING ID: {findingId}
                      </div>

                      <p>
                        Pull request: #{item.pr_number || "Unknown"}
                      </p>

                      <p>
                        Author: {item.pr_author || "Unknown"}
                      </p>

                      <p>
                        Risk score: {item.risk_score ?? "Unknown"}/100
                      </p>

                      {finding.file_path && (
                        <p>Affected file: {finding.file_path}</p>
                      )}

                      <p>
                        Detected: {formatDate(item.detected_at)}
                      </p>

                      <div className="finding-id">
                        {currentTime === null
                          ? "Updating review countdown..."
                          : getRemainingTime(deadline, currentTime)}
                      </div>

                      {item.pr_url && (
                        <a
                          href={item.pr_url}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          View pull request
                        </a>
                      )}
                    </article>
                  );
                })}
              </div>
            ) : (
              <p className="empty-state">
                {backendConnected
                  ? "No active security quarantines were returned by the backend."
                  : "Connect to the DIFF SHIELD backend to retrieve security findings. This does not mean your repositories are safe."}
              </p>
            )}
          </section>

          {/* Security intelligence */}

          <section className="activity-section">
            <div className="section-heading">
              <div>
                <h3>Security intelligence</h3>
                <p>Detection capabilities</p>
              </div>

              <Shield size={19} />
            </div>

            {features.map((feature) => {
              const Icon = feature.icon;

              return (
                <button
                  className="feature-row"
                  key={feature.id}
                  onClick={() => setPage(feature.id)}
                  aria-label={`Learn about ${feature.title}`}
                >
                  <span className="feature-icon">
                    <Icon size={17} />
                  </span>

                  <span className="feature-description">
                    <span className="feature-title">
                      {feature.title}
                    </span>

                    <span className="feature-subtitle">
                      {feature.description}
                    </span>
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

            <h2>
              {page === "settings"
                ? "Settings"
                : activeFeature?.heading}
            </h2>
          </div>

          {page === "settings" ? (
            <div className="detail-section">
              <div className="detail-card">
                <h3>Finding filters</h3>

                <p>
                  Choose which security finding severities appear
                  on the dashboard.
                </p>

                {(
                  ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const
                ).map((severity) => (
                  <label className="setting-row" key={severity}>
                    <div>
                      <h4>{severity} risk</h4>
                      <p>Show {severity.toLowerCase()} findings</p>
                    </div>

                    <input
                      type="checkbox"
                      checked={visibleSeverities[severity]}
                      onChange={() => toggleSeverity(severity)}
                      aria-label={`Show ${severity.toLowerCase()} findings`}
                    />
                  </label>
                ))}
              </div>

              <button
                className="primary-button"
                onClick={() =>
                  setVisibleSeverities({
                    CRITICAL: true,
                    HIGH: true,
                    MEDIUM: true,
                    LOW: true,
                  })
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

                <span className="detail-label">
                  HOW IT WORKS
                </span>

                {activeFeature.steps.map((step, index) => (
                  <div className="pipeline-step" key={step}>
                    <span>
                      {String(index + 1).padStart(2, "0")}
                    </span>

                    <p>{step}</p>
                  </div>
                ))}
              </div>

              <div className="demo-notice" role="note">
                <ShieldAlert size={15} />
                <span>
                  Detection capabilities depend on the configured
                  backend and GitHub integration.
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
