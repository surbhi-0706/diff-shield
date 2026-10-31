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
  Search,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";

import {
  dismissLatestThreat,
  subscribeToLatestThreat,
  type ThreatFinding,
} from "./services/threatFindings";
import "./App.css";

const alerts = [
  {
    id: "DS-001",
    severity: "HIGH",
    title: "Possible vulnerability reintroduction",
    description:
      "A previously patched security pattern may have returned in a dependency update.",
    repository: "example/package",
    time: "Demo finding",
  },
  {
    id: "DS-002",
    severity: "MEDIUM",
    title: "Suspicious dependency modification",
    description:
      "A dependency version changed and requires additional security review.",
    repository: "example/api-client",
    time: "Demo finding",
  },
] as const;

const features = [
  {
    id: "patch-comparison",
    icon: Search,
    title: "Patch comparison",
    description: "Compare changes against historical fixes.",
    heading: "Patch comparison",
    summary:
      "Diff Shield is designed to compare incoming code changes with historical vulnerability fixes.",
    steps: [
      "Identify security fixes in project history.",
      "Compare incoming changes with the original patch.",
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
      "Pull request monitoring is not connected yet. Findings on the overview are illustrative demo data.",
    steps: [
      "Connect a repository monitoring integration.",
      "Review changed dependencies and security-sensitive code.",
      "Inspect flagged changes before merging.",
    ],
  },
  {
    id: "security-notifications",
    icon: Bell,
    title: "Security notifications",
    description: "Bring important findings to your attention.",
    heading: "Security notifications",
    summary:
      "Notification delivery is not connected yet. This popup currently shows demo findings only.",
    steps: [
      "Choose the finding severities shown on the overview.",
      "Connect monitoring to receive live security findings.",
      "Review each finding in its repository before taking action.",
    ],
  },
] as const;

type FeatureId = (typeof features)[number]["id"];
type Page = "overview" | "settings" | FeatureId;
type Severity = "HIGH" | "MEDIUM";

function App() {
  const [page, setPage] = useState<Page>("overview");
  const [latestThreat, setLatestThreat] = useState<ThreatFinding | null>(null);
  const [visibleSeverities, setVisibleSeverities] = useState<
    Record<Severity, boolean>
  >({ HIGH: true, MEDIUM: true });

  useEffect(
    () => subscribeToLatestThreat(setLatestThreat),
    [],
  );

  const visibleAlerts = alerts.filter(
    (alert) => visibleSeverities[alert.severity],
  );
  const activeFeature = features.find((feature) => feature.id === page);

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

      {latestThreat && (
        <section className="threat-banner" role="alert" aria-live="assertive">
          <div className="threat-banner-icon">
            <AlertTriangle size={19} />
          </div>
          <div className="threat-banner-content">
            <strong>MALICIOUS CHANGE DETECTED</strong>
            <span>{latestThreat.title}</span>
            <small>
              {latestThreat.repository} ·{" "}
              {new Date(latestThreat.detectedAt).toLocaleString()}
            </small>
          </div>
          <button
            className="threat-dismiss"
            aria-label="Dismiss security alert"
            onClick={dismissThreat}
          >
            <X size={17} />
          </button>
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

          <section className="status-card">
            <div className="status-icon">
              <ShieldCheck size={26} />
            </div>

            <div className="status-content">
              <span>PROTECTION STATUS</span>
              <h3>Alert receiver ready</h3>
              <p>Connect a scanner for live detection</p>
            </div>

            <span className="status-badge">SETUP</span>
          </section>

          <section className="stats">
            <div className="stat-card">
              <GitPullRequest size={19} />
              <h2>12</h2>
              <p>Sample PRs</p>
            </div>

            <div className="stat-card">
              <ShieldAlert size={19} />
              <h2>02</h2>
              <p>Sample alerts</p>
            </div>

            <div className="stat-card">
              <Package size={19} />
              <h2>08</h2>
              <p>Dependencies</p>
            </div>
          </section>

          <section className="alerts-section" id="security-findings">
            <div className="section-heading">
              <div>
                <h3>Security findings</h3>
                <p>Illustrative security alerts</p>
              </div>

              <span className="alert-count">
                {String(visibleAlerts.length).padStart(2, "0")}
              </span>
            </div>

            {visibleAlerts.length > 0 ? (
              <div className="alert-list">
                {visibleAlerts.map((alert) => (
                  <article className="alert-card" key={alert.id}>
                    <div className="alert-top">
                      <span className={`severity ${alert.severity.toLowerCase()}`}>
                        {alert.severity} RISK
                      </span>

                      <span className="alert-time">
                        <Clock3 size={11} />
                        {alert.time}
                      </span>
                    </div>

                    <h4>{alert.title}</h4>

                    <p>{alert.description}</p>

                    <div className="repository">
                      <GitBranch size={14} />
                      {alert.repository}
                    </div>

                    <div className="finding-id">FINDING ID: {alert.id}</div>
                  </article>
                ))}
              </div>
            ) : (
              <p className="empty-state">
                No findings match your filters. Update them in settings.
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
                  className="feature-row"
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
                  Choose which demo findings appear on the security overview.
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
                    ? "Analysis is not connected. The findings shown are examples."
                    : "Live monitoring is not connected in this demo."}
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
