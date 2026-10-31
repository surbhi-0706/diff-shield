
import {
  ShieldCheck,
  ShieldAlert,
  GitPullRequest,
  Activity,
  Settings,
  Search,
  Shield,
  Clock3,
  Package,
  ChevronRight,
  Bell,
  GitBranch,
} from "lucide-react";

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
];

function App() {
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

        <button className="icon-button" aria-label="Settings">
          <Settings size={19} />
        </button>
      </header>

      <section className="welcome">
        <div className="eyebrow">
          <Activity size={13} />
          SECURITY OVERVIEW
        </div>

        <h2>
          Your code deserves
          <br />
          a stronger shield.
        </h2>

        <p>
          Monitor open-source changes and identify
          suspicious security modifications before
          they become a threat.
        </p>
      </section>

      <section className="status-card">
        <div className="status-icon">
          <ShieldCheck size={26} />
        </div>

        <div className="status-content">
          <span>PROTECTION STATUS</span>
          <h3>Extension initialized</h3>
          <p>Real-time monitoring not connected yet</p>
        </div>

        <span className="status-badge">DEMO</span>
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

      <section className="alerts-section">
        <div className="section-heading">
          <div>
            <h3>Security findings</h3>
            <p>Illustrative security alerts</p>
          </div>

          <span className="alert-count">02</span>
        </div>

        <div className="alert-list">
          {alerts.map((alert) => (
            <article className="alert-card" key={alert.id}>
              <div className="alert-top">
                <span
                  className={`severity ${alert.severity.toLowerCase()}`}
                >
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

              <div className="finding-id">
                FINDING ID: {alert.id}
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="activity-section">
        <div className="section-heading">
          <div>
            <h3>Security intelligence</h3>
            <p>Our detection capabilities</p>
          </div>

          <Shield size={19} />
        </div>

        <div className="feature-row">
          <div className="feature-icon">
            <Search size={17} />
          </div>

          <div>
            <h4>Patch comparison</h4>
            <p>Compare changes against historical fixes.</p>
          </div>

          <ChevronRight size={17} />
        </div>

        <div className="feature-row">
          <div className="feature-icon">
            <GitPullRequest size={17} />
          </div>

          <div>
            <h4>Pull request analysis</h4>
            <p>Inspect suspicious repository changes.</p>
          </div>

          <ChevronRight size={17} />
        </div>

        <div className="feature-row">
          <div className="feature-icon">
            <Bell size={17} />
          </div>

          <div>
            <h4>Security notifications</h4>
            <p>Bring important findings to your attention.</p>
          </div>

          <ChevronRight size={17} />
        </div>
      </section>

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
