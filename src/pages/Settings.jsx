import {
  Settings as SettingsIcon,
  Brain,
  Database,
  ShieldCheck,
  Bell,
} from "lucide-react";

import PageLayout from "../components/PageLayout";

function Settings() {
  return (
    <PageLayout
      title="Settings"
      subtitle="Configure SecureX AI security preferences"
    >
      <div className="settings-page">

        <section className="settings-card">

          <div className="settings-heading">
            <div className="settings-heading-icon">
              <Brain size={21} />
            </div>

            <div>
              <h2>AI Detection Engine</h2>
              <p>Configure threat detection behaviour</p>
            </div>
          </div>

          <div className="setting-row">
            <div>
              <strong>Isolation Forest</strong>
              <span>AI anomaly detection model</span>
            </div>

            <span className="setting-active">
              ACTIVE
            </span>
          </div>

          <div className="setting-row">
            <div>
              <strong>Anomaly Detection</strong>
              <span>Automatically analyze network events</span>
            </div>

            <label className="toggle">
              <input type="checkbox" defaultChecked />
              <span></span>
            </label>
          </div>

          <div className="setting-row">
            <div>
              <strong>Automatic Risk Scoring</strong>
              <span>Calculate risk using AI and policy context</span>
            </div>

            <label className="toggle">
              <input type="checkbox" defaultChecked />
              <span></span>
            </label>
          </div>

        </section>

        <section className="settings-card">

          <div className="settings-heading">
            <div className="settings-heading-icon">
              <ShieldCheck size={21} />
            </div>

            <div>
              <h2>Zero Trust</h2>
              <p>Identity and access protection</p>
            </div>
          </div>

          <div className="setting-row">
            <div>
              <strong>Continuous Verification</strong>
              <span>Re-check sessions when risk changes</span>
            </div>

            <label className="toggle">
              <input type="checkbox" defaultChecked />
              <span></span>
            </label>
          </div>

          <div className="setting-row">
            <div>
              <strong>MFA for Medium Risk</strong>
              <span>Require additional verification</span>
            </div>

            <label className="toggle">
              <input type="checkbox" defaultChecked />
              <span></span>
            </label>
          </div>

        </section>

        <section className="settings-card">

          <div className="settings-heading">
            <div className="settings-heading-icon">
              <Database size={21} />
            </div>

            <div>
              <h2>System</h2>
              <p>SecureX AI infrastructure status</p>
            </div>
          </div>

          <div className="system-settings-grid">

            <div>
              <span>Frontend</span>
              <strong>React + Vite</strong>
            </div>

            <div>
              <span>Backend</span>
              <strong>FastAPI</strong>
            </div>

            <div>
              <span>Database</span>
              <strong>SQLite</strong>
            </div>

            <div>
              <span>AI Engine</span>
              <strong>scikit-learn</strong>
            </div>

          </div>

        </section>

        <section className="settings-card">

          <div className="settings-heading">
            <div className="settings-heading-icon">
              <Bell size={21} />
            </div>

            <div>
              <h2>Notifications</h2>
              <p>Security alert preferences</p>
            </div>
          </div>

          <div className="setting-row">
            <div>
              <strong>High Risk Alerts</strong>
              <span>Notify when risk exceeds 60</span>
            </div>

            <label className="toggle">
              <input type="checkbox" defaultChecked />
              <span></span>
            </label>
          </div>

        </section>

      </div>
    </PageLayout>
  );
}

export default Settings;
