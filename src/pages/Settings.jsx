import { useEffect, useState } from "react";
import {
  Settings as SettingsIcon,
  Brain,
  Database,
  ShieldCheck,
  Bell,
  RotateCcw,
  Save,
  SlidersHorizontal,
  CheckCircle,
} from "lucide-react";
import PageLayout from "../components/PageLayout";

const STORAGE_KEY = "sentinelai_security_preferences";

const DEFAULTS = {
  anomalyDetection: true,
  automaticRiskScoring: true,
  continuousVerification: true,
  mfaMediumRisk: true,
  highRiskAlerts: true,
  criticalRiskAlerts: true,
  assistantSuggestions: true,
  detectionSensitivity: "balanced",
  highRiskThreshold: 60,
  criticalRiskThreshold: 80,
};

const sections = {
  card: {
    background: "#111827",
    border: "1px solid #263449",
    borderRadius: 14,
    padding: 22,
    marginBottom: 18,
  },
  heading: {
    display: "flex",
    alignItems: "center",
    gap: 12,
    marginBottom: 20,
  },
  icon: {
    width: 42,
    height: 42,
    display: "grid",
    placeItems: "center",
    borderRadius: 10,
    background: "rgba(6,182,212,.12)",
    color: "#22D3EE",
  },
  title: {
    margin: 0,
    color: "#E2E8F0",
    fontSize: 18,
  },
  subtitle: {
    color: "#94A3B8",
    fontSize: 13,
    margin: "5px 0 0",
  },
  row: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: 16,
    padding: "15px 0",
    borderTop: "1px solid #263449",
    flexWrap: "wrap",
  },
  description: {
    color: "#94A3B8",
    display: "block",
    fontSize: 12,
    marginTop: 5,
  },
  button: {
    display: "inline-flex",
    alignItems: "center",
    gap: 8,
    padding: "10px 15px",
    border: "1px solid #334155",
    borderRadius: 9,
    background: "#1E293B",
    color: "#E2E8F0",
    cursor: "pointer",
    fontWeight: 700,
  },
};

function SettingToggle({ checked, onChange }) {
  return (
    <input
      type="checkbox"
      checked={checked}
      onChange={(event) => onChange(event.target.checked)}
      style={{
        width: 19,
        height: 19,
        accentColor: "#06B6D4",
        cursor: "pointer",
      }}
    />
  );
}

function SettingRow({ title, description, checked, onChange }) {
  return (
    <div style={sections.row}>
      <div>
        <strong style={{ color: "#E2E8F0", fontSize: 14 }}>
          {title}
        </strong>
        <span style={sections.description}>{description}</span>
      </div>
      <SettingToggle checked={checked} onChange={onChange} />
    </div>
  );
}

function SettingsCard({ icon, title, subtitle, children }) {
  return (
    <section style={sections.card}>
      <div style={sections.heading}>
        <div style={sections.icon}>{icon}</div>
        <div>
          <h2 style={sections.title}>{title}</h2>
          <p style={sections.subtitle}>{subtitle}</p>
        </div>
      </div>
      {children}
    </section>
  );
}

export default function Settings() {
  const [preferences, setPreferences] = useState(DEFAULTS);
  const [saved, setSaved] = useState(true);

  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        setPreferences({ ...DEFAULTS, ...parsed });
      }
    } catch (error) {
      console.error("Unable to load saved settings:", error);
    }
  }, []);

  function updateSetting(key, value) {
    setPreferences((previous) => ({
      ...previous,
      [key]: value,
    }));
    setSaved(false);
  }

  function saveSettings() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(preferences));
      setSaved(true);
    } catch (error) {
      console.error("Unable to save settings:", error);
      window.alert("Settings could not be saved in this browser.");
    }
  }

  function resetSettings() {
    setPreferences({ ...DEFAULTS });
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(DEFAULTS));
      setSaved(true);
    } catch (error) {
      setSaved(false);
    }
  }

  return (
    <PageLayout
      title="Settings"
      subtitle="Configure SentinelAI security preferences and detection behaviour"
    >
      <div style={{ width: "100%", maxWidth: 1250, margin: "0 auto" }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            gap: 12,
            flexWrap: "wrap",
            marginBottom: 20,
            padding: 16,
            background: "#111827",
            border: "1px solid #263449",
            borderRadius: 12,
          }}
        >
          <div>
            <strong style={{ color: "#E2E8F0" }}>
              Security Configuration
            </strong>
            <p style={{ ...sections.subtitle, marginBottom: 0 }}>
              Preferences are stored in this browser.
            </p>
          </div>

          <div style={{ display: "flex", gap: 9, flexWrap: "wrap" }}>
            <button style={sections.button} onClick={resetSettings}>
              <RotateCcw size={16} />
              Reset defaults
            </button>
            <button
              style={{
                ...sections.button,
                background: "#0891B2",
                borderColor: "#0891B2",
                color: "#FFFFFF",
              }}
              onClick={saveSettings}
            >
              <Save size={16} />
              Save settings
            </button>
          </div>
        </div>

        <div
          style={{
            padding: "10px 14px",
            marginBottom: 18,
            borderRadius: 9,
            background: saved
              ? "rgba(34,197,94,.08)"
              : "rgba(245,158,11,.08)",
            border: `1px solid ${saved ? "#166534" : "#92400E"}`,
            color: saved ? "#86EFAC" : "#FCD34D",
            display: "flex",
            alignItems: "center",
            gap: 9,
            fontSize: 13,
          }}
        >
          <CheckCircle size={17} />
          {saved
            ? "All preferences saved"
            : "You have unsaved changes"}
        </div>

        <SettingsCard
          icon={<Brain size={21} />}
          title="AI Detection Engine"
          subtitle="Configure threat detection behaviour"
        >
          <div style={sections.row}>
            <div>
              <strong style={{ color: "#E2E8F0" }}>
                Random Forest
              </strong>
              <span style={sections.description}>
                Existing supervised threat classifier
              </span>
            </div>
            <span style={{ color: "#4ADE80", fontWeight: 800 }}>
              ACTIVE
            </span>
          </div>

          <div style={sections.row}>
            <div>
              <strong style={{ color: "#E2E8F0" }}>
                Isolation Forest
              </strong>
              <span style={sections.description}>
                Existing anomaly detection model
              </span>
            </div>
            <span style={{ color: "#4ADE80", fontWeight: 800 }}>
              ACTIVE
            </span>
          </div>

          <SettingRow
            title="Anomaly Detection"
            description="Enable anomaly detection preference"
            checked={preferences.anomalyDetection}
            onChange={(v) => updateSetting("anomalyDetection", v)}
          />

          <SettingRow
            title="Automatic Risk Scoring"
            description="Enable automatic risk scoring preference"
            checked={preferences.automaticRiskScoring}
            onChange={(v) => updateSetting("automaticRiskScoring", v)}
          />

          <div style={sections.row}>
            <div>
              <strong style={{ color: "#E2E8F0" }}>
                Detection Sensitivity
              </strong>
              <span style={sections.description}>
                Preferred sensitivity for future policy integration
              </span>
            </div>
            <select
              value={preferences.detectionSensitivity}
              onChange={(e) =>
                updateSetting("detectionSensitivity", e.target.value)
              }
              style={{
                padding: 10,
                background: "#1E293B",
                color: "#E2E8F0",
                border: "1px solid #334155",
                borderRadius: 8,
              }}
            >
              <option value="low">Low</option>
              <option value="balanced">Balanced</option>
              <option value="high">High</option>
            </select>
          </div>
        </SettingsCard>

        <SettingsCard
          icon={<SlidersHorizontal size={21} />}
          title="Risk Threshold Configuration"
          subtitle="Configure preferred alert severity thresholds"
        >
          <div style={{ padding: "12px 0" }}>
            <div style={sections.row}>
              <div>
                <strong style={{ color: "#E2E8F0" }}>
                  High Risk Threshold
                </strong>
                <span style={sections.description}>
                  Preferred threshold for high-risk alerts
                </span>
              </div>
              <strong style={{ color: "#FBBF24" }}>
                {preferences.highRiskThreshold}/100
              </strong>
            </div>
            <input
              type="range"
              min="30"
              max="90"
              step="5"
              value={preferences.highRiskThreshold}
              onChange={(e) =>
                updateSetting("highRiskThreshold", Number(e.target.value))
              }
              style={{ width: "100%", accentColor: "#F59E0B" }}
            />
          </div>

          <div style={{ padding: "12px 0" }}>
            <div style={sections.row}>
              <div>
                <strong style={{ color: "#E2E8F0" }}>
                  Critical Risk Threshold
                </strong>
                <span style={sections.description}>
                  Preferred threshold for critical-risk alerts
                </span>
              </div>
              <strong style={{ color: "#F87171" }}>
                {preferences.criticalRiskThreshold}/100
              </strong>
            </div>
            <input
              type="range"
              min="60"
              max="100"
              step="5"
              value={preferences.criticalRiskThreshold}
              onChange={(e) =>
                updateSetting("criticalRiskThreshold", Number(e.target.value))
              }
              style={{ width: "100%", accentColor: "#EF4444" }}
            />
          </div>

          {preferences.criticalRiskThreshold <=
            preferences.highRiskThreshold && (
            <p style={{ color: "#FCA5A5", fontSize: 12 }}>
              Critical threshold should be higher than the high-risk threshold.
            </p>
          )}
        </SettingsCard>

        <SettingsCard
          icon={<ShieldCheck size={21} />}
          title="Zero Trust Security"
          subtitle="Identity, device and access protection preferences"
        >
          <SettingRow
            title="Continuous Verification"
            description="Preference for reassessing active sessions"
            checked={preferences.continuousVerification}
            onChange={(v) => updateSetting("continuousVerification", v)}
          />

          <SettingRow
            title="MFA for Medium Risk"
            description="Preference for additional verification"
            checked={preferences.mfaMediumRisk}
            onChange={(v) => updateSetting("mfaMediumRisk", v)}
          />
        </SettingsCard>

        <SettingsCard
          icon={<Bell size={21} />}
          title="Notifications"
          subtitle="Security alert and assistant preferences"
        >
          <SettingRow
            title="High Risk Alerts"
            description="Show preference for high-risk notifications"
            checked={preferences.highRiskAlerts}
            onChange={(v) => updateSetting("highRiskAlerts", v)}
          />

          <SettingRow
            title="Critical Risk Alerts"
            description="Show preference for critical-risk notifications"
            checked={preferences.criticalRiskAlerts}
            onChange={(v) => updateSetting("criticalRiskAlerts", v)}
          />

          <SettingRow
            title="AI Assistant Suggestions"
            description="Enable security recommendation preference"
            checked={preferences.assistantSuggestions}
            onChange={(v) => updateSetting("assistantSuggestions", v)}
          />
        </SettingsCard>

        <SettingsCard
          icon={<Database size={21} />}
          title="System Information"
          subtitle="SentinelAI infrastructure"
        >
          {[
            ["Frontend", "React + Vite"],
            ["Backend", "FastAPI"],
            ["Database", "SQLite"],
            ["Machine Learning", "scikit-learn"],
            ["Detection Models", "Random Forest + Isolation Forest"],
            ["Configuration Storage", "Browser local storage"],
          ].map(([name, value]) => (
            <div key={name} style={sections.row}>
              <span style={{ color: "#94A3B8", fontSize: 13 }}>
                {name}
              </span>
              <strong style={{ color: "#E2E8F0", fontSize: 13 }}>
                {value}
              </strong>
            </div>
          ))}
        </SettingsCard>

        <p
          style={{
            color: "#64748B",
            fontSize: 12,
            lineHeight: 1.6,
            marginTop: 15,
          }}
        >
          Note: These settings currently manage browser-side preferences.
          They do not independently change backend detection thresholds,
          firewall enforcement, authentication rules or live security policies.
        </p>
      </div>
    </PageLayout>
  );
}
