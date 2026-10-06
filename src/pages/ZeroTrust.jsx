import { useState } from "react";
import {
  ShieldCheck,
  UserCheck,
  Smartphone,
  MapPin,
  RefreshCw,
  Lock,
  CheckCircle,
  AlertTriangle,
  XCircle,
} from "lucide-react";

import PageLayout from "../components/PageLayout";

const API = "https://sentinelai-wnno.onrender.com";

function ZeroTrust() {

  const [form, setForm] = useState({
    user: "admin",
    device: "Laptop-01",
    resource: "Production Server",
    location: "Bangalore",
    risk_score: 20,
    identity_verified: true,
    device_trusted: true,
  });

  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const updateField = (field, value) => {
    setForm((current) => ({
      ...current,
      [field]: value,
    }));
  };

  const checkAccess = async () => {

    setLoading(true);
    setResult(null);

    try {

      const response = await fetch(
        `${API}/api/zero-trust/check`,
        {
          method: "POST",

          headers: {
            "Content-Type": "application/json",
          },

          body: JSON.stringify(form),
        }
      );

      if (!response.ok) {
        throw new Error("Zero Trust request failed");
      }

      const data = await response.json();

      setResult(data);

    } catch (error) {

      console.error(error);

      setResult({
        decision: "ERROR",
        reason: "Unable to connect to SecureX AI backend.",
      });

    } finally {

      setLoading(false);

    }
  };

  const decisionClass =
    result?.decision?.toLowerCase() || "";

  return (
    <PageLayout
      title="Zero Trust"
      subtitle="Continuous identity, device and access verification"
    >

      {/* ACTIVE STATUS */}

      <div className="zt-status-banner">

        <div className="zt-status-icon">
          <ShieldCheck size={25} />
        </div>

        <div>
          <h2>Zero Trust Security Active</h2>
          <p>
            Every request is continuously evaluated based on
            identity, device, context and risk.
          </p>
        </div>

        <span className="zt-active">
          ACTIVE
        </span>

      </div>


      {/* SECURITY PRINCIPLES */}

      <div className="zt-principles">

        <div className="zt-principle">

          <div className="zt-principle-icon blue">
            <UserCheck size={22} />
          </div>

          <h3>Identity Verification</h3>

          <p>
            User identity is verified before sensitive
            resources are accessed.
          </p>

          <span className="zt-good">
            ● Verified
          </span>

        </div>


        <div className="zt-principle">

          <div className="zt-principle-icon green">
            <Smartphone size={22} />
          </div>

          <h3>Device Trust</h3>

          <p>
            Device posture and trust scores are evaluated
            continuously.
          </p>

          <span className="zt-good">
            ● Monitoring
          </span>

        </div>


        <div className="zt-principle">

          <div className="zt-principle-icon purple">
            <MapPin size={22} />
          </div>

          <h3>Context Analysis</h3>

          <p>
            Location, behavior and connection context
            influence access decisions.
          </p>

          <span className="zt-good">
            ● Analyzing
          </span>

        </div>


        <div className="zt-principle">

          <div className="zt-principle-icon orange">
            <RefreshCw size={22} />
          </div>

          <h3>Continuous Verification</h3>

          <p>
            Sessions are re-evaluated when risk or
            behavior changes.
          </p>

          <span className="zt-good">
            ● Enabled
          </span>

        </div>

      </div>


      {/* ACCESS DECISION */}

      <section className="zt-engine">

        <div className="zt-engine-header">

          <div>
            <h2>Access Decision Engine</h2>
            <p>
              Live Zero Trust policy evaluation
            </p>
          </div>

          <Lock size={20} />

        </div>


        <div className="zt-form">

          <div className="zt-field">

            <label>User</label>

            <input
              value={form.user}
              onChange={(e) =>
                updateField("user", e.target.value)
              }
            />

          </div>


          <div className="zt-field">

            <label>Device</label>

            <select
              value={form.device}
              onChange={(e) =>
                updateField("device", e.target.value)
              }
            >

              <option>Laptop-01</option>
              <option>Workstation-01</option>
              <option>Server-01</option>
              <option>Gateway-01</option>

            </select>

          </div>


          <div className="zt-field">

            <label>Resource</label>

            <select
              value={form.resource}
              onChange={(e) =>
                updateField("resource", e.target.value)
              }
            >

              <option>Production Server</option>
              <option>Internal Application</option>
              <option>Database</option>
              <option>Admin Panel</option>

            </select>

          </div>


          <div className="zt-field">

            <label>Location</label>

            <select
              value={form.location}
              onChange={(e) =>
                updateField("location", e.target.value)
              }
            >

              <option>Bangalore</option>
              <option>Chennai</option>
              <option>Hyderabad</option>
              <option>Unknown</option>
              <option>Foreign</option>

            </select>

          </div>


          <div className="zt-field">

            <label>
              Risk Score: {form.risk_score}
            </label>

            <input
              type="range"
              min="0"
              max="100"
              value={form.risk_score}
              onChange={(e) =>
                updateField(
                  "risk_score",
                  Number(e.target.value)
                )
              }
            />

          </div>

        </div>


        <div className="zt-toggles">

          <label>

            <input
              type="checkbox"
              checked={form.identity_verified}
              onChange={(e) =>
                updateField(
                  "identity_verified",
                  e.target.checked
                )
              }
            />

            Identity Verified

          </label>


          <label>

            <input
              type="checkbox"
              checked={form.device_trusted}
              onChange={(e) =>
                updateField(
                  "device_trusted",
                  e.target.checked
                )
              }
            />

            Device Trusted

          </label>

        </div>


        <button
          className="zt-check-button"
          onClick={checkAccess}
          disabled={loading}
        >

          <ShieldCheck size={17} />

          {loading
            ? "Evaluating..."
            : "Evaluate Access"}

        </button>


        {/* RESULT */}

        {result && (

          <div
            className={`zt-result ${decisionClass}`}
          >

            <div className="zt-result-icon">

              {result.decision === "ALLOW" && (
                <CheckCircle size={30} />
              )}

              {result.decision === "MFA" && (
                <AlertTriangle size={30} />
              )}

              {result.decision === "BLOCK" && (
                <XCircle size={30} />
              )}

            </div>


            <div className="zt-result-content">

              <span>ZERO TRUST DECISION</span>

              <strong>
                {result.decision}
              </strong>

              {result.risk_score !== undefined && (
                <p>
                  Risk Score:{" "}
                  <b>{result.risk_score}</b>
                </p>
              )}

              <p>
                {result.reason}
              </p>

            </div>

          </div>

        )}

      </section>


      {/* DECISION FLOW */}

      <section className="zt-flow">

        <div className="zt-flow-item">
          <span>IDENTITY</span>
          <strong>Verified</strong>
        </div>

        <div className="zt-arrow">→</div>

        <div className="zt-flow-item">
          <span>DEVICE</span>
          <strong>Trusted</strong>
        </div>

        <div className="zt-arrow">→</div>

        <div className="zt-flow-item">
          <span>RISK</span>
          <strong>Analyzed</strong>
        </div>

        <div className="zt-arrow">→</div>

        <div className="zt-flow-item decision">
          <span>DECISION</span>
          <strong>ALLOW / MFA / BLOCK</strong>
        </div>

      </section>

    </PageLayout>
  );
}

export default ZeroTrust;
