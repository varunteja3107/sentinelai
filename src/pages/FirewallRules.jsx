import { useEffect, useState } from "react";
import {
  Shield,
  ShieldCheck,
  ShieldX,
  RefreshCw,
  Power,
  Plus,
} from "lucide-react";

import PageLayout from "../components/PageLayout";

const API = "https://sentinelai-wnno.onrender.com";

function FirewallRules() {

  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");

  const loadRules = async () => {

    try {

      setLoading(true);

      const response = await fetch(
        `${API}/api/firewall/rules`
      );

      if (!response.ok) {
        throw new Error("Failed to load rules");
      }

      const data = await response.json();

      setRules(data);

    } catch (error) {

      console.error(error);

      setMessage(
        "Unable to connect to SentinelAI backend."
      );

    } finally {

      setLoading(false);

    }
  };


  useEffect(() => {

    loadRules();

  }, []);


  const toggleRule = async (id) => {

    try {

      const response = await fetch(
        `${API}/api/firewall/rules/${id}/toggle`,
        {
          method: "POST",
        }
      );

      const updatedRule = await response.json();

      setRules((current) =>
        current.map((rule) =>
          rule.id === id
            ? updatedRule
            : rule
        )
      );

      setMessage(
        `${updatedRule.name} is now ${updatedRule.status}.`
      );

      setTimeout(() => {
        setMessage("");
      }, 2500);

    } catch (error) {

      console.error(error);

      setMessage("Unable to update firewall rule.");

    }
  };


  const activeRules = rules.filter(
    (rule) => rule.status === "ACTIVE"
  ).length;


  const blockedRules = rules.filter(
    (rule) => rule.action === "BLOCK"
  ).length;


  const allowedRules = rules.filter(
    (rule) => rule.action === "ALLOW"
  ).length;


  return (
    <PageLayout
      title="Firewall Rules"
      subtitle="Adaptive policy enforcement and traffic control"
    >

      {/* HEADER */}

      <div className="fw-header">

        <div>

          <h2>
            <Shield size={20} />
            Firewall Policy Engine
          </h2>

          <p>
            Rules generated from AI risk analysis and
            Zero Trust decisions.
          </p>

        </div>

        <button
          className="fw-refresh"
          onClick={loadRules}
        >
          <RefreshCw size={15} />
          Refresh
        </button>

      </div>


      {/* STATUS */}

      {message && (

        <div className="fw-message">
          <ShieldCheck size={17} />
          {message}
        </div>

      )}


      {/* STATS */}

      <div className="fw-stats">

        <div className="fw-stat">

          <div className="fw-stat-icon blue">
            <Shield size={20} />
          </div>

          <div>
            <strong>{rules.length}</strong>
            <span>Total Rules</span>
          </div>

        </div>


        <div className="fw-stat">

          <div className="fw-stat-icon green">
            <Power size={20} />
          </div>

          <div>
            <strong>{activeRules}</strong>
            <span>Active Rules</span>
          </div>

        </div>


        <div className="fw-stat">

          <div className="fw-stat-icon red">
            <ShieldX size={20} />
          </div>

          <div>
            <strong>{blockedRules}</strong>
            <span>Blocking Rules</span>
          </div>

        </div>


        <div className="fw-stat">

          <div className="fw-stat-icon purple">
            <ShieldCheck size={20} />
          </div>

          <div>
            <strong>{allowedRules}</strong>
            <span>Allow Rules</span>
          </div>

        </div>

      </div>


      {/* RULES */}

      <section className="fw-panel">

        <div className="fw-panel-header">

          <div>
            <h2>Active Firewall Policies</h2>

            <p>
              Network traffic is evaluated against these
              policies before access is permitted.
            </p>
          </div>

          <button className="fw-add">
            <Plus size={15} />
            Add Rule
          </button>

        </div>


        {loading ? (

          <div className="fw-loading">
            Loading firewall rules...
          </div>

        ) : (

          <div className="fw-table">

            <div className="fw-row fw-table-head">

              <span>RULE</span>
              <span>SOURCE</span>
              <span>DESTINATION</span>
              <span>PORT</span>
              <span>PROTOCOL</span>
              <span>ACTION</span>
              <span>STATUS</span>
              <span></span>

            </div>


            {rules.map((rule) => (

              <div
                className="fw-row"
                key={rule.id}
              >

                <div className="fw-rule-name">

                  {rule.action === "BLOCK" ? (
                    <ShieldX size={17} />
                  ) : (
                    <ShieldCheck size={17} />
                  )}

                  <strong>
                    {rule.name}
                  </strong>

                </div>


                <span>
                  {rule.source}
                </span>


                <span>
                  {rule.destination}
                </span>


                <span className="fw-port">
                  {rule.port}
                </span>


                <span>
                  {rule.protocol}
                </span>


                <span>

                  <b
                    className={
                      rule.action === "BLOCK"
                        ? "fw-block"
                        : "fw-allow"
                    }
                  >
                    {rule.action}
                  </b>

                </span>


                <span>

                  <b
                    className={
                      rule.status === "ACTIVE"
                        ? "fw-active"
                        : "fw-disabled"
                    }
                  >
                    {rule.status}
                  </b>

                </span>


                <button
                  className="fw-toggle"
                  onClick={() =>
                    toggleRule(rule.id)
                  }
                >
                  <Power size={14} />

                  {rule.status === "ACTIVE"
                    ? "Disable"
                    : "Enable"}
                </button>

              </div>

            ))}

          </div>

        )}

      </section>


      {/* POLICY FLOW */}

      <section className="fw-flow">

        <div className="fw-flow-title">

          <Shield size={19} />

          <div>
            <h3>Adaptive Firewall Response</h3>

            <p>
              AI threat detection automatically influences
              firewall enforcement.
            </p>
          </div>

        </div>


        <div className="fw-flow-items">

          <div>
            <span>01</span>
            <strong>Traffic</strong>
            <small>Network event detected</small>
          </div>

          <div className="fw-arrow">
            →
          </div>

          <div>
            <span>02</span>
            <strong>AI Analysis</strong>
            <small>Anomaly and risk calculated</small>
          </div>

          <div className="fw-arrow">
            →
          </div>

          <div>
            <span>03</span>
            <strong>Zero Trust</strong>
            <small>Access policy evaluated</small>
          </div>

          <div className="fw-arrow">
            →
          </div>

          <div className="fw-final">
            <span>04</span>
            <strong>Firewall</strong>
            <small>ALLOW / BLOCK / MFA</small>
          </div>

        </div>

      </section>

    </PageLayout>
  );
}

export default FirewallRules;
