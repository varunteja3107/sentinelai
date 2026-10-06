import { useEffect, useState } from "react";
import {
  Bot,
  Send,
  ShieldAlert,
  Activity,
  BrainCircuit,
  Lock,
  Sparkles,
} from "lucide-react";
import PageLayout from "../components/PageLayout";
import "./Assistant.css";

const API = "https://sentinelai-wnno.onrender.com";

const quickQuestions = [
  "Why was the latest threat blocked?",
  "What is the current risk score?",
  "What threat was detected?",
  "What do you recommend?",
];

function Assistant() {
  const [question, setQuestion] = useState("");
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(false);
  const [latestThreat, setLatestThreat] = useState(null);

  useEffect(() => {
    loadLatestThreat();
  }, []);

  async function loadLatestThreat() {
    try {
      const response = await fetch(`${API}/api/threats`);
      const data = await response.json();

      if (Array.isArray(data) && data.length > 0) {
        setLatestThreat(data[data.length - 1]);
      }
    } catch (error) {
      console.error("Threat loading failed:", error);
    }
  }

  async function askAssistant(text = question) {
    const trimmed = text.trim();

    if (!trimmed || loading) return;

    setQuestion("");
    setMessages((prev) => [
      ...prev,
      { role: "user", text: trimmed },
    ]);

    setLoading(true);

    try {
      const response = await fetch(
        `${API}/api/assistant?question=${encodeURIComponent(trimmed)}`,
        {
          method: "POST",
        }
      );

      const data = await response.json();

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          text: data.answer || "I could not generate an answer.",
        },
      ]);

      if (data.threat) {
        setLatestThreat(data.threat);
      }
    } catch (error) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          text: "Unable to connect to the SecureX AI security engine. Make sure the FastAPI backend is running on port 8000.",
        },
      ]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <PageLayout>
      <div className="assistant-page">

        <div className="assistant-header">
          <div>
            <div className="assistant-title-row">
              <div className="assistant-icon">
                <Bot size={27} />
              </div>

              <div>
                <h1>AI Security Assistant</h1>
                <p>
                  Ask SecureX AI about threats, risk and security decisions
                </p>
              </div>
            </div>
          </div>

          <div className="assistant-online">
            <span className="online-dot"></span>
            AI ENGINE ONLINE
          </div>
        </div>

        <div className="assistant-grid">

          <section className="assistant-chat-card">

            <div className="card-heading">
              <div className="heading-icon">
                <BrainCircuit size={20} />
              </div>

              <div>
                <h2>SecureX AI Assistant</h2>
                <span>Security intelligence engine</span>
              </div>
            </div>

            <div className="chat-window">

              {messages.length === 0 ? (
                <div className="welcome-message">
                  <div className="welcome-icon">
                    <Sparkles size={24} />
                  </div>

                  <h3>Hello, I'm SecureX AI Security Assistant.</h3>

                  <p>
                    Ask me about threats, risk scores, blocked connections,
                    or recommended responses.
                  </p>
                </div>
              ) : (
                messages.map((message, index) => (
                  <div
                    key={index}
                    className={`chat-message ${message.role}`}
                  >
                    <div className="message-avatar">
                      {message.role === "assistant" ? (
                        <Bot size={16} />
                      ) : (
                        <Activity size={16} />
                      )}
                    </div>

                    <div className="message-bubble">
                      {message.text}
                    </div>
                  </div>
                ))
              )}

              {loading && (
                <div className="chat-message assistant">
                  <div className="message-avatar">
                    <Bot size={16} />
                  </div>

                  <div className="message-bubble typing">
                    Analyzing security events...
                    <span>•••</span>
                  </div>
                </div>
              )}

            </div>

            <div className="quick-section">
              <span className="quick-label">QUICK QUESTIONS</span>

              <div className="quick-buttons">
                {quickQuestions.map((item) => (
                  <button
                    key={item}
                    onClick={() => askAssistant(item)}
                    disabled={loading}
                  >
                    {item}
                  </button>
                ))}
              </div>
            </div>

            <form
              className="assistant-input"
              onSubmit={(e) => {
                e.preventDefault();
                askAssistant();
              }}
            >
              <input
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                placeholder="Ask about your security events..."
              />

              <button type="submit" disabled={loading || !question.trim()}>
                <Send size={18} />
              </button>
            </form>

          </section>

          <aside className="threat-context-card">

            <div className="context-header">
              <div>
                <span className="context-label">LIVE</span>
                <h2>Latest Threat Context</h2>
              </div>

              <div className="context-shield">
                <ShieldAlert size={23} />
              </div>
            </div>

            {latestThreat ? (
              <div className="threat-details">

                <div className="threat-type">
                  <ShieldAlert size={18} />
                  <strong>{latestThreat.threat_type}</strong>
                </div>

                <div className="detail-row">
                  <span>Source IP</span>
                  <strong>{latestThreat.source_ip}</strong>
                </div>

                <div className="detail-row">
                  <span>Destination</span>
                  <strong>{latestThreat.destination_ip}</strong>
                </div>

                <div className="detail-row">
                  <span>Port</span>
                  <strong>{latestThreat.port}</strong>
                </div>

                <div className="detail-row">
                  <span>Protocol</span>
                  <strong>{latestThreat.protocol}</strong>
                </div>

                <div className="risk-box">
                  <div>
                    <span>RISK SCORE</span>
                    <strong>{latestThreat.risk_score}</strong>
                  </div>

                  <div className="risk-bar">
                    <div
                      style={{
                        width: `${Math.min(
                          latestThreat.risk_score || 0,
                          100
                        )}%`,
                      }}
                    />
                  </div>
                </div>

                <div className="context-status">
                  <div>
                    <span>Severity</span>
                    <strong className="high">
                      {latestThreat.severity}
                    </strong>
                  </div>

                  <div>
                    <span>Action</span>
                    <strong className="blocked">
                      <Lock size={14} />
                      {latestThreat.action}
                    </strong>
                  </div>
                </div>

              </div>
            ) : (
              <div className="empty-context">
                <Activity size={30} />
                <p>
                  Ask the assistant a question to load the latest threat
                  context.
                </p>
              </div>
            )}

          </aside>

        </div>
      </div>
    </PageLayout>
  );
}

export default Assistant;
