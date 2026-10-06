function ThreatLevel({
  score = 100,
}) {

  let level = "LOW";
  let levelClass = "low";

  if (score < 30) {
    level = "CRITICAL";
    levelClass = "critical";
  } else if (score < 60) {
    level = "HIGH";
    levelClass = "high";
  } else if (score < 80) {
    level = "MEDIUM";
    levelClass = "medium";
  }

  return (
    <section className="threat-card">

      <div className="threat-card-header">

        <div>
          <h2>Threat Level</h2>

          <p>
            Current network risk
          </p>
        </div>

      </div>

      <div className="risk-display">

        <div className={`risk-circle ${levelClass}`}>

          <div className="risk-score">
            {score}
          </div>

          <div className="risk-label">
            SECURITY
          </div>

        </div>

      </div>

      <div className={`risk-status ${levelClass}`}>
        {level} RISK
      </div>

      <div className="risk-details">

        <div>
          <span>System Risk</span>
          <strong>
            {Math.max(0, 100 - score)}%
          </strong>
        </div>

        <div>
          <span>AI Confidence</span>
          <strong>94%</strong>
        </div>

      </div>

    </section>
  );
}

export default ThreatLevel;
