function RecentThreats({ threats = [] }) {
  return (
    <section className="recent-threats">

      <div className="section-header">

        <div>
          <h2>Recent Threats</h2>

          <p>
            Latest AI-detected network activity
          </p>
        </div>

        <span className="threat-count">
          {threats.length} events
        </span>

      </div>

      {threats.length === 0 ? (

        <div className="empty-state">
          No threats detected
        </div>

      ) : (

        <div className="threat-table">

          <div className="threat-table-header">
            <span>Threat</span>
            <span>Source</span>
            <span>Risk</span>
            <span>Severity</span>
            <span>Action</span>
          </div>

          {threats.slice(0, 8).map((threat) => (

            <div
              className="threat-row"
              key={threat.id}
            >

              <span>
                <strong>
                  {threat.threat_type}
                </strong>

                <small>
                  Port {threat.port}
                </small>
              </span>

              <span>
                {threat.source_ip}
              </span>

              <span>
                {threat.risk_score}
              </span>

              <span>
                <span
                  className={`severity-badge ${threat.severity.toLowerCase()}`}
                >
                  {threat.severity}
                </span>
              </span>

              <span>
                <span
                  className={`action-badge ${threat.action.toLowerCase()}`}
                >
                  {threat.action}
                </span>
              </span>

            </div>

          ))}

        </div>

      )}

    </section>
  );
}

export default RecentThreats;
