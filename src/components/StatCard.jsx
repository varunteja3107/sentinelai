function StatCard({
  title,
  value,
  icon,
}) {
  return (
    <div className="stat-card">

      <div className="stat-card-top">

        <div className="stat-icon">
          {icon}
        </div>

      </div>

      <div className="stat-title">
        {title}
      </div>

      <div className="stat-value">
        {value}
      </div>

    </div>
  );
}

export default StatCard;
