export function detectBlockSpike(logs = [], isBlockedEvent) {
  const validBlockEvents = logs
    .filter(item => isBlockedEvent(item))
    .map(item => new Date(item.created_at))
    .filter(timestamp => !Number.isNaN(timestamp.getTime()));

  const validAllEvents = logs
    .map(item => new Date(item.created_at))
    .filter(timestamp => !Number.isNaN(timestamp.getTime()));

  const latestTimestamp = validAllEvents.length
    ? new Date(Math.max(...validAllEvents.map(time => time.getTime())))
    : null;

  const latestHour = latestTimestamp
    ? new Date(latestTimestamp)
    : null;

  if (latestHour) latestHour.setMinutes(0, 0, 0);

  const hourlyBlocks = latestHour
    ? Array.from({ length: 6 }, (_, index) => {
        const start = new Date(
          latestHour.getTime() - (5 - index) * 60 * 60 * 1000
        );

        const end = new Date(start.getTime() + 60 * 60 * 1000);

        return validBlockEvents.filter(
          timestamp => timestamp >= start && timestamp < end
        ).length;
      })
    : [];

  const coverageStart = latestHour
    ? new Date(latestHour.getTime() - 5 * 60 * 60 * 1000)
    : null;

  const oldestEvent = validAllEvents.length
    ? new Date(Math.min(...validAllEvents.map(time => time.getTime())))
    : null;

  const enoughData = Boolean(
    latestHour &&
    hourlyBlocks.length === 6 &&
    oldestEvent &&
    oldestEvent <= coverageStart
  );

  const latestBlocks = enoughData ? hourlyBlocks[5] : 0;

  const baseline = enoughData
    ? hourlyBlocks.slice(0, 5).reduce((sum, value) => sum + value, 0) / 5
    : 0;

  const spikeDetected = enoughData &&
    latestBlocks >= 3 &&
    latestBlocks >= baseline * 2;

  const criticalSpike = spikeDetected &&
    latestBlocks >= 6 &&
    (baseline === 0 || latestBlocks >= baseline * 3);

  const status = !enoughData
    ? "INSUFFICIENT DATA"
    : criticalSpike
      ? "CRITICAL SPIKE"
      : spikeDetected
        ? "HIGH SPIKE"
        : "NO SPIKE DETECTED";

  return {
    status,
    enoughData,
    latestBlocks,
    baseline,
    threshold: Math.max(3, baseline * 2),
    hourlyBlocks,
    spikeDetected,
    criticalSpike
  };
}
