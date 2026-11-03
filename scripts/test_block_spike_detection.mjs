import { detectBlockSpike } from "../src/utils/blockSpikeDetector.js";

function makeLogs(hourlyCounts, latestHour = "2026-10-31T12:00:00") {
  const logs = [];

  hourlyCounts.forEach((count, index) => {
    const hour = new Date(
      new Date(latestHour).getTime() -
      (hourlyCounts.length - 1 - index) * 60 * 60 * 1000
    );

    for (let i = 0; i < count; i++) {
      logs.push({
        action: "BLOCK",
        created_at: new Date(hour.getTime() + i * 60 * 1000).toISOString()
      });
    }

    if (count === 0) {
      logs.push({
        action: "ALLOW",
        created_at: hour.toISOString()
      });
    }
  });

  return logs;
}

const isBlockedEvent = item =>
  item.action?.toUpperCase() === "BLOCK";

const tests = [
  {
    name: "Normal activity",
    logs: makeLogs([2, 2, 2, 2, 2, 1]),
    expected: "NO SPIKE DETECTED"
  },
  {
    name: "Elevated BLOCK activity",
    logs: makeLogs([2, 2, 2, 2, 2, 4]),
    expected: "HIGH SPIKE"
  },
  {
    name: "Critical activity with zero baseline",
    logs: makeLogs([0, 0, 0, 0, 0, 6]),
    expected: "CRITICAL SPIKE"
  },
  {
    name: "Incomplete historical coverage",
    logs: makeLogs([0, 0, 0, 0, 0, 4]).filter(
      item => new Date(item.created_at) >=
        new Date("2026-10-31T09:00:00")
    ),
    expected: "INSUFFICIENT DATA"
  }
];

let passed = 0;

console.log("\nSENTINELAI SHARED BLOCK SPIKE ENGINE TESTS\n");

for (const test of tests) {
  const result = detectBlockSpike(test.logs, isBlockedEvent);
  const success = result.status === test.expected;

  if (success) passed++;

  console.log(`${success ? "PASS" : "FAIL"}: ${test.name}`);
  console.log(`  Expected: ${test.expected}`);
  console.log(`  Actual:   ${result.status}`);
  console.log(`  Latest BLOCKs: ${result.latestBlocks}`);
  console.log(`  Baseline: ${result.baseline.toFixed(2)}\n`);
}

console.log(`RESULT: ${passed}/${tests.length} tests passed.`);
process.exitCode = passed === tests.length ? 0 : 1;
