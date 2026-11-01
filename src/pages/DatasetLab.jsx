import { useState } from "react";
import {
  Upload,
  FileSpreadsheet,
  AlertCircle,
  RefreshCw,
  Brain,
  Download,
} from "lucide-react";
import PageLayout from "../components/PageLayout";
import { API_BASE as API } from "../api";

const panel = {
  background: "#0F172A",
  border: "1px solid #263449",
  borderRadius: 14,
  padding: 20,
  minWidth: 0,
  color: "#E2E8F0",
};

const muted = { color: "#94A3B8", fontSize: 13 };

const button = {
  display: "inline-flex",
  alignItems: "center",
  gap: 8,
  padding: "11px 16px",
  borderRadius: 9,
  border: 0,
  background: "#06B6D4",
  color: "#06202A",
  fontWeight: 800,
  cursor: "pointer",
};

const secondaryButton = {
  ...button,
  background: "#A7F3D0",
};

const metricNames = [
  ["accuracy", "Accuracy"],
  ["weighted_precision", "Weighted precision"],
  ["weighted_recall", "Weighted recall"],
  ["weighted_f1", "Weighted F1-score"],
  ["macro_false_positive_rate", "Macro false-positive rate"],
];

export default function DatasetLab() {
  const [file, setFile] = useState(null);
  const [data, setData] = useState(null);
  const [evaluation, setEvaluation] = useState(null);
  const [labelColumn, setLabelColumn] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [evaluating, setEvaluating] = useState(false);
  const [intelligence, setIntelligence] = useState(null);
  const [intelligenceLoading, setIntelligenceLoading] = useState(false);

  function chooseFile(event) {
    const chosen = event.target.files?.[0] || null;
    setFile(chosen);
    setData(null);
    setEvaluation(null);
    setIntelligence(null);
    setError("");

    if (chosen && !chosen.name.toLowerCase().endsWith(".csv")) {
      setError("Please select a CSV file.");
    } else if (chosen && chosen.size > 10 * 1024 * 1024 * 1024) {
      setError("The file exceeds the 10 GiB preview limit.");
    }
  }

  async function upload() {
    if (!file) {
      setError("Choose a CSV file first.");
      return;
    }

    setBusy(true);
    setError("");
    setData(null);

    try {
      const body = new FormData();
      body.append("file", file);

      const response = await fetch(`${API}/api/datasets/preview`, {
        method: "POST",
        body,
      });

      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.detail || "Dataset preview failed.");
      }

      setData(result);
      if (result.label_column && !labelColumn) {
        setLabelColumn(result.label_column);
      }
    } catch (e) {
      setError(`${e.message || "Upload failed."} Check that the backend is running.`);
    } finally {
      setBusy(false);
    }
  }

  async function runDatasetIntelligence() {
    if (!file) {
      setError("Choose a CSV dataset first.");
      return;
    }

    if (file.size > 10 * 1024 * 1024 * 1024) {
      setError("Dataset intelligence supports CSV files up to 10 GiB.");
      return;
    }

    setIntelligenceLoading(true);
    setError("");
    setIntelligence(null);

    try {
      const body = new FormData();
      body.append("file", file);

      const response = await fetch(`${API}/api/datasets/intelligence`, {
        method: "POST",
        body,
      });

      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.detail || "Dataset intelligence analysis failed.");
      }

      setIntelligence(result);
    } catch (e) {
      setError(`${e.message || "Analysis failed."} Check that the backend is running.`);
    } finally {
      setIntelligenceLoading(false);
    }
  }

  async function runEvaluation() {
    if (!file) {
      setError("Choose a labelled CSV file first.");
      return;
    }

    if (file.size > 10 * 1024 * 1024 * 1024) {
      setError("Model evaluation supports CSV files up to 10 GiB.");
      return;
    }

    setEvaluating(true);
    setError("");
    setEvaluation(null);

    try {
      const body = new FormData();
      body.append("file", file);

      const query = labelColumn.trim()
        ? `?label_column=${encodeURIComponent(labelColumn.trim())}`
        : "";

      const response = await fetch(
        `${API}/api/datasets/evaluate${query}`,
        { method: "POST", body }
      );

      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.detail || "Model evaluation failed.");
      }

      setEvaluation(result);
    } catch (e) {
      setError(`${e.message || "Evaluation failed."} Check that the backend is running.`);
    } finally {
      setEvaluating(false);
    }
  }

  return (
    <PageLayout
      title="Dataset Lab"
      subtitle="Inspect network datasets and evaluate a classifier on labelled traffic"
    >
      <div style={{ display: "grid", gap: 18, color: "#E2E8F0" }}>
        <section
          style={{
            ...panel,
            background: "linear-gradient(135deg,#0F172A,#102A3A)",
          }}
        >
          <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 18 }}>
            <FileSpreadsheet size={28} color="#22D3EE" />
            <div>
              <h2 style={{ margin: 0, fontSize: 20 }}>Network dataset upload</h2>
              <p style={{ ...muted, margin: "5px 0 0" }}>
                CSV only · Preview up to 10 GiB · Evaluation up to 10 GiB
              </p>
            </div>
          </div>

          <label
            htmlFor="dataset-file"
            style={{
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              gap: 10,
              padding: 30,
              border: "1px dashed #3B6478",
              borderRadius: 12,
              background: "rgba(8,47,73,.25)",
              cursor: "pointer",
              textAlign: "center",
            }}
          >
            <Upload size={30} color="#22D3EE" />
            <strong>{file ? file.name : "Choose a CSV dataset"}</strong>
            <span style={muted}>
              {file
                ? `${(file.size / 1048576).toFixed(2)} MB`
                : "Click to browse files on your Mac"}
            </span>
            <input
              id="dataset-file"
              type="file"
              accept=".csv,text/csv"
              style={{ display: "none" }}
              onChange={chooseFile}
            />
          </label>

          <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginTop: 16 }}>
            <button
              style={button}
              onClick={upload}
              disabled={busy || evaluating || !file || !file.name.toLowerCase().endsWith(".csv") || file.size > 10 * 1024 * 1024 * 1024}
            >
              {busy ? <RefreshCw size={17} /> : <Upload size={17} />}
              {busy ? "Analyzing CSV..." : "Upload & Analyze"}
            </button>

            <button
              style={{ ...button, background: "#C4B5FD", color: "#24134A" }}
              onClick={runDatasetIntelligence}
              disabled={busy || evaluating || intelligenceLoading || !file || !file.name.toLowerCase().endsWith(".csv") || file.size > 10 * 1024 * 1024 * 1024}
            >
              {intelligenceLoading ? <RefreshCw size={17} /> : <Brain size={17} />}
              {intelligenceLoading ? "Profiling dataset..." : "Run Dataset Intelligence"}
            </button>
            <button
              style={secondaryButton}
              onClick={runEvaluation}
              disabled={busy || evaluating || !file || !file.name.toLowerCase().endsWith(".csv") || file.size > 10 * 1024 * 1024 * 1024}
            >
              {evaluating ? <RefreshCw size={17} /> : <Brain size={17} />}
              {evaluating ? "Training and evaluating..." : "Run Model Evaluation"}
            </button>
          </div>

          <div style={{ marginTop: 14 }}>
            <label htmlFor="label-column" style={{ ...muted, display: "block", marginBottom: 6 }}>
              Label column (optional if auto-detected)
            </label>
            <input
              id="label-column"
              value={labelColumn}
              onChange={(event) => setLabelColumn(event.target.value)}
              placeholder="e.g. Label or Attack"
              style={{
                width: "100%",
                maxWidth: 420,
                boxSizing: "border-box",
                background: "#0B1220",
                color: "#E2E8F0",
                border: "1px solid #334155",
                borderRadius: 8,
                padding: 11,
              }}
            />
          </div>

          <p style={muted}>
            Preview inspects the CSV. Evaluation trains a separate Random Forest
            model using supported numeric features and a held-out test split.
            Neither action automatically creates firewall blocks.
          </p>
        </section>

        {error && (
          <div
            role="alert"
            style={{
              ...panel,
              color: "#FCA5A5",
              borderColor: "#7F1D1D",
              display: "flex",
              gap: 10,
              alignItems: "center",
            }}
          >
            <AlertCircle size={20} />
            <span>{error}</span>
          </div>
        )}

        {data && (
          <>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(145px,1fr))", gap: 12 }}>
              {[
                ["ROWS", data.rows],
                ["COLUMNS", data.columns_count],
                ["NUMERIC FEATURES", data.numeric_columns.length],
                ["LABEL TYPES", Object.keys(data.label_distribution || {}).length],
              ].map(([label, value]) => (
                <div key={label} style={panel}>
                  <div style={{ ...muted, letterSpacing: 1 }}>{label}</div>
                  <div style={{ fontSize: 27, fontWeight: 800, marginTop: 8 }}>
                    {Number(value).toLocaleString()}
                  </div>
                </div>
              ))}
            </div>

            <section style={panel}>
              <h3 style={{ marginTop: 0 }}>Dataset summary</h3>
              <p style={muted}>File: {data.filename}</p>
              <p style={muted}>Label column: {data.label_column || "Not detected"}</p>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {data.columns.map((column) => (
                  <span
                    key={column}
                    style={{
                      border: "1px solid #334155",
                      background: "#111E30",
                      padding: "5px 9px",
                      borderRadius: 7,
                      fontSize: 12,
                    }}
                  >
                    {column}
                  </span>
                ))}
              </div>
            </section>

            {Object.keys(data.label_distribution || {}).length > 0 && (
              <section style={panel}>
                <h3 style={{ marginTop: 0 }}>Label distribution</h3>
                {Object.entries(data.label_distribution).map(([label, count]) => {
                  const max = Math.max(1, ...Object.values(data.label_distribution));
                  return (
                    <div
                      key={label}
                      style={{
                        display: "grid",
                        gridTemplateColumns: "minmax(80px,1fr) 2fr auto",
                        gap: 12,
                        alignItems: "center",
                        margin: "13px 0",
                      }}
                    >
                      <span style={{ fontSize: 13, overflowWrap: "anywhere" }}>{label}</span>
                      <div style={{ height: 8, borderRadius: 9, background: "#263449", overflow: "hidden" }}>
                        <div
                          style={{
                            height: "100%",
                            width: `${Math.max(2, (count / max) * 100)}%`,
                            background: "#22D3EE",
                          }}
                        />
                      </div>
                      <strong>{count.toLocaleString()}</strong>
                    </div>
                  );
                })}
              </section>
            )}

            {Object.keys(data.label_distribution || {}).length > 1 && (
              <section style={panel}>
                <h3 style={{ marginTop: 0 }}>Advanced dataset quality analysis</h3>
                {(() => {
                  const counts = Object.values(data.label_distribution).map(Number);
                  const largest = Math.max(...counts);
                  const smallest = Math.min(...counts);
                  const ratio = smallest > 0 ? largest / smallest : Infinity;
                  return (
                    <>
                      <p style={muted}>
                        Largest class: {largest.toLocaleString()} rows ·
                        Smallest class: {smallest.toLocaleString()} rows
                      </p>
                      <p style={{
                        color: ratio >= 5 ? "#FBBF24" : "#4ADE80",
                        fontWeight: 700
                      }}>
                        {ratio >= 5
                          ? `Potential class imbalance detected (${ratio.toFixed(1)}:1 ratio). Consider stratified splitting and training-only resampling.`
                          : `No severe class imbalance detected (${ratio.toFixed(1)}:1 ratio).`}
                      </p>
                      <p style={muted}>
                        This is a class-frequency check, not proof of dataset quality
                        or model generalization.
                      </p>
                    </>
                  );
                })()}
              </section>
            )}

            <section style={panel}>
              <h3 style={{ marginTop: 0 }}>First 10 rows</h3>
              <div style={{ overflowX: "auto" }}>
                <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 12, whiteSpace: "nowrap" }}>
                  <thead>
                    <tr>
                      {data.columns.map((column) => (
                        <th key={column} style={{ textAlign: "left", padding: 10, borderBottom: "1px solid #334155", color: "#67E8F9" }}>
                          {column}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {data.preview.map((row, index) => (
                      <tr key={index}>
                        {data.columns.map((column) => (
                          <td key={column} style={{ padding: 10, borderBottom: "1px solid #1E293B" }}>
                            {row[column] == null ? "—" : String(row[column])}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
            <p style={muted}>
              Dataset labels are reported as supplied. They are not independently verified live detections.
            </p>
          </>
        )}

        {evaluation && (
          <section style={{ display: "grid", gap: 18 }}>
            <section style={{
              ...panel,
              borderColor: "#0E7490",
              background: "linear-gradient(135deg, #10243A, #111827)"
            }}>
              <div style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                flexWrap: "wrap",
                gap: 12
              }}>
                <div>
                  <div style={{ color: "#67E8F9", fontSize: 11, fontWeight: 800, letterSpacing: 1.5 }}>
                    SENTINELAI / MODEL RESEARCH
                  </div>
                  <h2 style={{ margin: "8px 0" }}>Model Evaluation Report</h2>
                  <p style={muted}>{evaluation.filename || "Uploaded dataset"}</p>
                </div>
                <button
                  type="button"
                  style={secondaryButton}
                  onClick={() => {
                    const blob = new Blob(
                      [JSON.stringify(evaluation, null, 2)],
                      { type: "application/json" }
                    );
                    const url = URL.createObjectURL(blob);
                    const link = document.createElement("a");
                    link.href = url;
                    link.download = "sentinelai-evaluation-report.json";
                    link.click();
                    URL.revokeObjectURL(url);
                  }}
                >
                  <Download size={16} /> Export Report
                </button>
              </div>

              <div style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))",
                gap: 12,
                marginTop: 20
              }}>
                {[
                  ["Accuracy", "accuracy"],
                  ["Weighted Precision", "weighted_precision"],
                  ["Weighted Recall", "weighted_recall"],
                  ["Weighted F1 Score", "weighted_f1"]
                ].map(([label, key]) => (
                  <div key={key} style={{
                    background: "#0B1728",
                    border: "1px solid #263D54",
                    borderRadius: 12,
                    padding: 16
                  }}>
                    <div style={{ ...muted, fontSize: 11 }}>{label}</div>
                    <div style={{
                      fontSize: 27,
                      fontWeight: 800,
                      color: "#67E8F9",
                      marginTop: 9
                    }}>
                      {evaluation.metrics?.[key] == null
                        ? "N/A"
                        : `${(evaluation.metrics[key] * 100).toFixed(2)}%`}
                    </div>
                  </div>
                ))}
              </div>

              <div style={{
                display: "flex",
                flexWrap: "wrap",
                gap: 18,
                marginTop: 18,
                color: "#CBD5E1",
                fontSize: 12
              }}>
                <span>Algorithm: <b>Random Forest</b></span>
                <span>Label: <b>{evaluation.label_column}</b></span>
                <span>Classes: <b>{evaluation.classes?.length || 0}</b></span>
              </div>
            </section>

            <section style={panel}>
              <h3 style={{ marginTop: 0 }}>01. Dataset & Experiment Overview</h3>
              <div style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit,minmax(145px,1fr))",
                gap: 12
              }}>
                {[
                  ["Rows scanned", evaluation.evaluation_details?.rows_scanned ?? evaluation.rows_read],
                  ["Rows sampled", evaluation.evaluation_details?.sampled_rows ?? evaluation.valid_rows],
                  ["Training records", evaluation.training_rows],
                  ["Testing records", evaluation.testing_rows],
                  ["Discarded records", evaluation.rows_discarded],
                  ["Features selected", evaluation.features_used?.length || 0]
                ].map(([label, value]) => (
                  <div key={label} style={{
                    padding: 14,
                    borderRadius: 10,
                    background: "#111E30",
                    border: "1px solid #263449"
                  }}>
                    <div style={muted}>{label}</div>
                    <div style={{ fontSize: 23, fontWeight: 800, marginTop: 7 }}>
                      {Number(value ?? 0).toLocaleString()}
                    </div>
                  </div>
                ))}
              </div>
              <p style={muted}>
                Sampling: {evaluation.evaluation_details?.sampling_method || "Not reported"}
                {" · "}
                Split: {evaluation.evaluation_details?.split || "Not reported"}
              </p>
              <p style={muted}>
                Features used: {(evaluation.features_used || []).join(", ") || "Not reported"}
              </p>
            </section>

            <section style={panel}>
              <h3 style={{ marginTop: 0 }}>02. Class-wise Performance</h3>
              <p style={muted}>
                Measures how effectively the model identifies each traffic category.
              </p>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                  <thead>
                    <tr>
                      {["Attack Class", "Precision", "Recall", "F1 Score", "Support"].map(label => (
                        <th key={label} style={{
                          textAlign: "left",
                          padding: 12,
                          color: "#67E8F9",
                          borderBottom: "1px solid #334155"
                        }}>{label}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {(evaluation.classes || []).map(label => {
                      const item = evaluation.classification_report?.[label] || {};
                      return (
                        <tr key={label}>
                          <td style={{ padding: 12, fontWeight: 700 }}>{label}</td>
                          {["precision", "recall", "f1-score"].map(key => (
                            <td key={key} style={{ padding: 12 }}>
                              {item[key] == null ? "N/A" : `${(item[key] * 100).toFixed(2)}%`}
                            </td>
                          ))}
                          <td style={{ padding: 12 }}>
                            {(item.support ?? 0).toLocaleString()}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </section>

            <section style={panel}>
              <h3 style={{ marginTop: 0 }}>03. Confusion Matrix</h3>
              <p style={muted}>
                Rows represent actual classes. Columns represent predicted classes.
                Diagonal cells are correct predictions.
              </p>
              <div style={{ overflowX: "auto" }}>
                {(() => {
                  const matrix = evaluation.confusion_matrix || [];
                  const maximum = Math.max(1, ...matrix.flat());
                  return (
                    <table style={{ borderCollapse: "separate", borderSpacing: 4, fontSize: 12 }}>
                      <thead>
                        <tr>
                          <th style={{ padding: 10, color: "#94A3B8" }}>Actual / Predicted</th>
                          {(evaluation.classes || []).map(label => (
                            <th key={label} style={{ padding: 10, color: "#67E8F9" }}>{label}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {matrix.map((row, i) => (
                          <tr key={evaluation.classes?.[i] || i}>
                            <th style={{ textAlign: "left", padding: 10 }}>
                              {evaluation.classes?.[i] || i}
                            </th>
                            {row.map((count, j) => (
                              <td key={j} style={{
                                minWidth: 75,
                                padding: 14,
                                textAlign: "center",
                                fontWeight: 800,
                                borderRadius: 6,
                                color: "#F8FAFC",
                                background: i === j
                                  ? `rgba(16,185,129,${0.2 + 0.7 * count / maximum})`
                                  : `rgba(239,68,68,${0.08 + 0.65 * count / maximum})`
                              }}>
                                {Number(count).toLocaleString()}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  );
                })()}
              </div>
              <div style={{ ...muted, marginTop: 12 }}>
                <span style={{ color: "#34D399" }}>■ Correct classifications</span>
                {" · "}
                <span style={{ color: "#F87171" }}>■ Misclassifications</span>
              </div>
            </section>

            <section style={panel}>
              <h3 style={{ marginTop: 0 }}>04. False-Positive Analysis</h3>
              <div style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit,minmax(160px,1fr))",
                gap: 12
              }}>
                <div style={{ background: "#111E30", padding: 16, borderRadius: 10 }}>
                  <div style={muted}>Macro False Positive Rate</div>
                  <div style={{ fontSize: 25, fontWeight: 800, marginTop: 8, color: "#FBBF24" }}>
                    {evaluation.metrics?.macro_false_positive_rate == null
                      ? "N/A"
                      : `${(evaluation.metrics.macro_false_positive_rate * 100).toFixed(2)}%`}
                  </div>
                </div>
              </div>
              <div style={{ overflowX: "auto", marginTop: 12 }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                  <thead>
                    <tr>
                      <th style={{ textAlign: "left", padding: 10 }}>Class</th>
                      <th style={{ textAlign: "left", padding: 10 }}>False Positive Rate</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(evaluation.false_positive_rates_by_class || {}).map(([label, rate]) => (
                      <tr key={label}>
                        <td style={{ padding: 10 }}>{label}</td>
                        <td style={{ padding: 10 }}>{(rate * 100).toFixed(2)}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <section style={panel}>
              <h3 style={{ marginTop: 0 }}>05. Evaluation Findings & Recommendations</h3>
              {(() => {
                const details = evaluation.evaluation_details || {};
                const metrics = evaluation.metrics || {};
                const distribution = details.full_dataset_class_distribution || {};
                const sampled = evaluation.class_distribution || {};
                const report = evaluation.classification_report || {};
                const classes = evaluation.classes || [];
                const scanned = Number(details.rows_scanned ?? evaluation.rows_read ?? 0);
                const sampledRows = Number(details.sampled_rows ?? evaluation.valid_rows ?? 0);
                const excluded = Math.max(0, scanned - sampledRows);
                const coverage = scanned > 0 ? sampledRows / scanned * 100 : 0;
                const recalls = classes.map(label => ({
                  label,
                  recall: Number(report[label]?.recall)
                })).filter(item => Number.isFinite(item.recall));
                const weakest = [...recalls].sort((a, b) => a.recall - b.recall)[0];
                const f1 = Number(metrics.weighted_f1);
                const accuracy = Number(metrics.accuracy);
                const fpr = Number(metrics.macro_false_positive_rate);
                const findings = [];

                if (Number.isFinite(f1)) {
                  findings.push({
                    severity: f1 < 0.8 ? "warning" : "success",
                    title: f1 < 0.8 ? "Model performance needs review" : "Weighted F1 threshold passed",
                    text: `Weighted F1 is ${(f1 * 100).toFixed(2)}%. ${f1 < 0.8 ? "Review class-wise errors, feature quality and model configuration." : "Validate on independent datasets before considering deployment."}`
                  });
                }

                if (weakest) {
                  findings.push({
                    severity: weakest.recall < 0.8 ? "warning" : "info",
                    title: `Lowest recall: ${weakest.label}`,
                    text: `Recall is ${(weakest.recall * 100).toFixed(2)}%. ${weakest.recall < 0.8 ? "Inspect false negatives and consider class-specific preprocessing or additional representative samples." : "Continue monitoring this class during independent validation."}`
                  });
                }

                if (excluded > 0) {
                  findings.push({
                    severity: "info",
                    title: "Class-aware sampling reduced the evaluation sample",
                    text: `${excluded.toLocaleString()} scanned labelled rows were not selected for model evaluation. This is sampling exclusion, not proof that these rows were invalid or corrupt.`
                  });
                }

                if (Number(evaluation.testing_rows || 0) < 100) {
                  findings.push({
                    severity: "warning",
                    title: "Small test set",
                    text: `Only ${Number(evaluation.testing_rows || 0).toLocaleString()} rows were used for testing. Metrics may be unstable; evaluate with a larger independent test set.`
                  });
                }

                if (Number.isFinite(fpr)) {
                  findings.push({
                    severity: fpr > 0.05 ? "warning" : "success",
                    title: "False-positive review",
                    text: `Macro false-positive rate is ${(fpr * 100).toFixed(2)}%. ${fpr > 0.05 ? "Review benign traffic incorrectly classified as attacks." : "The reported macro false-positive rate is below 5%; verify on real operational traffic."}`
                  });
                }

                if (findings.length === 0) {
                  findings.push({
                    severity: "info",
                    title: "Limited evaluation evidence",
                    text: "Some metrics are unavailable. Review the technical report and dataset quality before drawing conclusions."
                  });
                }

                const colors = {
                  warning: { background: "rgba(245,158,11,.10)", border: "#92400E", text: "#FCD34D", label: "REVIEW" },
                  success: { background: "rgba(16,185,129,.10)", border: "#065F46", text: "#6EE7B7", label: "PASSED" },
                  info: { background: "rgba(56,189,248,.08)", border: "#155E75", text: "#BAE6FD", label: "INFO" }
                };

                return (
                  <>
                    <div style={{
                      display: "grid",
                      gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))",
                      gap: 12,
                      marginTop: 14
                    }}>
                      {[
                        ["SCANNED LABELLED ROWS", scanned.toLocaleString()],
                        ["ROWS USED", sampledRows.toLocaleString()],
                        ["EXCLUDED BY SAMPLING", excluded.toLocaleString()],
                        ["SAMPLE COVERAGE", `${coverage.toFixed(2)}%`]
                      ].map(([label, value]) => (
                        <div key={label} style={{ ...panel, background: "#111E30", margin: 0 }}>
                          <div style={muted}>{label}</div>
                          <div style={{ fontSize: 21, fontWeight: 800, marginTop: 8 }}>{value}</div>
                        </div>
                      ))}
                    </div>

                    <h4 style={{ margin: "20px 0 8px" }}>Evaluation findings</h4>
                    {findings.map((item, index) => {
                      const color = colors[item.severity];
                      return (
                        <div key={index} style={{
                          marginTop: 10,
                          padding: 13,
                          borderRadius: 9,
                          background: color.background,
                          border: `1px solid ${color.border}`
                        }}>
                          <div style={{ display: "flex", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
                            <strong style={{ color: color.text }}>{item.title}</strong>
                            <span style={{ color: color.text, fontSize: 10, fontWeight: 800 }}>{color.label}</span>
                          </div>
                          <p style={{ margin: "7px 0 0", color: "#CBD5E1", fontSize: 13, lineHeight: 1.6 }}>{item.text}</p>
                        </div>
                      );
                    })}

                    <h4 style={{ margin: "20px 0 8px" }}>Class representation</h4>
                    <div style={{ overflowX: "auto" }}>
                      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                        <thead>
                          <tr>
                            {["Class", "Dataset rows", "Evaluation sample", "Sampled recall"].map(label => (
                              <th key={label} style={{ textAlign: "left", padding: 10, color: "#67E8F9", borderBottom: "1px solid #334155" }}>{label}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {classes.map(label => (
                            <tr key={label}>
                              <td style={{ padding: 10 }}>{label}</td>
                              <td style={{ padding: 10 }}>{Number(distribution[label] ?? 0).toLocaleString()}</td>
                              <td style={{ padding: 10 }}>{Number(sampled[label] ?? 0).toLocaleString()}</td>
                              <td style={{ padding: 10 }}>
                                {Number.isFinite(Number(report[label]?.recall))
                                  ? `${(Number(report[label].recall) * 100).toFixed(2)}%`
                                  : "Not reported"}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <p style={{ ...muted, marginTop: 14 }}>
                      Findings are derived from the evaluation response. Sampling exclusions are not classified as invalid records. Recommendations do not guarantee production security performance.
                    </p>
                  </>
                );
              })()}
            </section>

            <details style={{ ...panel, cursor: "pointer" }}>
              <summary style={{ fontWeight: 700, color: "#67E8F9" }}>
                06. Advanced Technical Details
              </summary>
              {(() => {
                const details = evaluation.evaluation_details || {};
                const distribution = details.full_dataset_class_distribution || {};
                const sampled = evaluation.class_distribution || {};
                const features = evaluation.features_used || [];
                const removed = details.removed_constant_or_empty_features || [];
                const scanned = Number(details.rows_scanned ?? evaluation.rows_read ?? 0);
                const sampledRows = Number(details.sampled_rows ?? evaluation.valid_rows ?? 0);
                const excluded = Math.max(0, scanned - sampledRows);
                const rows = [
                  ["Algorithm", details.algorithm || "Not reported"],
                  ["Sampling strategy", details.sampling_method || "Not reported"],
                  ["Maximum samples per class", details.maximum_rows_per_class?.toLocaleString?.() ?? "Not reported"],
                  ["Imputation strategy", details.imputation || "Not reported"],
                  ["Train/test split", details.split || "Not reported"],
                  ["Rows scanned", scanned.toLocaleString()],
                  ["Rows used in evaluation", sampledRows.toLocaleString()],
                  ["Rows excluded by sampling", excluded.toLocaleString()],
                  ["Training rows", Number(evaluation.training_rows || 0).toLocaleString()],
                  ["Testing rows", Number(evaluation.testing_rows || 0).toLocaleString()],
                  ["Features used", features.length.toLocaleString()],
                  ["Classes evaluated", (evaluation.classes || []).length.toLocaleString()]
                ];

                return (
                  <div style={{ marginTop: 16 }}>
                    <div style={{
                      display: "grid",
                      gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))",
                      gap: 10
                    }}>
                      {rows.map(([label, value]) => (
                        <div key={label} style={{ ...panel, background: "#111E30", margin: 0 }}>
                          <div style={muted}>{label}</div>
                          <div style={{ marginTop: 6, fontWeight: 700, fontSize: 13, overflowWrap: "anywhere" }}>{value}</div>
                        </div>
                      ))}
                    </div>

                    <h4>Model configuration</h4>
                    <p style={muted}>Random Forest configuration: 150 estimators, random_state 42, balanced class weights and parallel execution, when the reported algorithm is Random Forest.</p>

                    <h4>Features included ({features.length})</h4>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 7 }}>
                      {features.map(feature => (
                        <span key={feature} style={{ background: "#1E293B", border: "1px solid #334155", borderRadius: 6, padding: "5px 8px", fontSize: 11 }}>{feature}</span>
                      ))}
                    </div>

                    <h4>Removed constant or empty features ({removed.length})</h4>
                    <p style={muted}>{removed.join(", ") || "No removed features were reported."}</p>

                    <h4>Full dataset class distribution</h4>
                    <div style={{ overflowX: "auto" }}>
                      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                        <thead>
                          <tr>
                            {["Class", "Full dataset count", "Sample count"].map(label => (
                              <th key={label} style={{ textAlign: "left", padding: 9, color: "#67E8F9", borderBottom: "1px solid #334155" }}>{label}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {Object.entries(distribution).map(([label, count]) => (
                            <tr key={label}>
                              <td style={{ padding: 9 }}>{label}</td>
                              <td style={{ padding: 9 }}>{Number(count).toLocaleString()}</td>
                              <td style={{ padding: 9 }}>{Number(sampled[label] ?? 0).toLocaleString()}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    <h4>Reproducibility and interpretation</h4>
                    <p style={muted}>The evaluator uses a fixed random seed and a stratified hold-out split. Results depend on the selected sample, available features, label quality and dataset characteristics.</p>
                    <p style={muted}>Sampling exclusion is separate from data cleaning. The current evaluation response does not independently establish how many source rows were unlabelled, malformed or removed during preprocessing.</p>
                  </div>
                );
              })()}
            </details>

            <section style={{
              ...panel,
              borderColor: "#334155"
            }}>
              <h3 style={{ marginTop: 0 }}>Evaluation Notes</h3>
              <p style={muted}>
                {evaluation.evaluation_note || "Metrics are calculated on a held-out test split."}
              </p>
              {evaluation.testing_rows < 30 && (
                <p style={{ color: "#FCD34D", fontSize: 13 }}>
                  Small test set: only {evaluation.testing_rows} rows were evaluated.
                  Treat these metrics as preliminary.
                </p>
              )}
            </section>
          </section>
        )}

        {intelligence && (
          <section style={{ display: "grid", gap: 16 }}>
            <section style={{ ...panel, borderColor: "#8B5CF6" }}>
              <h2 style={{ marginTop: 0, color: "#C4B5FD" }}>
                Dataset Intelligence Report
              </h2>
              <p style={muted}>
                File: {intelligence.filename} ·
                Analyzed rows: {intelligence.rows_analyzed.toLocaleString()} ·
                Columns: {intelligence.columns_analyzed}
              </p>
              {intelligence.truncated && (
                <p style={{ color: "#FBBF24", fontSize: 13 }}>
                  Analysis was limited to the first {intelligence.analysis_limit.toLocaleString()} rows.
                </p>
              )}
              <div style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit,minmax(145px,1fr))",
                gap: 12,
                marginTop: 16
              }}>
                {[
                  ["ROWS ANALYZED", intelligence.rows_analyzed],
                  ["DUPLICATE ROWS", intelligence.duplicate_rows],
                  ["MISSING VALUES", intelligence.missing_values_total],
                  ["INFINITE VALUES", intelligence.infinite_values_total],
                  ["CONSTANT FEATURES", intelligence.constant_columns.length],
                  ["LABEL CLASSES", Object.keys(intelligence.label_distribution || {}).length],
                ].map(([label, value]) => (
                  <div key={label} style={{ ...panel, background: "#111E30" }}>
                    <div style={muted}>{label}</div>
                    <div style={{ fontSize: 25, fontWeight: 800, marginTop: 8 }}>
                      {Number(value).toLocaleString()}
                    </div>
                  </div>
                ))}
              </div>
            </section>

            <section style={panel}>
              <h3 style={{ marginTop: 0 }}>Data quality findings</h3>
              {intelligence.warnings.length === 0 ? (
                <p style={{ color: "#4ADE80" }}>No configured quality warnings were detected.</p>
              ) : (
                intelligence.warnings.map((warning) => (
                  <p key={warning} style={{ color: "#FBBF24", margin: "10px 0" }}>
                    ⚠ {warning}
                  </p>
                ))
              )}
              <p style={muted}>
                Constant features: {intelligence.constant_columns.join(", ") || "None"}
              </p>
              <p style={muted}>
                Low-variance features: {intelligence.low_variance_columns.join(", ") || "None"}
              </p>
              <p style={muted}>
                Potential leakage warnings: {intelligence.potential_leakage_warnings.length}
              </p>
              {intelligence.potential_leakage_warnings.map((item) => (
                <p key={item.column} style={{ color: "#FBBF24", fontSize: 13 }}>
                  {item.column}: {item.reason}
                </p>
              ))}
            </section>

            <section style={panel}>
              <h3 style={{ marginTop: 0 }}>Numeric feature intelligence</h3>
              <div style={{ overflowX: "auto" }}>
                <table style={{ borderCollapse: "collapse", width: "100%", minWidth: 700, fontSize: 12 }}>
                  <thead>
                    <tr>
                      {["Feature", "Valid", "Missing", "Mean", "Median", "Std Dev", "Variance", "Unique"].map((heading) => (
                        <th key={heading} style={{ textAlign: "left", padding: 10, color: "#67E8F9", borderBottom: "1px solid #334155" }}>
                          {heading}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(intelligence.numeric_features).map(([name, stats]) => (
                      <tr key={name}>
                        <td style={{ padding: 10 }}>{name}</td>
                        <td style={{ padding: 10 }}>{stats.valid_values.toLocaleString()}</td>
                        <td style={{ padding: 10 }}>{stats.missing_values.toLocaleString()}</td>
                        {[stats.mean, stats.median, stats.std, stats.variance].map((value, index) => (
                          <td key={index} style={{ padding: 10 }}>
                            {value == null ? "N/A" : Number(value).toLocaleString(undefined, { maximumFractionDigits: 3 })}
                          </td>
                        ))}
                        <td style={{ padding: 10 }}>{stats.unique_values.toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {Object.keys(intelligence.numeric_features).length === 0 && (
                <p style={muted}>No numeric features were detected.</p>
              )}
            </section>

            <section style={panel}>
              <h3 style={{ marginTop: 0 }}>Missing values by feature</h3>
              {Object.keys(intelligence.missing_by_column).length === 0 ? (
                <p style={{ color: "#4ADE80" }}>No missing values detected.</p>
              ) : (
                Object.entries(intelligence.missing_by_column).map(([name, item]) => (
                  <p key={name} style={muted}>
                    {name}: {item.count.toLocaleString()} ({item.percentage}%)
                  </p>
                ))
              )}
            </section>

            <section style={panel}>
              <h3 style={{ marginTop: 0 }}>Class distribution intelligence</h3>
              <p style={muted}>
                Label column: {intelligence.label_column || "Not detected"}
              </p>
              <p style={{
                color: intelligence.class_imbalance_warning ? "#FBBF24" : "#4ADE80",
                fontWeight: 700
              }}>
                {intelligence.class_imbalance_ratio == null
                  ? "Class imbalance ratio unavailable."
                  : `Largest-to-smallest class ratio: ${intelligence.class_imbalance_ratio}:1`}
              </p>
              {Object.entries(intelligence.label_distribution).map(([label, count]) => (
                <div key={label} style={{
                  display: "flex",
                  justifyContent: "space-between",
                  gap: 12,
                  padding: "9px 0",
                  borderBottom: "1px solid #263449"
                }}>
                  <span>{label}</span>
                  <strong>{count.toLocaleString()}</strong>
                </div>
              ))}
            </section>

            <p style={muted}>{intelligence.note}</p>
          </section>
        )}
      </div>
    </PageLayout>
  );
}
