import { useState } from "react";
import { Upload, FileSpreadsheet, AlertCircle, RefreshCw } from "lucide-react";
import PageLayout from "../components/PageLayout";

const API = (import.meta.env.VITE_API_URL || "https://sentinelai-wnno.onrender.com").replace(/\/+$/, "");
const panel = {
  background: "#0F172A", border: "1px solid #263449",
  borderRadius: 14, padding: 20, minWidth: 0, color: "#E2E8F0"
};
const muted = { color: "#94A3B8", fontSize: 13 };
const button = {
  display: "inline-flex", alignItems: "center", gap: 8, padding: "11px 16px",
  borderRadius: 9, border: 0, background: "#06B6D4",
  color: "#06202A", fontWeight: 800, cursor: "pointer"
};

export default function DatasetLab() {
  const [file, setFile] = useState(null);
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function upload() {
    if (!file) return setError("Choose a CSV file first.");
    setBusy(true);
    setError("");
    setData(null);
    try {
      const body = new FormData();
      body.append("file", file);
      const response = await fetch(`${API}/api/datasets/preview`, {
        method: "POST", body
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || "Upload failed.");
      setData(result);
    } catch (e) {
      setError(`${e.message || "Upload failed."} Confirm the backend is deployed and running.`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <PageLayout title="Dataset Lab" subtitle="Upload and inspect network traffic datasets">
      <div style={{ display: "grid", gap: 18, color: "#E2E8F0" }}>
        <section style={{ ...panel, background: "linear-gradient(135deg,#0F172A,#102A3A)" }}>
          <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 18 }}>
            <FileSpreadsheet size={28} color="#22D3EE" />
            <div>
              <h2 style={{ margin: 0, fontSize: 20 }}>Network dataset upload</h2>
              <p style={{ ...muted, margin: "5px 0 0" }}>CSV only · Maximum 10 GB · Chunked processing</p>
            </div>
          </div>
          <label htmlFor="dataset-file" style={{
            display: "flex", flexDirection: "column", alignItems: "center",
            gap: 10, padding: 30, border: "1px dashed #3B6478",
            borderRadius: 12, background: "rgba(8,47,73,.25)",
            cursor: "pointer", textAlign: "center"
          }}>
            <Upload size={30} color="#22D3EE" />
            <strong>{file ? file.name : "Choose a CSV dataset"}</strong>
            <span style={muted}>{file ? `${(file.size / 1048576).toFixed(2)} MB` : "Click to browse files on your Mac"}</span>
            <input id="dataset-file" type="file" accept=".csv,text/csv"
              style={{ display: "none" }}
              onChange={e => {
                const chosen = e.target.files?.[0] || null;
                setFile(chosen); setData(null); setError("");
                if (chosen && chosen.size > 10 * 1024 * 1024 * 1024) {
                  setError("This file exceeds the 10 GB upload limit.");
                }
              }} />
          </label>
          <button style={{ ...button, marginTop: 16 }} onClick={upload}
            disabled={busy || !file || file.size > 10 * 1024 * 1024 * 1024}>
            {busy ? <RefreshCw size={17} /> : <Upload size={17} />}
            {busy ? "Analyzing CSV..." : "Upload & Analyze"}
          </button>
          <p style={muted}>Uploads are used for dataset inspection. They do not automatically create firewall blocks.</p>
        </section>

        {error && <div role="alert" style={{
          ...panel, color: "#FCA5A5", borderColor: "#7F1D1D",
          display: "flex", gap: 10, alignItems: "center"
        }}><AlertCircle size={20} />{error}</div>}

        {data && <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(145px,1fr))", gap: 12 }}>
            {[["ROWS", data.rows], ["COLUMNS", data.columns_count],
              ["NUMERIC FEATURES", data.numeric_columns.length],
              ["LABEL TYPES", Object.keys(data.label_distribution || {}).length]
            ].map(([label, value]) => <div key={label} style={panel}>
              <div style={{ ...muted, letterSpacing: 1 }}>{label}</div>
              <div style={{ fontSize: 27, fontWeight: 800, marginTop: 8 }}>{Number(value).toLocaleString()}</div>
            </div>)}
          </div>
          <section style={panel}>
            <h3 style={{ marginTop: 0 }}>Dataset summary</h3>
            <p style={muted}>File: {data.filename}</p>
            <p style={muted}>Label column: {data.label_column || "Not detected"}</p>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {data.columns.map(c => <span key={c} style={{
                border: "1px solid #334155", background: "#111E30",
                padding: "5px 9px", borderRadius: 7, fontSize: 12
              }}>{c}</span>)}
            </div>
          </section>
          {Object.keys(data.label_distribution || {}).length > 0 && <section style={panel}>
            <h3 style={{ marginTop: 0 }}>Label distribution</h3>
            {Object.entries(data.label_distribution).map(([label, count]) => {
              const max = Math.max(1, ...Object.values(data.label_distribution));
              return <div key={label} style={{
                display: "grid", gridTemplateColumns: "minmax(80px,1fr) 2fr auto",
                gap: 12, alignItems: "center", margin: "13px 0"
              }}>
                <span style={{ fontSize: 13, overflowWrap: "anywhere" }}>{label}</span>
                <div style={{ height: 8, borderRadius: 9, background: "#263449", overflow: "hidden" }}>
                  <div style={{ height: "100%", width: `${Math.max(2, count / max * 100)}%`, background: "#22D3EE" }} />
                </div>
                <strong>{count.toLocaleString()}</strong>
              </div>;
            })}
          </section>}
          <section style={panel}>
            <h3 style={{ marginTop: 0 }}>First 10 rows</h3>
            <div style={{ overflowX: "auto" }}>
              <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 12, whiteSpace: "nowrap" }}>
                <thead><tr>{data.columns.map(c => <th key={c} style={{
                  textAlign: "left", padding: 10, borderBottom: "1px solid #334155", color: "#67E8F9"
                }}>{c}</th>)}</tr></thead>
                <tbody>{data.preview.map((row, i) => <tr key={i}>{data.columns.map(c =>
                  <td key={c} style={{ padding: 10, borderBottom: "1px solid #1E293B" }}>
                    {row[c] == null ? "—" : String(row[c])}
                  </td>)}</tr>)}</tbody>
              </table>
            </div>
          </section>
          <p style={muted}>CSV labels are reported as provided. They are not independently verified attack detections.</p>
        </>}
      </div>
    </PageLayout>
  );
}
