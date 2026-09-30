"use client";

import { useEffect, useRef, useState } from "react";
import { analyzeLogHeuristically } from "../lib/heuristics";

const HISTORY_KEY = "debrief_history_v1";
const API_KEY_STORAGE = "debrief_api_key_v1";
const MODE_STORAGE = "debrief_mode_v1";
const MAX_HISTORY = 10;
const MAX_UPLOAD_CHARS = 500000; // guard against pasting huge binaries by mistake

const LOG_TYPES = [
  { value: "", label: "Auto-detect" },
  { value: "SSH / auth", label: "SSH / auth log" },
  { value: "firewall", label: "Firewall" },
  { value: "web server", label: "Web server access log" },
  { value: "cloud (AWS/GCP/Azure)", label: "Cloud provider" },
  { value: "Windows Event Log", label: "Windows Event Log" },
  { value: "application", label: "Application log" },
];

function makeId() {
  return "h" + Date.now() + Math.random().toString(36).slice(2, 7);
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export default function LogSummarizer() {
  const [mode, setMode] = useState("upload"); // upload | paste
  const [fileName, setFileName] = useState("");
  const [fileSize, setFileSize] = useState(0);
  const [logText, setLogText] = useState("");
  const [logType, setLogType] = useState("");
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [copyLabel, setCopyLabel] = useState("Copy summary");
  const fileInputRef = useRef(null);

  const [analysisMode, setAnalysisMode] = useState("offline"); // offline | ai
  const [apiKey, setApiKey] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [keyDraft, setKeyDraft] = useState("");

  useEffect(() => {
    try {
      const raw = localStorage.getItem(HISTORY_KEY);
      if (raw) setHistory(JSON.parse(raw));
    } catch {}
    try {
      const savedKey = localStorage.getItem(API_KEY_STORAGE);
      if (savedKey) { setApiKey(savedKey); setKeyDraft(savedKey); }
    } catch {}
    try {
      const savedMode = localStorage.getItem(MODE_STORAGE);
      if (savedMode) setAnalysisMode(savedMode);
    } catch {}
  }, []);

  function selectAnalysisMode(next) {
    setAnalysisMode(next);
    try { localStorage.setItem(MODE_STORAGE, next); } catch {}
  }

  function saveApiKey() {
    const trimmed = keyDraft.trim();
    setApiKey(trimmed);
    try {
      if (trimmed) localStorage.setItem(API_KEY_STORAGE, trimmed);
      else localStorage.removeItem(API_KEY_STORAGE);
    } catch {}
    setSettingsOpen(false);
  }

  function removeApiKey() {
    setApiKey("");
    setKeyDraft("");
    try { localStorage.removeItem(API_KEY_STORAGE); } catch {}
  }

  function saveHistory(next) {
    setHistory(next);
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
    } catch {}
  }

  function loadFile(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = String(e.target.result || "").slice(0, MAX_UPLOAD_CHARS);
      setLogText(text);
      setFileName(file.name);
      setFileSize(file.size);
    };
    reader.readAsText(file);
  }

  function handleDrop(e) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    loadFile(file);
  }

  function clearFile() {
    setFileName("");
    setFileSize(0);
    setLogText("");
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  async function handleSummarize() {
    if (!logText.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);

    if (analysisMode === "offline") {
      // Runs synchronously in the browser — no network call at all.
      const data = analyzeLogHeuristically(logText, logType);
      setResult(data);
      const entry = {
        id: makeId(),
        title: data.title,
        severity: data.severity,
        mode: "offline",
        fileName: fileName || (mode === "paste" ? "Pasted log" : "Untitled"),
        timestamp: new Date().toISOString(),
        result: data,
      };
      saveHistory([entry, ...history].slice(0, MAX_HISTORY));
      setLoading(false);
      return;
    }

    try {
      const res = await fetch("/api/summarize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ logText, logType, fileName: fileName || undefined, apiKey }),
      });
      const data = await res.json();
      if (!res.ok || data.error) {
        setError(data.error || "Something went wrong.");
        setLoading(false);
        return;
      }
      setResult(data);
      const entry = {
        id: makeId(),
        title: data.title,
        severity: data.severity,
        mode: "ai",
        fileName: fileName || (mode === "paste" ? "Pasted log" : "Untitled"),
        timestamp: new Date().toISOString(),
        result: data,
      };
      saveHistory([entry, ...history].slice(0, MAX_HISTORY));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function loadFromHistory(entry) {
    setResult(entry.result);
    setError("");
  }

  function clearHistory() {
    if (!confirm("Clear analysis history?")) return;
    saveHistory([]);
  }

  async function copySummary() {
    if (!result) return;
    const lines = [
      `${result.title} — ${result.severity?.toUpperCase()}`,
      "",
      result.summary,
      "",
    ];
    if (result.timeline?.length) {
      lines.push("Timeline:");
      result.timeline.forEach((t) => lines.push(`- ${t.time ? t.time + ": " : ""}${t.event}`));
      lines.push("");
    }
    if (result.recommended_actions?.length) {
      lines.push("Recommended actions:");
      result.recommended_actions.forEach((a, i) => lines.push(`${i + 1}. ${a}`));
    }
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
      setCopyLabel("Copied!");
      setTimeout(() => setCopyLabel("Copy summary"), 1500);
    } catch {}
  }

  const iocEntries = result?.iocs
    ? Object.entries(result.iocs).filter(([, v]) => Array.isArray(v))
    : [];

  return (
    <div className="wrap">
      <header>
        <div className="brand-mark">🔎</div>
        <div style={{ flex: 1 }}>
          <h1>Debrief</h1>
          <div className="sub">Upload a log and get an incident summary — no API key required.</div>
        </div>
        <button className="btn-ghost" onClick={() => { setKeyDraft(apiKey); setSettingsOpen(true); }}>
          ⚙ Settings
        </button>
      </header>

      <div className="mode-switch">
        <button
          className={`mode-btn ${analysisMode === "offline" ? "active" : ""}`}
          onClick={() => selectAnalysisMode("offline")}
        >
          <b>Offline heuristics</b>
          <span>Instant, private, no API key</span>
        </button>
        <button
          className={`mode-btn ${analysisMode === "ai" ? "active" : ""}`}
          onClick={() => selectAnalysisMode("ai")}
        >
          <b>AI-enhanced (Claude)</b>
          <span>{apiKey ? "Key saved — deeper analysis" : "Requires your API key"}</span>
        </button>
      </div>

      {settingsOpen && (
        <div className="modal-backdrop" onClick={() => setSettingsOpen(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h2 style={{ marginBottom: 6 }}>Anthropic API key</h2>
            <p className="modal-copy">
              Optional. Only needed for AI-enhanced mode. Stored in your browser's
              localStorage only — it's sent to this app's own server on each AI
              request and forwarded to Anthropic; it's never stored server-side.
            </p>
            <input
              type="password"
              placeholder="sk-ant-…"
              value={keyDraft}
              onChange={(e) => setKeyDraft(e.target.value)}
              autoComplete="off"
            />
            <div className="modal-actions">
              {apiKey && <button className="btn-ghost" onClick={removeApiKey}>Remove key</button>}
              <button className="btn-ghost" onClick={() => setSettingsOpen(false)}>Cancel</button>
              <button className="btn-primary" style={{ marginTop: 0 }} onClick={saveApiKey}>Save</button>
            </div>
          </div>
        </div>
      )}

      <div className="layout">
        <div className="panel">
          <h2>Log input</h2>
          <div className="tabs">
            <button className={`tab ${mode === "upload" ? "active" : ""}`} onClick={() => setMode("upload")}>
              Upload file
            </button>
            <button className={`tab ${mode === "paste" ? "active" : ""}`} onClick={() => setMode("paste")}>
              Paste text
            </button>
          </div>

          {mode === "upload" ? (
            <>
              {!fileName ? (
                <label
                  className={`dropzone ${dragging ? "drag" : ""}`}
                  onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
                  onDragLeave={() => setDragging(false)}
                  onDrop={handleDrop}
                >
                  <b>Drop a log file here, or click to browse</b>
                  .log, .txt, .csv, .json — parsed entirely in your browser
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".log,.txt,.csv,.json,text/plain"
                    onChange={(e) => loadFile(e.target.files?.[0])}
                  />
                </label>
              ) : (
                <div className="file-chip">
                  <div>
                    <div className="name">{fileName}</div>
                    <div className="meta">{formatBytes(fileSize)} · {logText.length.toLocaleString()} characters loaded</div>
                  </div>
                  <button onClick={clearFile} title="Remove file">&times;</button>
                </div>
              )}
            </>
          ) : (
            <textarea
              placeholder="Paste raw log lines here…"
              value={logText}
              onChange={(e) => setLogText(e.target.value)}
            />
          )}

          <div className="row2">
            <div>
              <label htmlFor="logType">Log type <span style={{ color: "var(--faint)" }}>(optional hint)</span></label>
              <select id="logType" value={logType} onChange={(e) => setLogType(e.target.value)}>
                {LOG_TYPES.map((t) => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
            </div>
            <button
              className="btn-primary"
              disabled={loading || !logText.trim() || (analysisMode === "ai" && !apiKey)}
              onClick={handleSummarize}
              title={analysisMode === "ai" && !apiKey ? "Add an API key in Settings first" : ""}
            >
              {loading ? (<><span className="dot pulse" />Analyzing…</>) : analysisMode === "ai" && !apiKey ? "Add API key to continue" : "Generate summary"}
            </button>
          </div>

          {error && <div className="error-box">{error}</div>}
        </div>

        <div className="panel">
          <h2>Incident summary</h2>
          {!result && !loading && (
            <div className="empty">
              <b>No analysis yet</b>
              Upload or paste a log above and click "Generate summary".
            </div>
          )}
          {loading && (
            <div className="empty pulse">
              <b>Reading the log…</b>
              Claude is analyzing the excerpt for signs of an incident.
            </div>
          )}
          {result && !loading && (
            <div>
              <div className="result-head">
                <div>
                  <span className={`badge ${result.severity}`}>{result.severity}</span>
                  <span className="mode-tag">{result.mode === "ai" ? "AI analysis" : "Offline analysis"}</span>
                  <div className="result-title" style={{ marginTop: 8 }}>{result.title}</div>
                </div>
                <div className="result-toolbar">
                  <button className="btn-ghost" onClick={copySummary}>{copyLabel}</button>
                </div>
              </div>

              <div className="summary-text">{result.summary}</div>

              {result.timeline?.length > 0 && (
                <>
                  <div className="section-label">Timeline</div>
                  <ul className="timeline">
                    {result.timeline.map((t, i) => (
                      <li key={i}>
                        {t.time && <span className="time">{t.time}</span>}
                        {t.event}
                      </li>
                    ))}
                  </ul>
                </>
              )}

              {iocEntries.length > 0 && (
                <>
                  <div className="section-label">Indicators observed</div>
                  <div className="ioc-groups">
                    {iocEntries.map(([key, values]) => (
                      <div className="ioc-group" key={key}>
                        <h4>{key}</h4>
                        {values.length ? (
                          <div className="ioc-tags">
                            {values.map((v, i) => <span className="ioc-tag" key={i}>{v}</span>)}
                          </div>
                        ) : (
                          <div className="ioc-empty">none found</div>
                        )}
                      </div>
                    ))}
                  </div>
                </>
              )}

              {result.recommended_actions?.length > 0 && (
                <>
                  <div className="section-label">Recommended actions</div>
                  <ul className="actions-list">
                    {result.recommended_actions.map((a, i) => (
                      <li key={i}><span className="num">{i + 1}</span>{a}</li>
                    ))}
                  </ul>
                </>
              )}

              {result.notes && <div className="notes-box">{result.notes}</div>}
              {result.truncated && (
                <div className="notes-box">This log was large — only the beginning and end were analyzed in full detail.</div>
              )}
            </div>
          )}
        </div>

        {history.length > 0 && (
          <div className="panel">
            <div className="result-head" style={{ marginBottom: 12 }}>
              <h2 style={{ margin: 0 }}>Recent analyses</h2>
              <button className="btn-ghost" onClick={clearHistory}>Clear history</button>
            </div>
            <div className="history-list">
              {history.map((h) => (
                <div className="history-item" key={h.id} onClick={() => loadFromHistory(h)}>
                  <div>
                    <div className="h-name">{h.title || h.fileName}</div>
                    <div className="h-meta">{h.fileName} · {h.mode === "ai" ? "AI" : "Offline"} · {new Date(h.timestamp).toLocaleString()}</div>
                  </div>
                  <span className={`badge ${h.severity}`}>{h.severity}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
