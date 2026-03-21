import { useEffect, useRef, useState } from "react";
import "./App.css";
import {
  cancelScan,
  clearScanHistory,
  getLocalNetwork,
  getScan,
  getScans,
  startScan,
} from "./api";
import type { InventoryResponse, ScanSummary, ScanStatus } from "./types";
import type { LocalNetworkResponse } from "./types";

function deviceOpenPortsToText(
  open_ports: InventoryResponse["devices"][number]["open_ports"],
) {
  const entries = Object.entries(open_ports ?? {});
  if (entries.length === 0) return "";
  return entries.map(([port, service]) => `${port} (${service})`).join(", ");
}

type Stage =
  | "queued"
  | "discovering"
  | "scanning"
  | "done"
  | "cancelled"
  | "failed";

function getStage(status: ScanStatus | null): Stage {
  if (!status) return "queued";
  if (status.state === "failed") return "failed";
  if (status.state === "completed") return "done";
  if (status.state === "cancelled") return "cancelled";

  const msg = (status.progress.message ?? "").toLowerCase();
  if (msg.includes("cancel")) return "cancelled";
  if (msg.includes("discover")) return "discovering";
  if (
    msg.includes("scanning discovered") ||
    msg.includes("scanning discovered hosts")
  )
    return "scanning";
  if (status.progress.current_ip) return "scanning";
  return status.state === "queued" ? "queued" : "discovering";
}

function stageLabel(stage: Stage) {
  switch (stage) {
    case "queued":
      return "Queued";
    case "discovering":
      return "Discovering live hosts";
    case "scanning":
      return "Scanning discovered hosts";
    case "done":
      return "Inventory ready";
    case "cancelled":
      return "Scan cancelled";
    case "failed":
      return "Scan failed";
  }
}

function getProgressPercent(status: ScanStatus | null): number | null {
  if (!status) return null;
  const total = status.progress.total_devices;
  const scanned = status.progress.devices_scanned;
  if (!total || total <= 0) return null;
  const p = (scanned / total) * 100;
  if (Number.isNaN(p)) return null;
  return Math.max(0, Math.min(100, p));
}

function App() {
  const [subnet, setSubnet] = useState("");
  const [skipPingSweep, setSkipPingSweep] = useState(false);
  const [scanHistory, setScanHistory] = useState<ScanSummary[]>([]);
  const [scanId, setScanId] = useState<string | null>(null);
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [inventory, setInventory] = useState<InventoryResponse | null>(null);
  const [starting, setStarting] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [localNetwork, setLocalNetwork] = useState<LocalNetworkResponse | null>(
    null,
  );
  const [detectingNetwork, setDetectingNetwork] = useState(true);

  const pollRef = useRef<number | null>(null);

  async function refreshHistory() {
    const next = await getScans();
    setScanHistory(next);
  }

  async function refreshScan(id: string) {
    const res = await getScan(id);
    setStatus(res.scan);
    setInventory(res.inventory ?? null);
    return res.scan.state;
  }

  function stopPolling() {
    if (pollRef.current !== null) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }

  async function startNewScan() {
    setError(null);
    setStarting(true);
    stopPolling();

    try {
      // #region agent log
      fetch(
        "http://127.0.0.1:7400/ingest/f8ffa4c1-03c2-4355-86d2-96a8f91d6d86",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Debug-Session-Id": "8721f5",
          },
          body: JSON.stringify({
            sessionId: "8721f5",
            runId: "iter4",
            hypothesisId: "H6_fetch_hang",
            location: "App.tsx:startNewScan",
            message: "before_await_startScan",
            data: { subnet, skipPingSweep },
            timestamp: Date.now(),
          }),
        },
      ).catch(() => {});
      // #endregion
      const started = await startScan(subnet, skipPingSweep);
      // #region agent log
      fetch(
        "http://127.0.0.1:7400/ingest/f8ffa4c1-03c2-4355-86d2-96a8f91d6d86",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Debug-Session-Id": "8721f5",
          },
          body: JSON.stringify({
            sessionId: "8721f5",
            runId: "baseline",
            hypothesisId: "H2",
            location: "App.tsx:startNewScan",
            message: "start_scan_response",
            data: { scanId: started.scan_id, subnet, skipPingSweep },
            timestamp: Date.now(),
          }),
        },
      ).catch(() => {});
      // #endregion
      setScanId(started.scan_id);
      setStatus(null);
      setInventory(null);

      // #region agent log
      fetch(
        "http://127.0.0.1:7400/ingest/f8ffa4c1-03c2-4355-86d2-96a8f91d6d86",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Debug-Session-Id": "8721f5",
          },
          body: JSON.stringify({
            sessionId: "8721f5",
            runId: "baseline",
            hypothesisId: "H1_or_H2",
            location: "App.tsx:startNewScan",
            message: "before_refreshHistory",
            data: { scanId: started.scan_id },
            timestamp: Date.now(),
          }),
        },
      ).catch(() => {});
      // #endregion
      await refreshHistory();
      // `useEffect([scanId])` will fetch + poll as needed.
      // #region agent log
      fetch(
        "http://127.0.0.1:7400/ingest/f8ffa4c1-03c2-4355-86d2-96a8f91d6d86",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Debug-Session-Id": "8721f5",
          },
          body: JSON.stringify({
            sessionId: "8721f5",
            runId: "baseline",
            hypothesisId: "H1_or_H2",
            location: "App.tsx:startNewScan",
            message: "after_refreshHistory",
            data: { scanId: started.scan_id },
            timestamp: Date.now(),
          }),
        },
      ).catch(() => {});
      // #endregion
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setStarting(false);
    }
  }

  useEffect(() => {
    (async () => {
      try {
        const local = await getLocalNetwork();
        setLocalNetwork(local);
        if (local.detected?.cidr) {
          setSubnet(local.detected.cidr);
        } else {
          setSubnet("10.0.0.0/24");
        }
      } catch {
        setSubnet("10.0.0.0/24");
      } finally {
        setDetectingNetwork(false);
      }
    })();

    refreshHistory().catch((e) =>
      setError(e instanceof Error ? e.message : String(e)),
    );
  }, []);

  useEffect(() => {
    // If user selects a previous scan, fetch it once (and don't poll unless it is actively running).
    if (!scanId) return;
    // #region agent log
    fetch("http://127.0.0.1:7400/ingest/f8ffa4c1-03c2-4355-86d2-96a8f91d6d86", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Debug-Session-Id": "8721f5",
      },
      body: JSON.stringify({
        sessionId: "8721f5",
        runId: "baseline",
        hypothesisId: "H2",
        location: "App.tsx:useEffect(scanId)",
        message: "scan_id_effect_triggered",
        data: { scanId },
        timestamp: Date.now(),
      }),
    }).catch(() => {});
    // #endregion
    stopPolling();
    (async () => {
      const state = await refreshScan(scanId);
      if (state === "running" || state === "queued") {
        pollRef.current = window.setInterval(async () => {
          await refreshScan(scanId);
        }, 1000);
      }
    })().catch((e) => setError(e instanceof Error ? e.message : String(e)));

    return () => stopPolling();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  useEffect(() => {
    if (!status) return;
    // #region agent log
    fetch("http://127.0.0.1:7400/ingest/f8ffa4c1-03c2-4355-86d2-96a8f91d6d86", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Debug-Session-Id": "8721f5",
      },
      body: JSON.stringify({
        sessionId: "8721f5",
        runId: "baseline",
        hypothesisId: "H3",
        location: "App.tsx:useEffect(status)",
        message: "status_state_changed",
        data: {
          scanId,
          statusState: status.state,
          progressMessage: status.progress.message ?? null,
        },
        timestamp: Date.now(),
      }),
    }).catch(() => {});
    // #endregion
    if (
      status.state === "completed" ||
      status.state === "failed" ||
      status.state === "cancelled"
    ) {
      stopPolling();
      refreshHistory().catch(() => {});
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status?.state]);

  async function handleClearHistory() {
    if (
      !window.confirm(
        "Permanently delete all scan history? This cannot be undone."
      )
    ) {
      return;
    }
    setError(null);
    setClearing(true);
    try {
      const { deleted } = await clearScanHistory();
      const selectedScan = scanHistory.find((s) => s.scan_id === scanId);
      const wasSelectedDeleted =
        selectedScan &&
        selectedScan.state !== "queued" &&
        selectedScan.state !== "running";
      // Clear selection first so the right panel updates immediately
      if (wasSelectedDeleted) {
        setScanId(null);
        setStatus(null);
        setInventory(null);
      }
      await refreshHistory();
      if (deleted > 0) {
        setError(null);
        // Brief positive feedback - could use a toast if we had one
        window.alert(`Cleared ${deleted} scan(s) from history.`);
      } else {
        window.alert(
          "No scans to clear. (Running or queued scans are kept.)"
        );
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setClearing(false);
    }
  }

  async function cancelCurrentScan() {
    if (!scanId) return;
    setError(null);
    setCancelling(true);
    // #region agent log
    fetch("http://127.0.0.1:7400/ingest/f8ffa4c1-03c2-4355-86d2-96a8f91d6d86", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Debug-Session-Id": "8721f5",
      },
      body: JSON.stringify({
        sessionId: "8721f5",
        runId: "baseline",
        hypothesisId: "H4",
        location: "App.tsx:cancelCurrentScan",
        message: "cancel_clicked",
        data: { scanId },
        timestamp: Date.now(),
      }),
    }).catch(() => {});
    // #endregion
    try {
      await cancelScan(scanId);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setCancelling(false);
    }
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <h1 className="brand-title">Device Discovery</h1>
          <p className="brand-subtitle">
            Scan your network and discover connected devices
          </p>
        </div>
      </header>

      <main className="layout">
        <section className="panel">
          <h2 className="panel-title">Scan</h2>

          <div className="row">
            <label className="label" htmlFor="subnet">
              Subnet or IP
            </label>
            <input
              id="subnet"
              className="input"
              value={subnet}
              onChange={(e) => setSubnet(e.target.value)}
              disabled={starting}
              placeholder="10.0.0.0/24 or 10.0.0.187"
              spellCheck={false}
              inputMode="text"
            />
          </div>

          {localNetwork?.detected ? (
            <div className="detect-card">
              <div className="detect-card-body">
                <div className="detect-card-main">
                  <span className="detect-label">Auto-detected network</span>
                  <span className="detect-cidr mono">
                    {localNetwork.detected.cidr}
                  </span>
                </div>
                <div className="detect-card-meta">
                  <div>This machine: {localNetwork.detected.ip}</div>
                  <div>Netmask: {localNetwork.detected.netmask}</div>
                </div>
              </div>
              <button
                className="btn btn-sm primary"
                disabled={starting || detectingNetwork}
                onClick={() =>
                  setSubnet(localNetwork.detected?.cidr ?? "")
                }
              >
                Use
              </button>
            </div>
          ) : null}

          <div className="checkbox-row checkbox-row-with-hint">
            <label className="checkbox">
              <input
                type="checkbox"
                checked={skipPingSweep}
                onChange={(e) => setSkipPingSweep(e.target.checked)}
                disabled={starting}
              />
              Scan every address (ICMP can be blocked)
              <span className="hint-trigger" aria-label="More info">
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                  <circle cx="7" cy="7" r="6.25" stroke="currentColor" strokeWidth="1.5" fill="none" />
                  <path d="M7 6.5v4M7 4.5v.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                </svg>
              </span>
            </label>
            <div className="hint-tooltip" role="tooltip">
              {`If unchecked, the scan sends a broadcast signal to all devices on the network (called a "ping sweep" or "ICMP sweep") to see which devices respond, then only checks those for efficiency.

If checked, the scan will iteratively scan every address instead. Some networks block sweeps (common on work or school networks).`}
            </div>
          </div>

          <div className="actions">
            <button
              className="btn primary"
              onClick={startNewScan}
              disabled={starting || !subnet.trim()}
            >
              {starting ? "Starting..." : "Start Scan"}
            </button>
            <button
              className="btn"
              onClick={() =>
                refreshHistory().catch((e) =>
                  setError(e instanceof Error ? e.message : String(e)),
                )
              }
              disabled={starting}
            >
              Refresh History
            </button>
          </div>

          {error ? (
            <div className="error">
              {error}
              <button
                type="button"
                className="error-dismiss"
                onClick={() => setError(null)}
                aria-label="Dismiss"
              >
                ×
              </button>
            </div>
          ) : null}

          <div className="divider" />

          <div className="section-header">
            <h2 className="panel-title">Scan History</h2>
            {scanHistory.length > 0 ? (
              <button
                type="button"
                className="btn-clear"
                onClick={handleClearHistory}
                disabled={clearing || starting}
                title="Remove completed scans from history"
              >
                {clearing ? "Clearing…" : "Clear history"}
              </button>
            ) : null}
          </div>
          <div className="history">
            {scanHistory.length === 0 ? (
              <div className="muted">No scans yet.</div>
            ) : (
              scanHistory.map((s) => (
                <button
                  key={s.scan_id}
                  className={`history-item ${scanId === s.scan_id ? "active" : ""}`}
                  onClick={() => setScanId(s.scan_id)}
                >
                  <div className="history-item-top">
                    <span className="history-id">{s.scan_id.slice(0, 8)}</span>
                    <span className={`pill ${s.state}`}>{s.state}</span>
                  </div>
                  <div className="history-item-bottom">
                    <span>{s.hosts_found ?? 0} host(s)</span>
                    <span className="dot">•</span>
                    <span>
                      {s.scan_time
                        ? new Date(s.scan_time).toLocaleString()
                        : "—"}
                    </span>
                  </div>
                </button>
              ))
            )}
          </div>
        </section>

        <section className="panel wide results">
          <h2 className="panel-title">Results</h2>

          {!scanId ? (
            <div className="muted">Select a scan (or start a new one).</div>
          ) : null}

          {scanId && status ? (
            <div className="status">
              <div className="status-head">
                <span className={`pill ${status.state}`}>{status.state}</span>
                <div className="status-meta">
                  {status.progress.current_ip ? (
                    <span className="muted">
                      Current: {status.progress.current_ip}
                    </span>
                  ) : null}
                </div>
              </div>

              {status.progress.message ? (
                <div className="status-message">{status.progress.message}</div>
              ) : null}

              <div className="stage">
                <div className="stage-label">
                  {stageLabel(getStage(status))}
                </div>
                {(status.state === "queued" || status.state === "running") ? (
                  <>
                    <div className="stage-bar" aria-hidden="true">
                      {getProgressPercent(status) === null ? (
                        <div className="stage-bar-indeterminate" />
                      ) : (
                        <div
                          className="stage-bar-fill"
                          style={{ width: `${getProgressPercent(status) ?? 0}%` }}
                        />
                      )}
                    </div>
                    <div className="stage-sub">
                      {status.progress.total_devices ? (
                        <>
                          {status.progress.devices_scanned}/
                          {status.progress.total_devices} devices scanned
                        </>
                      ) : (
                        <span className="muted">Scanning in progress…</span>
                      )}
                    </div>
                  </>
                ) : null}

                {status.state === "queued" || status.state === "running" ? (
                  <div className="cancel-row">
                    <button
                      className="btn danger"
                      onClick={cancelCurrentScan}
                      disabled={cancelling || starting}
                    >
                      {cancelling ? "Cancelling…" : "Cancel Scan"}
                    </button>
                  </div>
                ) : null}
              </div>

              {status.state !== "failed" &&
              inventory &&
              (status.state === "completed" || status.state === "cancelled") ? (
                <div className="summary">
                  <div className="summary-item">
                    <div className="summary-k">Hosts</div>
                    <div className="summary-v">
                      {inventory.scan_metadata.hosts_found}
                    </div>
                  </div>
                  <div className="summary-item">
                    <div className="summary-k">Duration</div>
                    <div className="summary-v">
                      {inventory.scan_metadata.duration_seconds}s
                    </div>
                  </div>
                </div>
              ) : null}

              {status.state === "failed" && status.error ? (
                <div className="error">{status.error}</div>
              ) : null}
            </div>
          ) : null}

          {scanId && inventory && inventory.devices.length === 0 ? (
            <div className="empty-scan">
              <p className="empty-scan-title">No devices found</p>
              <p className="empty-scan-desc">
                The scan completed but didn&apos;t detect any hosts on the
                network. This can happen if the subnet doesn&apos;t match your
                network, devices block ping, or the network is offline.
              </p>
              <p className="empty-scan-hint">
                Try a different subnet or enable &quot;Scan every address&quot;
                if your network blocks ICMP ping.
              </p>
            </div>
          ) : scanId && inventory ? (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>IP</th>
                    <th>Hostname</th>
                    <th>MAC</th>
                    <th>Manufacturer</th>
                    <th>Open Ports</th>
                  </tr>
                </thead>
                <tbody>
                  {inventory.devices.map((d) => (
                      <tr key={d.ip}>
                        <td className="mono">{d.ip}</td>
                        <td>{d.hostname}</td>
                        <td className="mono">{d.mac}</td>
                        <td>{d.manufacturer}</td>
                        <td title={deviceOpenPortsToText(d.open_ports)}>
                          {Object.keys(d.open_ports).length === 0 ? (
                            <span className="muted">—</span>
                          ) : (
                            <div className="chips">
                              {Object.entries(d.open_ports).map(
                                ([port, service]) => (
                                  <span key={port} className="chip">
                                    <span className="chip-port">{port}</span>
                                    <span className="chip-sep">/</span>
                                    <span className="chip-svc">{service}</span>
                                  </span>
                                ),
                              )}
                            </div>
                          )}
                        </td>
                      </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : scanId &&
            status &&
            (status.state === "queued" || status.state === "running") ? (
            <div className="muted">
              Scanning… results will appear when completed.
            </div>
          ) : null}
        </section>
      </main>
    </div>
  );
}

export default App;
