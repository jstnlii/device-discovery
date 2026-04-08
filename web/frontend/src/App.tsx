import { useEffect, useRef, useState } from "react";
import "./App.css";
import refreshIcon from "./assets/refreshicon.png";
import {
  cancelScan,
  clearScanHistory,
  getLocalNetwork,
  getScan,
  getScans,
  startScan,
} from "./api";
import {
  getChipTitle,
  inferDeviceType,
  type Device,
  type DeviceType,
} from "./deviceUtils";
import { NetworkMap } from "./NetworkMap";
import type { InventoryResponse, ScanSummary, ScanStatus } from "./types";
import type { LocalNetworkResponse } from "./types";

function deviceOpenPortsToText(
  open_ports: InventoryResponse["devices"][number]["open_ports"],
) {
  const entries = Object.entries(open_ports ?? {});
  if (entries.length === 0) return "";
  return entries.map(([port, service]) => `${port} (${service})`).join(", ");
}

/** Last octet is 1 (common convention for subnet routers; not always the default route). */
function ipv4LastOctetIsOne(ip: string): boolean {
  const parts = ip.trim().split(".");
  return (
    parts.length === 4 &&
    parts[3] === "1" &&
    parts.every((p) => /^\d{1,3}$/.test(p))
  );
}

function HostnameCell({
  device,
  defaultGateway,
}: {
  device: InventoryResponse["devices"][number];
  defaultGateway: string | null;
}) {
  const hostname = (device.hostname ?? "").trim();
  const isUnknown = !hostname || hostname.toLowerCase() === "unknown";
  const gatewayFromOs = Boolean(defaultGateway?.trim());
  const matchesDetectedGateway =
    gatewayFromOs && device.ip === defaultGateway?.trim();
  const inferredFromDotOneWhenNoOsGateway =
    !gatewayFromOs && isUnknown && ipv4LastOctetIsOne(device.ip);

  if (isUnknown && (matchesDetectedGateway || inferredFromDotOneWhenNoOsGateway)) {
    return (
      <span
        className="hostname-gateway-badge"
        title={
          matchesDetectedGateway
            ? "This address matches your detected default gateway (typically your router)."
            : "Default gateway could not be read from this machine. Addresses ending in .1 are often the subnet router (not guaranteed)."
        }
      >
        default gateway
      </span>
    );
  }
  return <>{hostname || "unknown"}</>;
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

const DEVICE_TYPE_LABELS: Record<DeviceType, string> = {
  router: "Router",
  computer: "Computer",
  printer: "Printer",
  nas: "NAS",
  iot: "IoT / Smart",
  other: "Other",
};

function Dashboard({
  inventory,
  defaultGateway,
}: {
  inventory: InventoryResponse;
  defaultGateway: string | null;
}) {
  const meta = inventory.scan_metadata;
  const devices = inventory.devices;

  const typeCounts: Record<DeviceType, number> = {
    router: 0,
    computer: 0,
    printer: 0,
    nas: 0,
    iot: 0,
    other: 0,
  };
  for (const d of devices) {
    const t = inferDeviceType(d as Device, defaultGateway);
    typeCounts[t]++;
  }
  const typePills = (Object.entries(typeCounts) as [DeviceType, number][])
    .filter(([, n]) => n > 0)
    .map(([t, n]) => `${n} ${DEVICE_TYPE_LABELS[t]}${n !== 1 ? "s" : ""}`)
    .join(" • ");

  return (
    <div className="dashboard">
      <div className="dashboard-headline">
        {meta.hosts_found} device{meta.hosts_found !== 1 ? "s" : ""} found
        in {meta.duration_seconds}s
      </div>
      <div className="dashboard-stats">
        <div className="dashboard-stat">
          <span className="dashboard-stat-k">Subnet</span>
          <span className="dashboard-stat-v mono">{meta.subnet}</span>
        </div>
        {typePills ? (
          <div className="dashboard-stat">
            <span className="dashboard-stat-k">By type</span>
            <span className="dashboard-stat-v">{typePills}</span>
          </div>
        ) : null}
      </div>
    </div>
  );
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
  const [resultsView, setResultsView] = useState<"table" | "map">("table");

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
      const started = await startScan(subnet, skipPingSweep);
      setScanId(started.scan_id);
      setStatus(null);
      setInventory(null);

      await refreshHistory();
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
        // Leave input blank on startup so user can press "Use" for auto-detected IP
        if (!local.detected?.cidr) {
          setSubnet("10.0.0.0/24"); // fallback when detection fails
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
            <div className="section-header-actions">
              <button
                type="button"
                className="btn-icon"
                onClick={() =>
                  refreshHistory().catch((e) =>
                    setError(e instanceof Error ? e.message : String(e)),
                  )
                }
                disabled={starting}
                title="Refresh history"
                aria-label="Refresh history"
              >
                <img src={refreshIcon} alt="" width={18} height={18} />
              </button>
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
          </div>
          <div className="history">
            {scanHistory.length === 0 ? (
              <div className="muted">No scans yet.</div>
            ) : (
              scanHistory.map((s) => (
                <button
                  key={s.scan_id}
                  className={`history-item ${scanId === s.scan_id ? "active" : ""}`}
                  onClick={() => setScanId(scanId === s.scan_id ? null : s.scan_id)}
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
                <Dashboard
                  inventory={inventory}
                  defaultGateway={inventory.default_gateway ?? null}
                />
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
            <>
              <div className="results-view-toggle">
                <button
                  type="button"
                  className={resultsView === "table" ? "active" : ""}
                  onClick={() => setResultsView("table")}
                >
                  Table
                </button>
                <button
                  type="button"
                  className={resultsView === "map" ? "active" : ""}
                  onClick={() => setResultsView("map")}
                >
                  Map
                </button>
              </div>
              {resultsView === "table" ? (
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
                        <td>
                          <HostnameCell
                            device={d}
                            defaultGateway={inventory.default_gateway ?? null}
                          />
                        </td>
                        <td className="mono">{d.mac}</td>
                        <td>{d.manufacturer}</td>
                        <td title={deviceOpenPortsToText(d.open_ports)}>
                          {Object.keys(d.open_ports).length === 0 ? (
                            <span className="muted">—</span>
                          ) : (
                            <div className="chips">
                              {Object.entries(d.open_ports).map(
                                ([port, service]) => (
                                  <span
                                    key={port}
                                    className="chip"
                                    title={getChipTitle(port, service)}
                                  >
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
              ) : (
                <NetworkMap
                  inventory={inventory}
                  defaultGateway={inventory.default_gateway ?? null}
                />
              )}
            </>
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
