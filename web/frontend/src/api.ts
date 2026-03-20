import type { GetScanResponse, LocalNetworkResponse, ScanSummary } from './types'

const API_BASE = '/api'

export async function startScan(subnet: string, skipPingSweep: boolean = false): Promise<{ scan_id: string }> {
  const res = await fetch(`${API_BASE}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subnet, skip_ping_sweep: skipPingSweep }),
  })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`Failed to start scan: ${res.status} ${text}`.trim())
  }
  return res.json()
}

export async function getScans(): Promise<ScanSummary[]> {
  const res = await fetch(`${API_BASE}/scans`)
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`Failed to load scan history: ${res.status} ${text}`.trim())
  }
  return res.json()
}

export async function getScan(scanId: string): Promise<GetScanResponse> {
  const res = await fetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}`)
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`Failed to load scan ${scanId}: ${res.status} ${text}`.trim())
  }
  return res.json()
}

export async function cancelScan(scanId: string): Promise<{ cancelled: boolean }> {
  const res = await fetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/cancel`, {
    method: 'POST',
  })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`Failed to cancel scan ${scanId}: ${res.status} ${text}`.trim())
  }
  return res.json()
}

export async function getLocalNetwork(): Promise<LocalNetworkResponse> {
  const res = await fetch(`${API_BASE}/network/local`)
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`Failed to detect local network: ${res.status} ${text}`.trim())
  }
  return res.json()
}

