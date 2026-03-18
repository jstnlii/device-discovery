export type ScanState = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'

export type ScanProgress = {
  message?: string | null
  hosts_found?: number | null
  devices_scanned: number
  total_devices?: number | null
  current_ip?: string | null
}

export type ScanStatus = {
  scan_id: string
  state: ScanState
  created_at: string
  updated_at: string
  progress: ScanProgress
  error?: string | null
}

export type ScanSummary = {
  scan_id: string
  state: ScanState
  scan_time?: string | null
  hosts_found?: number | null
  updated_at: string
}

export type InventoryResponse = {
  scan_metadata: {
    subnet: string
    scan_time: string
    duration_seconds: number
    hosts_found: number
  }
  devices: Array<{
    ip: string
    hostname: string
    mac: string
    manufacturer: string
    open_ports: Record<string, string>
    scanned_at: string
  }>
}

export type GetScanResponse = {
  scan: ScanStatus
  inventory?: InventoryResponse | null
}

