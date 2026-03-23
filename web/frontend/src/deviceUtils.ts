/**
 * Device utilities: type inference, port descriptions, and shared helpers.
 */

export type DeviceType =
  | 'router'
  | 'computer'
  | 'printer'
  | 'nas'
  | 'iot'
  | 'other'

export type Device = {
  ip: string
  hostname: string
  mac: string
  manufacturer: string
  open_ports: Record<string, string>
  scanned_at?: string
}

/**
 * Human-readable descriptions for common ports (shown on hover).
 * Technical names (e.g. HTTP) remain visible in the chip.
 */
export const PORT_FRIENDLY_DESCRIPTIONS: Record<string, string> = {
  '7': 'Echo / diagnostic',
  '9': 'Discard / diagnostic',
  '21': 'File transfer (FTP)',
  '22': 'Remote access (SSH)',
  '23': 'Remote terminal (Telnet)',
  '25': 'Email delivery (SMTP)',
  '53': 'DNS server',
  '67': 'DHCP server',
  '79': 'User info (Finger)',
  '80': 'Web interface / admin panel',
  '110': 'Email retrieval (POP3)',
  '111': 'Remote procedure call (RPC)',
  '113': 'Authentication (Ident)',
  '135': 'Windows RPC',
  '139': 'NetBIOS session',
  '143': 'Email (IMAP)',
  '161': 'Network management (SNMP)',
  '389': 'Directory (LDAP)',
  '443': 'Secure web (HTTPS)',
  '445': 'File sharing (SMB)',
  '465': 'Secure SMTP',
  '515': 'Printing (LPD)',
  '548': 'Apple file sharing (AFP)',
  '554': 'Media streaming (RTSP)',
  '587': 'Email submission',
  '631': 'Printing (IPP)',
  '873': 'File sync (Rsync)',
  '993': 'Secure IMAP',
  '995': 'Secure POP3',
  '2049': 'Network filesystem (NFS)',
  '3306': 'MySQL database',
  '3389': 'Remote desktop (RDP)',
  '5000': 'UPnP / Synology admin',
  '5357': 'Device discovery (WS-Discovery)',
  '5432': 'PostgreSQL database',
  '5800': 'VNC over HTTP',
  '5900': 'Remote desktop (VNC)',
  '8000': 'HTTP alternative',
  '8080': 'HTTP proxy / alt',
  '8443': 'HTTPS alternative',
  '9100': 'Network printing (JetDirect)',
}

/**
 * Returns enhanced tooltip for a port chip: "80 / HTTP — Web interface"
 */
export function getChipTitle(port: string, service: string): string {
  const friendly = PORT_FRIENDLY_DESCRIPTIONS[port]
  if (friendly) {
    return `${port} / ${service} — ${friendly}`
  }
  return `${port} / ${service}`
}

/**
 * Infer device type from open ports and optional gateway IP.
 */
export function inferDeviceType(
  device: Device,
  defaultGateway?: string | null
): DeviceType {
  const ports = new Set(Object.keys(device.open_ports).map(Number))
  const has = (...p: number[]) => p.some((port) => ports.has(port))
  const mfr = (device.manufacturer || '').toLowerCase()

  if (defaultGateway && device.ip === defaultGateway) {
    return 'router'
  }

  // Router: DNS + DHCP, or DNS + HTTP, or HTTP + HTTPS
  if (
    (has(53) && has(67)) ||
    (has(53) && has(80)) ||
    (has(80) && has(443))
  ) {
    return 'router'
  }

  // Printer
  if (has(515) || has(631) || has(9100) || (has(80) && has(631))) {
    return 'printer'
  }

  // Computer: SSH, RDP, Windows file sharing, or Mac (AFP/VNC/AirPlay) — check before NAS
  if (has(22) || (has(135) && has(445)) || has(3389)) {
    return 'computer'
  }
  // Mac / computer: AFP, VNC, or Apple/Mac hostname + file-sharing ports
  if (has(548) || has(5900)) {
    return 'computer' // AFP or VNC = almost always a computer
  }
  const host = (device.hostname || '').toLowerCase()
  const looksLikeMac = mfr.includes('apple') || /macbook|imac|mac\s*mini|mac\s*pro/.test(host)
  if (looksLikeMac && (has(445) || has(5000) || has(2049))) {
    return 'computer'
  }

  // NAS: SMB + NFS, or Synology (5000), or NFS
  if ((has(445) && has(2049)) || has(5000) || has(2049)) {
    return 'nas'
  }

  // IoT / smart device: few ports, common IoT manufacturers
  const iotHints = ['google', 'sonos', 'philips', 'hue', 'apple', 'amazon', 'samsung', 'roku', 'chromecast']
  if (iotHints.some((h) => mfr.includes(h)) && (has(80) || has(443) || has(5353))) {
    return 'iot'
  }
  if (ports.size <= 3 && (has(80) || has(443) || has(5353))) {
    return 'iot'
  }

  return 'other'
}
