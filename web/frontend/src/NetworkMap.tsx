import { motion } from "framer-motion";
import {
  inferDeviceType,
  type Device,
  type DeviceType,
} from "./deviceUtils";
import type { InventoryResponse } from "./types";

function deviceOpenPortsSummary(open_ports: Record<string, string>): string {
  const entries = Object.entries(open_ports ?? {});
  if (entries.length === 0) return "No open ports";
  return entries
    .slice(0, 5)
    .map(([p, s]) => `${p}/${s}`)
    .join(", ") + (entries.length > 5 ? "…" : "");
}

function getDisplayName(d: Device): string {
  if (d.hostname && d.hostname !== "unknown") return d.hostname;
  const octet = d.ip.split(".").pop();
  return `Device .${octet}`;
}

export function NetworkMap({
  inventory,
  defaultGateway,
}: {
  inventory: InventoryResponse;
  defaultGateway: string | null;
}) {
  const devices = inventory.devices;
  if (devices.length === 0) return null;

  const gw = defaultGateway ?? undefined;
  const centerDevice =
    devices.find((d) => d.ip === gw) ??
    devices.find((d) => inferDeviceType(d as Device, gw) === "router") ??
    devices[0];
  const satellites = devices.filter((d) => d.ip !== centerDevice!.ip);

  const cx = 50;
  const cy = 50;
  const radius = Math.min(38, 25 + satellites.length * 2);
  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: { staggerChildren: 0.05, delayChildren: 0.05 },
    },
  };
  return (
    <div className="network-map">
      <div className="network-map-container">
        <svg
          className="network-map-svg"
          viewBox="0 0 100 100"
          preserveAspectRatio="xMidYMid meet"
        >
          {satellites.map((d, i) => {
            const angle = (i / satellites.length) * 2 * Math.PI - Math.PI / 2;
            const x = cx + radius * Math.cos(angle);
            const y = cy + radius * Math.sin(angle);
            return (
              <line
                key={`edge-${d.ip}`}
                x1={cx}
                y1={cy}
                x2={x}
                y2={y}
                className="network-map-edge"
                stroke="var(--border)"
                strokeWidth="0.3"
                opacity="0.5"
              />
            );
          })}
        </svg>
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="network-map-nodes"
        >
          <MapNode
            device={centerDevice as Device}
            defaultGateway={gw}
            cx={cx}
            cy={cy}
            isCenter
          />
          {satellites.map((d, i) => {
            const angle = (i / satellites.length) * 2 * Math.PI - Math.PI / 2;
            const x = cx + radius * Math.cos(angle);
            const y = cy + radius * Math.sin(angle);
            return (
              <MapNode
                key={d.ip}
                device={d as Device}
                defaultGateway={gw}
                cx={x}
                cy={y}
              />
            );
          })}
        </motion.div>
      </div>
    </div>
  );
}

const nodeVariants = {
  hidden: { opacity: 0, scale: 0.8 },
  visible: { opacity: 1, scale: 1 },
};

function MapNode({
  device,
  defaultGateway,
  cx,
  cy,
  isCenter = false,
}: {
  device: Device;
  defaultGateway?: string;
  cx: number;
  cy: number;
  isCenter?: boolean;
}) {
  const type = inferDeviceType(device, defaultGateway);
  const displayName = getDisplayName(device);
  const tooltip = [
    displayName,
    device.ip,
    device.manufacturer && device.manufacturer !== "unknown"
      ? device.manufacturer
      : null,
    deviceOpenPortsSummary(device.open_ports),
  ]
    .filter(Boolean)
    .join(" • ");

  return (
    <motion.div
      className={`network-map-node ${isCenter ? "center" : ""} type-${type}`}
      style={{
        position: "absolute",
        left: `${cx}%`,
        top: `${cy}%`,
        transform: "translate(-50%, -50%)",
      }}
      variants={nodeVariants}
      whileHover={{
        scale: 1.08,
        rotate: [0, -2, 2, -1, 0],
        transition: { duration: 0.35 },
      }}
      title={tooltip}
    >
      <span className="network-map-node-icon" aria-hidden>
        {getIcon(type)}
      </span>
      <span className="network-map-node-name">{displayName}</span>
      <span className="network-map-node-ip mono">{device.ip}</span>
    </motion.div>
  );
}

function getIcon(type: DeviceType): string {
  switch (type) {
    case "router":
      return "⊕";
    case "computer":
      return "◫";
    case "printer":
      return "⎙";
    case "nas":
      return "▣";
    case "iot":
      return "◉";
    default:
      return "○";
  }
}
