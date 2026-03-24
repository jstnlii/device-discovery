import { useCallback, useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import {
  inferDeviceType,
  type Device,
  type DeviceType,
} from "./deviceUtils";
import type { InventoryResponse } from "./types";

/** Fixed order: 6 device types, each maps to a specific zone. */
const ZONE_TYPES: DeviceType[] = [
  "computer",  // left top
  "printer",   // left middle
  "nas",       // left bottom
  "iot",       // right top
  "router",    // right middle (routers other than gateway)
  "other",     // right bottom
];

const ROWS = 2;
const CELL_W = 14;
const CELL_H = 9;
const GAP = 5;
const LABEL_H = 1;
const LABEL_GAP = 0;
const BUBBLE_PAD = 6;
const VIEW = 100;
const CENTER = VIEW / 2;
const SPINE_LENGTH = 22; // horizontal distance from center to each side (left/right edges equal)
const LEFT_EDGE = CENTER - SPINE_LENGTH;
const RIGHT_EDGE = CENTER + SPINE_LENGTH;

/** Fixed zone positions: (y, side). Left zones extend left from LEFT_EDGE; right zones extend right from RIGHT_EDGE. */
const ZONES: { y: number; side: "left" | "right" }[] = [
  { y: 8, side: "left" },
  { y: 50, side: "left" },
  { y: 92, side: "left" },
  { y: 8, side: "right" },
  { y: 50, side: "right" },
  { y: 92, side: "right" },
];

function getDisplayName(d: Device): string {
  if (d.hostname && d.hostname !== "unknown") return d.hostname;
  const octet = d.ip.split(".").pop();
  return `Device .${octet}`;
}

function getIcon(type: DeviceType): string {
  switch (type) {
    case "router": return "⊕";
    case "computer": return "◫";
    case "printer": return "⎙";
    case "nas": return "▣";
    case "iot": return "◉";
    default: return "○";
  }
}

function typeLabel(type: DeviceType): string {
  return type.charAt(0).toUpperCase() + type.slice(1);
}

type ZoneGroup = {
  type: DeviceType;
  devices: Device[];
  side: "left" | "right";
  y: number;
  width: number;
  height: number;
  left: number;
  top: number;
  devicePositions: { device: Device; x: number; y: number }[];
};

function layoutZones(
  satellites: Device[],
  defaultGateway: string | undefined
): { groups: ZoneGroup[]; centerX: number; centerY: number } {
  const byType = new Map<DeviceType, Device[]>();
  for (const t of ZONE_TYPES) byType.set(t, []);

  for (const d of satellites) {
    const t = inferDeviceType(d, defaultGateway);
    if (byType.has(t)) byType.get(t)!.push(d);
  }

  const groups: ZoneGroup[] = [];

  for (let i = 0; i < ZONE_TYPES.length; i++) {
    const type = ZONE_TYPES[i];
    const devices = byType.get(type)!;
    const zone = ZONES[i];

    const count = Math.max(devices.length, 1);
    const cols = Math.ceil(count / ROWS);
    const contentW = cols * (CELL_W + GAP) - GAP;
    const contentH = ROWS * (CELL_H + GAP) - GAP;
    const width = contentW + BUBBLE_PAD * 2 + CELL_W;
    const height = LABEL_H + LABEL_GAP + contentH + BUBBLE_PAD * 2;

    let left: number;
    if (zone.side === "left") {
      left = LEFT_EDGE - width;
    } else {
      left = RIGHT_EDGE;
    }
    const top = zone.y - height / 2;

    const devicePositions: { device: Device; x: number; y: number }[] = [];
    devices.forEach((d, j) => {
      const row = Math.floor(j / cols);
      const col = j % cols;
      const x = left + BUBBLE_PAD + col * (CELL_W + GAP) + CELL_W / 2;
      const y = top + LABEL_H + LABEL_GAP + row * (CELL_H + GAP) + CELL_H / 2;
      devicePositions.push({ device: d, x, y });
    });

    groups.push({
      type,
      devices,
      side: zone.side,
      y: zone.y,
      width,
      height,
      left,
      top,
      devicePositions,
    });
  }

  return { groups, centerX: CENTER, centerY: CENTER };
}

function deviceTooltip(d: Device): string {
  const name = getDisplayName(d);
  const parts = [name, d.ip];
  if (d.manufacturer && d.manufacturer !== "unknown") parts.push(d.manufacturer);
  const ports = Object.entries(d.open_ports ?? {}).slice(0, 5);
  if (ports.length) parts.push(ports.map(([p]) => p).join(", "));
  return parts.join(" • ");
}

const BEND_OFFSET = 16; // horizontal distance from center before vertical segment (for top/bottom boxes)
const PAN_PADDING = 80; // min pixels of map visible from each edge; limits how far you can pan

function edgePath(
  cx: number,
  cy: number,
  zoneSide: "left" | "right",
  zoneY: number
): string {
  const isDirect = zoneY === cy;
  if (isDirect) {
    const endX = zoneSide === "left" ? LEFT_EDGE : RIGHT_EDGE;
    return `M ${cx} ${cy} H ${endX}`;
  }
  const bendX = zoneSide === "left" ? cx - BEND_OFFSET : cx + BEND_OFFSET;
  const endX = zoneSide === "left" ? LEFT_EDGE : RIGHT_EDGE;
  return `M ${cx} ${cy} H ${bendX} V ${zoneY} H ${endX}`;
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

  const layout = layoutZones(satellites as Device[], gw);
  const { groups, centerX, centerY } = layout;

  const [zoom, setZoom] = useState(0.9);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const containerRef = useRef<HTMLDivElement>(null);
  const isPanning = useRef(false);
  const lastMouse = useRef({ x: 0, y: 0 });
  const zoomPanRef = useRef({ zoom: 0.9, pan: { x: 0, y: 0 } });
  zoomPanRef.current = { zoom, pan };

  const clampPan = useCallback(
    (p: { x: number; y: number }, z: number) => {
      const rect = containerRef.current?.getBoundingClientRect();
      if (!rect) return p;
      const maxX = Math.max(0, (rect.width * (1 + z)) / 2 - PAN_PADDING);
      const maxY = Math.max(0, (rect.height * (1 + z)) / 2 - PAN_PADDING);
      return {
        x: Math.max(-maxX, Math.min(maxX, p.x)),
        y: Math.max(-maxY, Math.min(maxY, p.y)),
      };
    },
    []
  );

  const handleWheel = useCallback(
    (e: WheelEvent) => {
      e.preventDefault();
      const rect = containerRef.current?.getBoundingClientRect();
      if (!rect) return;
      const cx = rect.width / 2;
      const cy = rect.height / 2;
      const mx = e.clientX - rect.left - cx;
      const my = e.clientY - rect.top - cy;
      const delta = e.deltaY > 0 ? -0.03 : 0.03;

      const { zoom: z, pan: p } = zoomPanRef.current;
      const newZoom = Math.max(0.3, Math.min(1.5, z + delta));
      const scaleFactor = newZoom / z;
      const newPan = clampPan(
        {
          x: mx - (mx - p.x) * scaleFactor,
          y: my - (my - p.y) * scaleFactor,
        },
        newZoom
      );
      setPan(newPan);
      setZoom(newZoom);
    },
    [clampPan]
  );

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    el.addEventListener("wheel", handleWheel, { passive: false });
    return () => el.removeEventListener("wheel", handleWheel);
  }, [handleWheel]);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button !== 0) return;
    isPanning.current = true;
    lastMouse.current = { x: e.clientX, y: e.clientY };
  }, []);

  const handleMouseMove = useCallback(
    (e: React.MouseEvent) => {
      if (!isPanning.current) return;
      const dx = e.clientX - lastMouse.current.x;
      const dy = e.clientY - lastMouse.current.y;
      lastMouse.current = { x: e.clientX, y: e.clientY };
      setPan((p) => clampPan({ x: p.x + dx, y: p.y + dy }, zoom));
    },
    [clampPan, zoom]
  );

  const handleMouseUp = useCallback(() => { isPanning.current = false; }, []);
  const handleMouseLeave = useCallback(() => { isPanning.current = false; }, []);

  useEffect(() => {
    const onUp = () => { isPanning.current = false; };
    window.addEventListener("mouseup", onUp);
    return () => window.removeEventListener("mouseup", onUp);
  }, []);

  return (
    <div className="network-map">
      <div
        ref={containerRef}
        className="network-map-viewport"
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseLeave}
      >
        <div
          className="network-map-pan-zoom"
          style={{ transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})` }}
        >
          <div className="network-map-inner">
            <svg
              className="network-map-svg"
              viewBox={`0 0 ${VIEW} ${VIEW}`}
              preserveAspectRatio="xMidYMid meet"
            >
              {groups.map((g) => (
                <path
                  key={g.type}
                  d={edgePath(centerX, centerY, g.side, g.y)}
                  className="network-map-edge"
                />
              ))}
            </svg>

            <motion.div
              className="network-map-node network-map-center"
              style={{
                left: `${(centerX / VIEW) * 100}%`,
                top: `${(centerY / VIEW) * 100}%`,
              }}
              initial={{ opacity: 0, scale: 0.8, x: "-50%", y: "-50%" }}
              animate={{ opacity: 1, scale: 1, x: "-50%", y: "-50%" }}
              transition={{ duration: 0.2 }}
              title={deviceTooltip(centerDevice as Device)}
            >
              <span className="network-map-node-icon">⊕</span>
              <span className="network-map-node-name">{getDisplayName(centerDevice as Device)}</span>
              <span className="network-map-node-ip mono">{centerDevice!.ip}</span>
              <span className="network-map-node-badge">default gateway</span>
            </motion.div>

            {groups.map((g) => (
              <motion.div
                key={g.type}
                className={`network-map-bubble network-map-bubble-${g.side}`}
                style={{
                  left: `${(g.left / VIEW) * 100}%`,
                  top: `${(g.top / VIEW) * 100}%`,
                  width: `${(g.width / VIEW) * 100}%`,
                  height: `${(g.height / VIEW) * 100}%`,
                }}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.2, delay: 0.03 }}
              >
                <div className="network-map-bubble-label">{typeLabel(g.type)}</div>
                <div className="network-map-bubble-devices">
                  {g.devices.length === 0 ? (
                    <div className="network-map-bubble-empty">No devices</div>
                  ) : (
                    g.devicePositions.map(({ device, x, y }) => {
                      const leftPct = ((x - g.left) / g.width) * 100;
                      const topPct = ((y - g.top) / g.height) * 100;
                      return (
                        <motion.div
                          key={device.ip}
                          className={`network-map-node type-${g.type}`}
                          style={{
                            position: "absolute",
                            left: `${leftPct}%`,
                            top: `${topPct}%`,
                            transform: "translate(-50%, -50%)",
                          }}
                          initial={{ opacity: 0, scale: 0.9 }}
                          animate={{ opacity: 1, scale: 1 }}
                          transition={{ duration: 0.12 }}
                          whileHover={{ scale: 1.08 }}
                          title={deviceTooltip(device)}
                        >
                          <span className="network-map-node-icon">{getIcon(g.type)}</span>
                          <span className="network-map-node-name">{getDisplayName(device)}</span>
                          <span className="network-map-node-ip mono">{device.ip}</span>
                        </motion.div>
                      );
                    })
                  )}
                </div>
              </motion.div>
            ))}
          </div>
        </div>

        <div className="network-map-legend">
          <div className="network-map-legend-title">Device types</div>
          {ZONE_TYPES.map((type) => (
            <div key={type} className="network-map-legend-item">
              <span className="network-map-legend-icon">{getIcon(type)}</span>
              <span className="network-map-legend-label">{typeLabel(type)}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="network-map-hint">Scroll to zoom · Drag to pan</div>
    </div>
  );
}
