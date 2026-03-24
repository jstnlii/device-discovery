from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

from networking import normalize_subnet_input


ScanState = Literal["queued", "running", "completed", "failed", "cancelled"]


class StartScanRequest(BaseModel):
    subnet: str = Field(
        ...,
        description="Subnet input. Accepts CIDR (e.g. 10.0.0.0/24) or an IP (e.g. 10.0.0.187) which is converted using detected local networks.",
    )
    skip_ping_sweep: bool = Field(
        default=False,
        description="If true, skips ICMP ping discovery and scans the whole CIDR instead (useful when ICMP is blocked).",
    )

    @field_validator("subnet")
    @classmethod
    def validate_subnet(cls, v: str) -> str:
        return normalize_subnet_input(v)


class StartScanResponse(BaseModel):
    scan_id: str


class ScanProgress(BaseModel):
    message: Optional[str] = None
    hosts_found: Optional[int] = None
    devices_scanned: int = 0
    total_devices: Optional[int] = None
    current_ip: Optional[str] = None


class ScanStatus(BaseModel):
    scan_id: str
    state: ScanState
    created_at: str
    updated_at: str
    progress: ScanProgress = Field(default_factory=ScanProgress)
    error: Optional[str] = None


class ScanSummary(BaseModel):
    scan_id: str
    state: ScanState
    scan_time: Optional[str] = None
    hosts_found: Optional[int] = None
    updated_at: str


class InventoryResponse(BaseModel):
    scan_metadata: Dict[str, Any]
    devices: List[Dict[str, Any]]
    default_gateway: Optional[str] = None


class GetScanResponse(BaseModel):
    scan: ScanStatus
    inventory: Optional[InventoryResponse] = None

