from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


ScanState = Literal["queued", "running", "completed", "failed", "cancelled"]


class StartScanRequest(BaseModel):
    subnet: str = Field(..., description="IPv4 CIDR, e.g. 10.0.0.0/24")

    @field_validator("subnet")
    @classmethod
    def validate_subnet(cls, v: str) -> str:
        try:
            net = ipaddress.IPv4Network(v, strict=False)
        except Exception as e:
            raise ValueError(f"Invalid IPv4 CIDR: {v}") from e
        return str(net)


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


class GetScanResponse(BaseModel):
    scan: ScanStatus
    inventory: Optional[InventoryResponse] = None

