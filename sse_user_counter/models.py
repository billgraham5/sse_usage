from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Product(str, Enum):
    UMBRELLA = "umbrella"
    SECURE_ACCESS = "secure-access"

    @property
    def display_name(self) -> str:
        return {
            Product.UMBRELLA: "Cisco Umbrella",
            Product.SECURE_ACCESS: "Cisco Secure Access",
        }[self]

    @property
    def supports_vpn(self) -> bool:
        return self is Product.SECURE_ACCESS

    @property
    def supports_ztna(self) -> bool:
        return self is Product.SECURE_ACCESS


@dataclass(frozen=True)
class Credentials:
    api_key: str
    api_secret: str
    org_id: str = ""


@dataclass(frozen=True)
class RunConfig:
    product: Product
    output_dir: Path
    reporting_region: str = "auto"
    swg_correlate_identities: bool = True
    swg_correlation_days: int = 30
    vpn_days: int = 60
    page_limit: int = 1000
    reporting_offset_max: int = 10000
    remote_access_window_limit: int = 5000
    min_remote_access_window_minutes: int = 5


@dataclass(frozen=True)
class RoamingComputer:
    device_id: str
    computer_name: str
    swg_status: str = ""
    status: str = ""
    last_sync: str = ""


@dataclass(frozen=True)
class ServiceRow:
    user_name: str
    computer_name: str
    service_type: str
    source_product: str
    device_id: str = ""
    first_seen: str = ""
    last_seen: str = ""
    event_count: int = 0
    notes: str = ""


@dataclass
class ServiceReport:
    service_type: str
    supported: bool
    primary_count: int = 0
    unique_users: int = 0
    rows: list[ServiceRow] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
