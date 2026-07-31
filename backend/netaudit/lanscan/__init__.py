"""Active LAN scan (Part E7 of docs/API_CONTRACT_V3.md). The only feature
in this task that sends traffic to other machines -- see README.md for
every constraint and where it's enforced.
"""
from __future__ import annotations

from .models import HostResult, ScanJob, ScanProgress, ScanRequest
from .providers import InterfaceProvider, PortConnector, RealPortConnector, get_interface_provider, get_port_connector
from .router import router
from .service import CONSENT_NOTICE, LanScanService, ScanAlreadyRunning, get_lanscan_service
from .validation import ScanValidationError

__all__ = [
    "router",
    "LanScanService",
    "get_lanscan_service",
    "ScanAlreadyRunning",
    "ScanValidationError",
    "InterfaceProvider",
    "PortConnector",
    "RealPortConnector",
    "get_interface_provider",
    "get_port_connector",
    "ScanRequest",
    "ScanJob",
    "ScanProgress",
    "HostResult",
    "CONSENT_NOTICE",
]
