"""Detector registry: the full B7 catalogue in one place.

`all_detectors()` returns one fresh instance of each detector class. Fresh
instances are cheap (detectors are stateless -- all mutable tunable/enabled
state lives in the engine/store, not on the detector object) and it keeps
tests from accidentally sharing state across engine instances.
"""
from __future__ import annotations

from .anomaly import NewExternalPeerDetector, NonstandardPortServiceDetector, ProtocolAnomalyDetector
from .base import Detector, Finding
from .c2 import C2BeaconingDetector
from .credentials import CredentialsPlaintextDetector
from .dns import DgaDomainsDetector, DnsTunnelingDetector
from .exfil import DataExfiltrationDetector, DnsExfilVolumeDetector, OffHoursTransferDetector
from .lateral import LateralSmbRdpDetector
from .peers import CryptoMiningDetector, KnownBadPeerDetector, TorOrProxyDetector
from .policy import DeprecatedProtocolDetector
from .recon import HostSweepDetector, PortScanInboundDetector, PortScanOutboundDetector
from .spoofing import ArpSpoofingDetector, MacFlappingDetector, RogueDhcpDetector
from .tls import SuspiciousTlsDetector

DETECTOR_CLASSES: list[type[Detector]] = [
    C2BeaconingDetector,
    DnsTunnelingDetector,
    DgaDomainsDetector,
    DnsExfilVolumeDetector,
    DataExfiltrationDetector,
    OffHoursTransferDetector,
    PortScanOutboundDetector,
    PortScanInboundDetector,
    HostSweepDetector,
    ArpSpoofingDetector,
    MacFlappingDetector,
    RogueDhcpDetector,
    LateralSmbRdpDetector,
    CredentialsPlaintextDetector,
    KnownBadPeerDetector,
    TorOrProxyDetector,
    CryptoMiningDetector,
    SuspiciousTlsDetector,
    NonstandardPortServiceDetector,
    NewExternalPeerDetector,
    ProtocolAnomalyDetector,
    DeprecatedProtocolDetector,
]


def all_detectors() -> list[Detector]:
    return [cls() for cls in DETECTOR_CLASSES]


__all__ = ["Detector", "Finding", "DETECTOR_CLASSES", "all_detectors"]
