"""Offline MITRE ATT&CK tactic/technique id -> name lookup.

Bundled, no network calls. This is a small hand-picked subset covering
exactly what the detector catalogue in API_CONTRACT_V2_SECURITY.md Part B7
needs, not a full ATT&CK mirror. Ids and names are taken from the public
ATT&CK Enterprise matrix; where a detector's behavior doesn't map cleanly
onto one specific technique, the detector deliberately ships a tactic-only
reference (technique=None) rather than inventing an id -- see the comments
in each `mitre_ref(...)` call site in detectors/*.py.
"""
from __future__ import annotations

from typing import Optional

from .models import MitreRef

TACTICS: dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0006": "Credential Access",
    "TA0005": "Defense Evasion",
    "TA0040": "Impact",
}

TECHNIQUES: dict[str, str] = {
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1071.004": "Application Layer Protocol: DNS",
    "T1568.002": "Dynamic Resolution: Domain Generation Algorithms",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1048.003": "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol",
    "T1029": "Scheduled Transfer",
    "T1046": "Network Service Discovery",
    "T1595.001": "Active Scanning: Scanning IP Blocks",
    "T1557.002": "Adversary-in-the-Middle: ARP Cache Poisoning",
    "T1557.003": "Adversary-in-the-Middle: DHCP Spoofing",
    "T1021": "Remote Services",
    "T1040": "Network Sniffing",
    "T1090.003": "Proxy: Multi-hop Proxy",
    "T1496": "Resource Hijacking",
    "T1573": "Encrypted Channel",
    "T1571": "Non-Standard Port",
}


def mitre_ref(tactic: str, technique: Optional[str] = None) -> MitreRef:
    """Build a MitreRef, resolving names from the bundled tables. Raises
    KeyError at import time (via detector module load) if a detector typos
    an id -- fail loud rather than ship a silently-wrong name."""
    tactic_name = TACTICS[tactic]
    technique_name = TECHNIQUES[technique] if technique else None
    return MitreRef(
        tactic=tactic,
        tactic_name=tactic_name,
        technique=technique,
        technique_name=technique_name,
    )
