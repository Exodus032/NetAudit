"""PCAP read/write, BPF capture filter, and import sessions (API Contract v3
Part E, sections E1-E4).

Exposes a bare `APIRouter` (`router`) with no side effects at import time
beyond module-level state for the active capture filter -- the orchestrator
wires it into the real app and can override dependencies for tests.
"""
from __future__ import annotations

from . import bpf, dissect, format, import_pipeline, live_query, session_store, synth
from .router import router

__all__ = [
    "router",
    "bpf",
    "dissect",
    "format",
    "import_pipeline",
    "live_query",
    "session_store",
    "synth",
]
