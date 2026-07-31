"""Probe layer: the only code in `posture/` that touches the OS.

`runner.py` is the single place that spawns a subprocess. `powershell.py`
wraps a fixed allowlist of read-only PowerShell/netsh invocations,
`registry_probe.py` wraps read-only `winreg` lookups, and `netprobe.py`
wraps `psutil`-based enumeration. Every function in this package returns a
`runner.ProbeResult` and never raises for expected failure modes (missing
admin rights, missing cmdlet, timeout) -- those become `ProbeResult(ok=False,
error=...)` instead.
"""
