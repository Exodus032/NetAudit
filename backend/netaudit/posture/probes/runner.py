"""THE ONLY PLACE in this package that spawns a subprocess.

Every other probe module (powershell.py, netprobe.py) and every check must
route command execution through `run_command()` here. `run_command()` never
builds a command string -- it accepts a pre-built, fixed argument list
(`Sequence[str]`) and passes it straight to `subprocess.run(..., shell=False)`.
No f-strings, no `%` formatting, no `.format()`, no string concatenation of
caller-supplied values ever happens on the way to a command in this codebase.

Read-only guarantee: this module has no notion of "write" -- it just runs
whatever argv it is given. The read-only guarantee comes from the *callers*
(powershell.py's ALLOWLIST, netprobe.py) only ever handing it argv lists for
`Get-*` / `show` / query commands. See test_allowlist_safety.py, which walks
every allowlisted command and asserts none of them contain a write verb or a
shell metacharacter / format placeholder.
"""
from __future__ import annotations

import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, Optional, Sequence

DEFAULT_TIMEOUT_SECONDS = 5.0

# On Windows, avoid flashing a console window when spawned from a GUI/service
# context. Harmless no-op on other platforms (tests run cross-platform).
_CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


@dataclass
class CommandResult:
    ok: bool
    stdout: str = ""
    stderr: str = ""
    returncode: Optional[int] = None
    error: Optional[str] = None
    duration_ms: int = 0


@dataclass
class ProbeResult:
    """The uniform result shape every probe module (powershell.py,
    registry_probe.py, netprobe.py) hands back to a Check. Checks are
    unit-tested by constructing this directly -- `ProbeResult(ok=True,
    data=...)` for the pass/fail cases, `ProbeResult(ok=False, error=...)`
    for the error case -- with no subprocess or registry access involved."""

    ok: bool
    data: Any = None
    error: Optional[str] = None
    raw_stdout: str = ""


def run_command(argv: Sequence[str], timeout: float = DEFAULT_TIMEOUT_SECONDS) -> CommandResult:
    """Run a fixed, hardcoded argument list. Never pass anything derived from
    HTTP input or free-form user text here -- see module docstring."""
    argv = list(argv)
    start = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            creationflags=_CREATE_NO_WINDOW,
        )
        duration_ms = int((time.monotonic() - start) * 1000)
        ok = proc.returncode == 0
        error = None if ok else (proc.stderr.strip() or f"command exited with code {proc.returncode}")
        return CommandResult(ok=ok, stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode, error=error, duration_ms=duration_ms)
    except subprocess.TimeoutExpired:
        duration_ms = int((time.monotonic() - start) * 1000)
        return CommandResult(ok=False, error=f"timed out after {timeout:g}s", duration_ms=duration_ms)
    except FileNotFoundError as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        return CommandResult(ok=False, error=f"command not found: {exc}", duration_ms=duration_ms)
    except OSError as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        return CommandResult(ok=False, error=f"failed to run command: {exc}", duration_ms=duration_ms)


def is_admin() -> bool:
    """Cheap elevation check. Never raises -- returns False if it can't tell
    (e.g. not on Windows, or the ctypes call itself fails)."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
