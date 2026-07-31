"""Grep-based tests for the package's read-only guarantee.

Two different things are checked here, deliberately scoped differently:

1. `probes/` (the only code that ever executes a command or touches the
   registry) must contain no write-verb PowerShell cmdlet, no
   `netsh ... set`, no `reg add`/`reg delete`, and no `winreg` write API call
   anywhere in its own source.
2. The *whole* package must contain no `winreg` write API call, and
   `subprocess`/`os.system`-style execution must appear only in
   `probes/runner.py` -- the single execution point the spec requires.

`checks/*.py` is deliberately excluded from the write-verb-cmdlet grep: each
check's `Remediation.commands[].command` field is advisory text for the user
to copy and run themselves (e.g. "Set-NetFirewallProfile ... -Enabled True")
-- that's the whole point of the read-only design (Part A: "the backend does
not run it"). Those strings are Python string literals, never passed to
`subprocess` or any execution API, which is exactly what test 2 below
verifies package-wide.
"""
from __future__ import annotations

import re
from pathlib import Path

POSTURE_ROOT = Path(__file__).resolve().parents[2] / "netaudit" / "posture"
PROBES_ROOT = POSTURE_ROOT / "probes"

_WRITE_VERB_PATTERN = re.compile(
    r"\b(Set|New|Remove|Disable|Enable|Add|Clear|Start|Stop|Restart|Rename|Copy|Move|Install|Uninstall)-\w+",
    re.IGNORECASE,
)
_NETSH_SET_PATTERN = re.compile(r"netsh(\.exe)?\s+\S+\s+set\b", re.IGNORECASE)
_REG_WRITE_PATTERN = re.compile(r"\breg(\.exe)?\s+(add|delete)\b", re.IGNORECASE)
_WINREG_WRITE_PATTERN = re.compile(
    r"winreg\.(SetValue(Ex)?|CreateKey(Ex)?|DeleteKey(Ex)?|DeleteValue)\s*\("
)
_EXECUTION_API_PATTERN = re.compile(r"\b(subprocess\.(run|Popen|call|check_call|check_output)|os\.system|os\.popen)\s*\(")


def _all_py_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.py"))


_TRIPLE_QUOTED_PATTERN = re.compile(r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'')


def _strip_docstrings(text: str) -> str:
    """Module/class/function docstrings in this package legitimately *talk
    about* write-verb cmdlets and `netsh ... set` (to explain what must never
    appear in real code) -- strip triple-quoted spans before grepping so
    those descriptions don't self-trigger the check. Every real command
    string in this package uses single-line quoting, never triple quotes."""
    return _TRIPLE_QUOTED_PATTERN.sub("", text)


def test_probes_package_has_no_write_verb_cmdlets():
    for path in _all_py_files(PROBES_ROOT):
        text = _strip_docstrings(path.read_text(encoding="utf-8"))
        match = _WRITE_VERB_PATTERN.search(text)
        assert match is None, f"{path}: found a write-verb cmdlet: {match.group(0)!r}"
        match = _NETSH_SET_PATTERN.search(text)
        assert match is None, f"{path}: found a netsh 'set' command: {match.group(0)!r}"
        match = _REG_WRITE_PATTERN.search(text)
        assert match is None, f"{path}: found a registry write via reg.exe: {match.group(0)!r}"


def test_no_winreg_write_call_anywhere_in_the_package():
    for path in _all_py_files(POSTURE_ROOT):
        text = path.read_text(encoding="utf-8")
        match = _WINREG_WRITE_PATTERN.search(text)
        assert match is None, f"{path}: found a winreg write call: {match.group(0)!r}"


def test_execution_apis_only_appear_in_runner_py():
    runner_path = PROBES_ROOT / "runner.py"
    assert runner_path.exists()
    offenders = []
    for path in _all_py_files(POSTURE_ROOT):
        if path == runner_path:
            continue
        text = path.read_text(encoding="utf-8")
        if _EXECUTION_API_PATTERN.search(text):
            offenders.append(str(path))
    assert not offenders, f"execution APIs (subprocess/os.system) found outside probes/runner.py: {offenders}"

    runner_text = runner_path.read_text(encoding="utf-8")
    assert _EXECUTION_API_PATTERN.search(runner_text), "runner.py should be the one place that does execute a command"


def test_checks_package_never_imports_execution_or_registry_apis_directly():
    """Checks must reach the OS only through `ProbeContext` -- never import
    `subprocess`, `winreg`, or `os.system` themselves."""
    checks_root = POSTURE_ROOT / "checks"
    banned_imports = re.compile(r"^\s*(import\s+(subprocess|winreg)\b|from\s+(subprocess|winreg)\s+import)", re.MULTILINE)
    for path in _all_py_files(checks_root):
        text = path.read_text(encoding="utf-8")
        match = banned_imports.search(text)
        assert match is None, f"{path}: checks must not import execution/registry APIs directly: {match.group(0)!r}"
