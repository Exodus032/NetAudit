"""Part C item 3 / the posture spec's "no shell string building" rule,
enforced against the actual allowlist rather than trusted by inspection.

What counts as unsafe here, and why:

- Every `powershell.ALLOWLIST` entry must be a `list[str]` (an argv), never
  a bare string -- a bare string would mean something upstream might be
  tempted to `shell=True` it or concatenate onto it.
- No entry may contain a write-verb cmdlet (`Set-`, `New-`, `Remove-`,
  `Disable-`, `Enable-`, `Add-`, `Clear-`, `Start-`, `Stop-`, `Restart-`,
  `Rename-`, `Copy-`, `Move-`, `Install-`, `Uninstall-`), `netsh ... set`,
  `reg add`, or `reg delete` -- this package must never be able to change
  system state no matter what a check does with the result.
- No entry may contain a Python-style format placeholder (`{0}`, `{1}`,
  `%s`, `%d`, `%r`) -- that pattern would mean the string was built to have
  a runtime value slotted in later, which is exactly what this package must
  never do.
- No entry may contain `&&`, `||`, or a backtick-escaped `$(` used as a
  *shell* chaining/substitution idiom. We deliberately do NOT ban PowerShell's
  own `$( ... )` subexpression operator or `@{ }` hashtable/scriptblock
  literals -- those are ordinary PowerShell syntax this package's own fixed
  scripts use internally (e.g. `$(if (...) {...} else {...})`), and since
  `subprocess.run(..., shell=False)` never hands these strings to a shell,
  they can't be abused as shell metacharacters regardless.
- The Python source of `powershell.py` itself must contain no f-string
  prefix, `.format(` call, or `%`-style string formatting -- the proof that
  nothing is ever assembled from a runtime value.
"""
from __future__ import annotations

import inspect
import re

from netaudit.posture.probes import netprobe, powershell

_WRITE_VERB_PATTERN = re.compile(
    r"\b(Set|New|Remove|Disable|Enable|Add|Clear|Start|Stop|Restart|Rename|Copy|Move|Install|Uninstall)-\w+",
    re.IGNORECASE,
)
_NETSH_SET_PATTERN = re.compile(r"netsh(\.exe)?\s+\S+\s+set\b", re.IGNORECASE)
_REG_WRITE_PATTERN = re.compile(r"\breg(\.exe)?\s+(add|delete)\b", re.IGNORECASE)
_FORMAT_PLACEHOLDER_PATTERN = re.compile(r"\{\d+\}|%s|%d|%r")
_SHELL_CHAIN_PATTERN = re.compile(r"&&|\|\|")


def test_every_allowlist_entry_is_an_argv_list():
    for key, argv in powershell.ALLOWLIST.items():
        assert isinstance(argv, list), f"{key!r} is not a list[str] (argv)"
        assert argv, f"{key!r} is an empty argv"
        for element in argv:
            assert isinstance(element, str), f"{key!r} contains a non-str argv element: {element!r}"


def test_first_argv_element_is_a_known_executable():
    allowed_executables = {"powershell.exe", "netsh.exe"}
    for key, argv in powershell.ALLOWLIST.items():
        assert argv[0].lower() in allowed_executables, f"{key!r} invokes an unexpected executable: {argv[0]!r}"


def test_no_write_verb_cmdlets_in_any_allowlisted_command():
    for key, argv in powershell.ALLOWLIST.items():
        full_command = " ".join(argv)
        match = _WRITE_VERB_PATTERN.search(full_command)
        assert match is None, f"{key!r} contains a write-verb cmdlet: {match.group(0)!r}"
        match = _NETSH_SET_PATTERN.search(full_command)
        assert match is None, f"{key!r} contains a netsh 'set' command: {match.group(0)!r}"
        match = _REG_WRITE_PATTERN.search(full_command)
        assert match is None, f"{key!r} contains a registry write via reg.exe: {match.group(0)!r}"


def test_no_format_placeholders_in_any_allowlisted_command():
    for key, argv in powershell.ALLOWLIST.items():
        full_command = " ".join(argv)
        match = _FORMAT_PLACEHOLDER_PATTERN.search(full_command)
        assert match is None, f"{key!r} contains a format placeholder: {match.group(0)!r}"


def test_no_shell_chaining_metacharacters_in_any_allowlisted_command():
    for key, argv in powershell.ALLOWLIST.items():
        full_command = " ".join(argv)
        match = _SHELL_CHAIN_PATTERN.search(full_command)
        assert match is None, f"{key!r} contains a shell chaining operator: {match.group(0)!r}"


def _allowlist_source_block() -> str:
    """The source text of just the `ALLOWLIST = {...}` assignment -- not the
    whole module (which also has ordinary f-strings in *error messages*
    like `run_ps()`'s "unknown probe key" -- those aren't commands and are
    fine; what must never happen is the *command* text itself being built
    from a runtime value)."""
    import ast

    source = inspect.getsource(powershell)
    tree = ast.parse(source)
    for node in ast.walk(tree):
        # ALLOWLIST is declared with a type annotation (`ALLOWLIST: dict[...] = {...}`),
        # which parses as ast.AnnAssign, not ast.Assign.
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "ALLOWLIST" for t in node.targets):
            segment = ast.get_source_segment(source, node)
            assert segment is not None
            return segment
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "ALLOWLIST":
            segment = ast.get_source_segment(source, node)
            assert segment is not None
            return segment
    raise AssertionError("could not locate the ALLOWLIST assignment in powershell.py")


def test_allowlist_assignment_never_builds_commands_with_string_formatting():
    block = _allowlist_source_block()
    # No f-strings feeding a command (every ALLOWLIST value is a plain
    # double/single-quoted string literal, or a call to `_ps()` wrapping one).
    assert 'f"' not in block and "f'" not in block, "the ALLOWLIST literal must not use f-strings"
    assert ".format(" not in block, "the ALLOWLIST literal must not use str.format()"
    # A bare '%' used as the string-formatting operator, e.g. "...%s..." % x.
    assert not re.search(r'["\']\s*%\s*\(', block), "the ALLOWLIST literal must not use %-style string formatting"


def test_netprobe_allowlist_only_exposes_read_only_enumeration():
    # netprobe doesn't shell out at all (it calls psutil directly), but it
    # still follows the same allowlist-by-name shape as powershell.py --
    # confirm every entry is a plain read/enumerate function, not something
    # named like a mutator.
    banned_name_fragments = ("set", "kill", "terminate", "write", "delete")
    for key, fn in netprobe.ALLOWLIST.items():
        assert callable(fn)
        lowered_name = fn.__name__.lower()
        for fragment in banned_name_fragments:
            assert fragment not in lowered_name, f"net probe {key!r} -> {fn.__name__} looks like a mutator, not a read"
