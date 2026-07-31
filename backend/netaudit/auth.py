"""Local auth token (Part C item 2, item 13).

On startup we generate (or reuse) a random token, write it to
``%LOCALAPPDATA%\\NetAudit\\token``, and lock it down to the current
Windows user via `icacls`. The token is then required on every `/api` and
`/ws` request (enforced by ``netaudit.security.SecurityMiddleware``), except
`GET /api/bootstrap`, which hands the token to the dashboard itself under a
loopback/same-origin check (see ``netaudit.api.bootstrap``).

Fail closed: if we cannot create the file, or cannot prove the ACL is
owner-only, ``ensure_token`` raises ``TokenSecurityError``. The server's
lifespan handler lets that exception propagate, which aborts startup rather
than falling back to serving unauthenticated (Part C item 13).
"""
from __future__ import annotations

import getpass
import logging
import os
import re
import secrets
import subprocess
from pathlib import Path

logger = logging.getLogger("netaudit.auth")

TOKEN_BYTES = 32

# icacls reports one ACE per line as "<grantee>:(perms)". The very first
# line is "<path> <grantee>:(perms)" -- path and grantee on the same line,
# space-separated -- which we strip using the exact path string before
# parsing (see _parse_icacls_grantees). Grantee identities are matched
# exactly (after lowercasing), never by substring: a naive `"\\users" in
# line` check is a real bug here, since every Windows user profile path
# contains "\Users\" and would false-positive against the file's own path
# on that first line.
_ACE_RE = re.compile(r"^(?P<grantee>.+?):\(")

# SYSTEM and built-in Administrators are treated as acceptable co-owners,
# not a violation of "owner-only". Neither can be excluded from a Windows
# ACL in any way that survives a reboot/service context, and any local
# administrator can already take ownership and rewrite the ACL at will --
# so requiring literally nobody but the plain user is not an achievable or
# meaningful bar on this OS. This matches the convention used by e.g.
# OpenSSH-on-Windows when it validates private key file permissions.
#
# "OWNER RIGHTS" (well-known SID S-1-3-4) is not a third-party grantee at
# all -- it's a placeholder meaning "whatever rights the current owner
# has", commonly present (inherited from the parent directory's default
# DACL, e.g. under %TEMP%) alongside an explicit owner grant. It doesn't
# widen access beyond the owner we already verified, so it's allowed too.
_ALLOWED_BUILTIN_GRANTEES = {
    "nt authority\\system",
    "builtin\\administrators",
    "owner rights",
}


class TokenSecurityError(RuntimeError):
    """Raised when the token file cannot be created/secured. Callers must
    treat this as fatal and refuse to start (Part C item 13)."""


def _current_username() -> str:
    domain = os.environ.get("USERDOMAIN")
    user = os.environ.get("USERNAME") or os.environ.get("USER")
    if not user:
        user = getpass.getuser()
    return f"{domain}\\{user}" if domain else user


def _run_icacls(args: list[str]) -> subprocess.CompletedProcess:
    """Fixed-argument-list subprocess call -- never shell=True, never a
    concatenated string, and nothing here is derived from HTTP input (path
    is our own token file, username comes from the local OS environment)."""
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=15,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def _secure_windows_file(path: Path) -> None:
    username = _current_username()
    result = _run_icacls(["icacls", str(path), "/inheritance:r", "/grant:r", f"{username}:F"])
    if result.returncode != 0:
        raise TokenSecurityError(
            f"icacls failed to set owner-only permissions on the token file "
            f"(exit code {result.returncode}): {result.stderr.strip()}"
        )
    if not _acl_is_owner_only(path, username):
        raise TokenSecurityError(
            "Could not verify owner-only permissions on the token file after icacls ran."
        )


def _parse_icacls_grantees(output: str, path: Path) -> list[str]:
    """Extract the lowercased grantee identity of every ACE line from
    `icacls <path>` output. Strips the literal path prefix from the first
    line (icacls prints "<path> <grantee>:(perms)" there) using the exact
    path string, not a substring/keyword heuristic, so a grantee name that
    happens to look like part of the path can't be confused for one."""
    path_str = str(path)
    grantees: list[str] = []
    lines = [l for l in output.splitlines() if l.strip()]
    for i, line in enumerate(lines):
        text = line
        if i == 0 and text.startswith(path_str):
            text = text[len(path_str):]
        text = text.strip()
        low = text.lower()
        if low.startswith("successfully processed") or low.startswith("failed processing"):
            continue
        m = _ACE_RE.match(text)
        if not m:
            continue
        grantees.append(m.group("grantee").strip().lower())
    return grantees


def _acl_is_owner_only(path: Path, username: str) -> bool:
    """Verify that every ACE on `path` is either the current user or one of
    the acceptable built-in elevated accounts (SYSTEM, Administrators) --
    i.e. no Everyone/Users/Authenticated Users/other-account grant survived.
    This is a string-parsing check over `icacls` output, not a Win32
    security-descriptor comparison -- documented as a residual limitation
    in SECURITY.md (locale-dependent wording, in particular)."""
    result = _run_icacls(["icacls", str(path)])
    if result.returncode != 0:
        return False
    grantees = _parse_icacls_grantees(result.stdout, path)
    if not grantees:
        return False

    bare_user = username.split("\\")[-1].lower()
    full_user = username.lower()
    found_user = False
    for grantee in grantees:
        if grantee in _ALLOWED_BUILTIN_GRANTEES:
            continue
        if grantee == full_user or grantee == bare_user or grantee.endswith("\\" + bare_user):
            found_user = True
            continue
        # Anything else -- Everyone, BUILTIN\Users, Authenticated Users, a
        # different account, a group -- means this is not owner-only.
        return False
    return found_user


def _permissions_ok(path: Path) -> bool:
    if os.name != "nt":  # pragma: no cover - dev-only fallback, not the target OS
        try:
            mode = path.stat().st_mode & 0o777
        except OSError:
            return False
        return mode in (0o600, 0o400)
    return _acl_is_owner_only(path, _current_username())


def _secure(path: Path) -> None:
    if os.name != "nt":  # pragma: no cover - dev-only fallback, not the target OS
        try:
            path.chmod(0o600)
        except OSError as exc:
            raise TokenSecurityError(f"Could not chmod token file: {exc}") from exc
        return
    _secure_windows_file(path)


def ensure_token(token_path: Path) -> str:
    """Generate or reuse the local auth token at ``token_path``.

    Reuses an existing token file only if it is present, non-empty, AND
    correctly permissioned (Part C item 2). Otherwise a fresh token is
    generated and the file (re-)secured. Raises ``TokenSecurityError`` if
    the file cannot be secured -- callers must not catch this and continue.
    """
    token_path = Path(token_path)
    try:
        token_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise TokenSecurityError(f"Could not create token directory {token_path.parent}: {exc}") from exc

    if token_path.exists():
        try:
            existing = token_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise TokenSecurityError(f"Could not read existing token file: {exc}") from exc
        if existing and _permissions_ok(token_path):
            logger.info("Reusing existing token file at %s (permissions verified).", token_path)
            return existing
        logger.warning(
            "Existing token file at %s is missing, empty, or has incorrect "
            "permissions; regenerating and re-securing it.", token_path,
        )

    token = secrets.token_urlsafe(TOKEN_BYTES)
    try:
        token_path.write_text(token, encoding="utf-8")
    except OSError as exc:
        raise TokenSecurityError(f"Could not write token file {token_path}: {exc}") from exc
    _secure(token_path)
    logger.info("Generated new auth token at %s.", token_path)
    return token
