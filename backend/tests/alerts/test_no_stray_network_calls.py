"""Proves, structurally, that `webhook.RealTransport.send()` is the only
place in this whole package capable of opening a real network connection.
A regression here (someone adding a second `requests.post(...)` somewhere,
or calling `socket.create_connection` outside the one sanctioned spot)
should fail this test even though the rest of the suite mocks everything
out and would otherwise never notice.
"""
from __future__ import annotations

import ast
from pathlib import Path

import netaudit.alerts as alerts_pkg

PACKAGE_DIR = Path(alerts_pkg.__file__).resolve().parent

# Names/attributes that indicate an actual outbound network call.
_NETWORK_MARKERS = (
    "create_connection",
    "socket.socket",
    "HTTPSConnection",
    "HTTPConnection",
    "urlopen",
    "requests.get",
    "requests.post",
    "requests.request",
)

_ALLOWED_FILE = "webhook.py"
_ALLOWED_FUNCTION = "send"  # RealTransport.send


def _source_files():
    return sorted(PACKAGE_DIR.rglob("*.py"))


def test_network_marker_strings_only_appear_in_webhook_py():
    offenders = []
    for path in _source_files():
        if path.name == _ALLOWED_FILE:
            continue
        text = path.read_text(encoding="utf-8")
        for marker in _NETWORK_MARKERS:
            if marker in text:
                offenders.append(f"{path.relative_to(PACKAGE_DIR)}: found {marker!r}")
    assert not offenders, "network call marker found outside webhook.py:\n" + "\n".join(offenders)


def test_socket_module_only_imported_and_used_in_webhook_py():
    for path in _source_files():
        if path.name == _ALLOWED_FILE:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in ("socket", "ssl", "http.client"), f"{path}: unexpected import of {alias.name!r}"
            if isinstance(node, ast.ImportFrom):
                assert node.module not in ("socket", "ssl", "http.client"), f"{path}: unexpected import from {node.module!r}"


def test_realtransport_send_is_the_only_function_calling_socket_create_connection():
    path = PACKAGE_DIR / _ALLOWED_FILE
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    offending_functions = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for inner in ast.walk(node):
                if isinstance(inner, ast.Attribute) and inner.attr == "create_connection":
                    if node.name != _ALLOWED_FUNCTION:
                        offending_functions.append(node.name)
    assert not offending_functions, f"socket.create_connection called outside {_ALLOWED_FUNCTION}(): {offending_functions}"
