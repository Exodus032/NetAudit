"""E6: streaming SIEM / log-pipeline export in jsonl, ecs, cef and syslog
(RFC 5424) formats.

Every formatter is a generator over normalized event dicts (see
`events.py`) and never materialises the whole export in memory -- the
router wraps these generators in a `StreamingResponse`.

Escaping is the part of this that actually matters in the wild: a CEF
extension value containing `=`, `|` or a newline must be escaped per the
CEF spec, not emitted raw (it would otherwise corrupt the record or let a
hostile field value inject fake extra fields into the log line). Syslog
RFC 5424 structured-data values need their own escaping of `"`, `\\` and
`]`. See `test_siem.py` for a hostile record exercising all of these at
once, and an assertion that each formatter's output parses back correctly.
"""
from __future__ import annotations

import json
from typing import Iterable, Iterator

from ..timeutil import iso_z

_SEVERITY_TO_CEF = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}
_SEVERITY_TO_SYSLOG = {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}

_SYSLOG_FACILITY = 13  # log audit / security messages (RFC 5424 Table 1)
# Example/placeholder Private Enterprise Number, matching the style RFC
# 5424 itself uses in its own worked examples (section 6.3.5) -- not a
# real IANA-registered PEN for this project, just a syntactically valid
# SD-ID so the structured-data block parses.
_SYSLOG_SD_ID = "netaudit@32473"


# --- jsonl --------------------------------------------------------------


def to_jsonl(events: Iterable[dict]) -> Iterator[str]:
    for ev in events:
        record = {
            "@timestamp": iso_z(ev["ts_epoch"]),
            "kind": ev["kind"],
            "category": ev["category"],
            "severity": ev["severity"],
            "title": ev["title"],
            "message": ev["message"],
            "source_ip": ev["source_ip"],
            "destination_ip": ev["destination_ip"],
            "protocol": ev["protocol"],
            "process_name": ev["process_name"],
            "technique_id": ev["technique_id"],
        }
        yield json.dumps(record, default=str) + "\n"


# --- ecs (Elastic Common Schema) -----------------------------------------


def to_ecs(events: Iterable[dict]) -> Iterator[str]:
    for ev in events:
        record = {
            "@timestamp": iso_z(ev["ts_epoch"]),
            "event": {
                "kind": ev["kind"],
                "category": [ev["category"]] if ev["category"] else [],
                "severity": _SEVERITY_TO_SYSLOG.get(ev["severity"], 6),
            },
            "message": ev["message"] or ev["title"],
        }
        if ev["source_ip"]:
            record["source"] = {"ip": ev["source_ip"]}
        if ev["destination_ip"]:
            record["destination"] = {"ip": ev["destination_ip"]}
        if ev["protocol"]:
            record["network"] = {"protocol": ev["protocol"]}
        if ev["process_name"]:
            record["process"] = {"name": ev["process_name"]}
        if ev["technique_id"]:
            record["threat"] = {"technique": {"id": ev["technique_id"]}}
        yield json.dumps(record, default=str) + "\n"


# --- cef (ArcSight CEF:0) --------------------------------------------------


def _escape_cef_header_field(value) -> str:
    """CEF header fields are pipe-delimited: '\\' and '|' must be escaped.
    Embedded newlines are also neutralised (as the literal two-char
    sequence '\\n') since CEF is a single-line format end to end -- a raw
    newline in a header field would split the record just as surely as an
    unescaped pipe would."""
    s = "" if value is None else str(value)
    s = s.replace("\\", "\\\\").replace("|", "\\|")
    s = s.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n")
    return s


def _escape_cef_extension_value(value) -> str:
    """CEF extension values are space-separated key=value pairs. Escapes
    '\\', '=' and '|' (a literal '|' inside an extension value doesn't
    strictly ambiguate parsing once the header's 7 fields are already
    consumed, but the task's own contract is explicit that any CEF value
    containing '=', '|' or a newline must be escaped, not emitted raw --
    so all three are escaped here regardless of which position they're
    in), and embedded newlines are encoded as the literal two-char
    sequence '\\n'."""
    s = "" if value is None else str(value)
    s = s.replace("\\", "\\\\").replace("=", "\\=").replace("|", "\\|")
    s = s.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n")
    return s


def to_cef(events: Iterable[dict]) -> Iterator[str]:
    for ev in events:
        severity = _SEVERITY_TO_CEF.get(ev["severity"], 1)
        header = "|".join([
            "CEF:0",
            "NetAudit",
            "NetAudit",
            "1.0",
            _escape_cef_header_field(ev["category"]),
            _escape_cef_header_field(ev["title"]),
            str(severity),
        ])

        ext_pairs: list[tuple[str, str]] = []
        if ev["source_ip"]:
            ext_pairs.append(("src", ev["source_ip"]))
        if ev["destination_ip"]:
            ext_pairs.append(("dst", ev["destination_ip"]))
        if ev["protocol"]:
            ext_pairs.append(("proto", ev["protocol"]))
        if ev["process_name"]:
            ext_pairs.append(("dproc", ev["process_name"]))
        if ev["technique_id"]:
            ext_pairs.append(("cs1", ev["technique_id"]))
            ext_pairs.append(("cs1Label", "mitreTechniqueId"))
        ext_pairs.append(("cat", ev["category"] or ""))
        ext_pairs.append(("rt", iso_z(ev["ts_epoch"])))
        if ev["message"]:
            ext_pairs.append(("msg", ev["message"]))

        extension = " ".join(f"{k}={_escape_cef_extension_value(v)}" for k, v in ext_pairs)
        yield f"{header}|{extension}\n"


# --- syslog (RFC 5424 with structured data) --------------------------------


def _escape_sd_value(value) -> str:
    """RFC 5424 section 6.3.3: PARAM-VALUE must escape '\\', '\"' and ']'.
    Embedded newlines are additionally encoded as the literal two-char
    sequence '\\n' -- RFC 5424 expects one syslog message per line, so a
    raw newline inside a structured-data value would split the message
    just as a raw ']' would corrupt the structured-data block."""
    s = "" if value is None else str(value)
    s = s.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")
    s = s.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n")
    return s


def to_syslog(events: Iterable[dict]) -> Iterator[str]:
    for ev in events:
        severity = _SEVERITY_TO_SYSLOG.get(ev["severity"], 6)
        pri = _SYSLOG_FACILITY * 8 + severity
        timestamp = iso_z(ev["ts_epoch"])
        hostname = "netaudit"
        app_name = "netaudit"
        procid = "-"
        msgid = ev["kind"] or "-"

        sd_params = [("category", ev["category"] or ""), ("title", ev["title"] or "")]
        if ev["source_ip"]:
            sd_params.append(("sourceIp", ev["source_ip"]))
        if ev["destination_ip"]:
            sd_params.append(("destinationIp", ev["destination_ip"]))
        if ev["protocol"]:
            sd_params.append(("protocol", ev["protocol"]))
        if ev["process_name"]:
            sd_params.append(("processName", ev["process_name"]))
        if ev["technique_id"]:
            sd_params.append(("techniqueId", ev["technique_id"]))

        sd_body = " ".join(f'{k}="{_escape_sd_value(v)}"' for k, v in sd_params)
        structured_data = f"[{_SYSLOG_SD_ID} {sd_body}]"

        msg = (ev["message"] or ev["title"] or "").replace("\r\n", " ").replace("\n", " ").replace("\r", " ")

        yield f"<{pri}>1 {timestamp} {hostname} {app_name} {procid} {msgid} {structured_data} {msg}\n"


FORMATTERS = {
    "jsonl": to_jsonl,
    "ecs": to_ecs,
    "cef": to_cef,
    "syslog": to_syslog,
}
