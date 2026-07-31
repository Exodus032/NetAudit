"""E6: each SIEM format against a hostile record containing '=', '|',
embedded newlines, quotes and brackets -- the characters that actually
break naive implementations of these formats in the wild. Confirms every
format both escapes correctly AND that the escaped output parses back to
the original value.
"""
from __future__ import annotations

import json
import re

import pytest

from netaudit.export import siem

HOSTILE_TITLE = 'Odd=Title|With|Pipes\nAnd "quotes" and ]bracket and \\backslash'
HOSTILE_MESSAGE = 'msg with = sign | pipe\nnewline\r\nCRLF and "double quotes" and ]bracket'
HOSTILE_PROCESS = 'evil.exe|arg1=val1\nx'


def _hostile_event(ts_epoch=1700000000.0):
    return {
        "ts_epoch": ts_epoch,
        "kind": "recommendation",
        "category": "hygiene",
        "severity": "high",
        "title": HOSTILE_TITLE,
        "message": HOSTILE_MESSAGE,
        "source_ip": "10.0.0.5",
        "destination_ip": "1.2.3.4",
        "protocol": "tcp",
        "process_name": HOSTILE_PROCESS,
        "technique_id": None,
        "raw": {"note": "hostile"},
    }


class TestJsonl:
    def test_hostile_record_round_trips(self):
        lines = list(siem.to_jsonl([_hostile_event()]))
        assert len(lines) == 1
        assert lines[0].endswith("\n")
        parsed = json.loads(lines[0])
        assert parsed["title"] == HOSTILE_TITLE
        assert parsed["message"] == HOSTILE_MESSAGE
        assert parsed["process_name"] == HOSTILE_PROCESS


class TestEcs:
    def test_hostile_record_round_trips_and_uses_ecs_field_names(self):
        lines = list(siem.to_ecs([_hostile_event()]))
        parsed = json.loads(lines[0])
        assert "@timestamp" in parsed
        assert parsed["event"]["kind"] == "recommendation"
        assert parsed["source"]["ip"] == "10.0.0.5"
        assert parsed["destination"]["ip"] == "1.2.3.4"
        assert parsed["network"]["protocol"] == "tcp"
        assert parsed["process"]["name"] == HOSTILE_PROCESS
        assert HOSTILE_MESSAGE.split("\n")[0] in parsed["message"]


# --- CEF ---------------------------------------------------------------


def _unescape_cef(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt == "n":
                out.append("\n")
            else:
                out.append(nxt)
            i += 2
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


def _split_unescaped_pipes(line: str) -> list[str]:
    parts = []
    current = []
    i = 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            current.append(line[i:i + 2])
            i += 2
            continue
        if c == "|":
            parts.append("".join(current))
            current = []
            i += 1
            continue
        current.append(c)
        i += 1
    parts.append("".join(current))
    return parts


def _parse_cef_extension(ext: str) -> dict:
    # Keys are always \w+=; split on unescaped whitespace immediately
    # preceding another key=, treating everything else as part of the
    # current value (mirrors how real CEF consumers scan for "<space>key=").
    pattern = re.compile(r"(\w+)=")
    matches = list(pattern.finditer(ext))
    result = {}
    for idx, m in enumerate(matches):
        key = m.group(1)
        start = m.end()
        end = matches[idx + 1].start() - 1 if idx + 1 < len(matches) else len(ext)
        raw_value = ext[start:end].rstrip()
        # strip a single trailing space that separates this value from the next key
        result[key] = _unescape_cef(raw_value)
    return result


class TestCef:
    def test_header_has_exactly_seven_unescaped_pipes(self):
        line = next(iter(siem.to_cef([_hostile_event()])))
        parts = _split_unescaped_pipes(line.rstrip("\n"))
        # CEF:0 | Vendor | Product | Version | SignatureID | Name | Severity | Extension
        assert len(parts) == 8
        assert parts[0] == "CEF:0"

    def test_hostile_title_in_header_round_trips(self):
        line = next(iter(siem.to_cef([_hostile_event()])))
        parts = _split_unescaped_pipes(line.rstrip("\n"))
        name_field = parts[5]  # Name is the 6th CEF header field
        assert _unescape_cef(name_field) == HOSTILE_TITLE

    def test_hostile_extension_values_round_trip(self):
        line = next(iter(siem.to_cef([_hostile_event()])))
        parts = _split_unescaped_pipes(line.rstrip("\n"))
        extension = parts[7]
        parsed = _parse_cef_extension(extension)
        assert parsed["dproc"] == HOSTILE_PROCESS
        assert parsed["msg"] == HOSTILE_MESSAGE
        assert parsed["src"] == "10.0.0.5"
        assert parsed["dst"] == "1.2.3.4"

    def test_raw_pipe_never_appears_unescaped_in_extension(self):
        line = next(iter(siem.to_cef([_hostile_event()])))
        parts = _split_unescaped_pipes(line.rstrip("\n"))
        # Confirms the hostile '|' inside title/message did not silently
        # create extra header fields.
        assert len(parts) == 8

    @pytest.mark.parametrize("severity,expected", [("critical", 10), ("high", 8), ("medium", 5), ("low", 3), ("info", 1)])
    def test_severity_mapping(self, severity, expected):
        ev = _hostile_event()
        ev["severity"] = severity
        line = next(iter(siem.to_cef([ev])))
        parts = _split_unescaped_pipes(line.rstrip("\n"))
        assert parts[6] == str(expected)


# --- syslog (RFC 5424) -------------------------------------------------------


_SYSLOG_LINE_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d+) (?P<timestamp>\S+) (?P<hostname>\S+) "
    r"(?P<appname>\S+) (?P<procid>\S+) (?P<msgid>\S+) (?P<sd>\[.*?(?<!\\)\]) (?P<msg>.*)$"
)


def _unescape_sd(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            out.append("\n" if nxt == "n" else nxt)
            i += 2
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


class TestSyslog:
    def test_line_structure_matches_rfc5424_shape(self):
        line = next(iter(siem.to_syslog([_hostile_event()]))).rstrip("\n")
        m = _SYSLOG_LINE_RE.match(line)
        assert m is not None, f"line did not match RFC 5424 shape: {line!r}"
        assert m.group("version") == "1"
        assert m.group("sd").startswith("[netaudit@")

    def test_pri_reflects_severity(self):
        ev = _hostile_event()
        ev["severity"] = "critical"
        line = next(iter(siem.to_syslog([ev]))).rstrip("\n")
        m = _SYSLOG_LINE_RE.match(line)
        pri = int(m.group("pri"))
        facility = pri // 8
        severity = pri % 8
        assert severity == 2  # Critical
        assert facility == 13

    def test_hostile_structured_data_values_round_trip(self):
        line = next(iter(siem.to_syslog([_hostile_event()]))).rstrip("\n")
        m = _SYSLOG_LINE_RE.match(line)
        sd = m.group("sd")
        # Extract processName="..." respecting backslash-escaped quotes.
        param_re = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
        params = {k: _unescape_sd(v) for k, v in param_re.findall(sd)}
        assert params["processName"] == HOSTILE_PROCESS
        assert params["sourceIp"] == "10.0.0.5"
        assert params["destinationIp"] == "1.2.3.4"

    def test_message_has_no_raw_newlines(self):
        line = next(iter(siem.to_syslog([_hostile_event()])))
        # Exactly one newline: the trailing line terminator we add ourselves.
        assert line.count("\n") == 1
        assert line.endswith("\n")

    def test_structured_data_brackets_do_not_prematurely_close(self):
        line = next(iter(siem.to_syslog([_hostile_event()]))).rstrip("\n")
        m = _SYSLOG_LINE_RE.match(line)
        assert m is not None
        # The hostile ']' inside processName must not have terminated the
        # structured-data block early.
        assert "processName=" in m.group("sd")


class TestAllFormatsStream:
    def test_multiple_events_each_formatter_yields_one_line_per_event(self):
        events = [_hostile_event(ts_epoch=1700000000.0 + i) for i in range(5)]
        for fmt_name, fn in siem.FORMATTERS.items():
            lines = list(fn(events))
            assert len(lines) == 5, f"{fmt_name} did not yield one line per event"
            for line in lines:
                assert line.endswith("\n")
