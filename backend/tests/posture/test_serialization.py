"""Every model round-trips through JSON, and every timestamp field is
Z-suffixed UTC, matching API_CONTRACT.md's shared timestamp convention."""
from __future__ import annotations

import json
import re

from netaudit.posture.base import utc_now_iso
from netaudit.posture.models import (
    CategoryScore,
    Counts,
    EvidenceItem,
    PostureCheck,
    PostureReport,
    Remediation,
    RemediationCommand,
    ScoreComponent,
    ScoreHistoryPoint,
    SecurityScoreResponse,
    TopWin,
)

_Z_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def _sample_check() -> PostureCheck:
    return PostureCheck(
        id="smb_signing_required",
        category="smb",
        title="SMB signing is not required",
        status="fail",
        severity="high",
        score_weight=8,
        observed="RequireSecuritySignature = False on the SMB client and server",
        expected="RequireSecuritySignature = True",
        why_it_matters="Without required signing, an attacker on the same network can relay or tamper with SMB sessions.",
        evidence=[EvidenceItem(label="Client", value="RequireSecuritySignature: False")],
        remediation=Remediation(
            summary="Require SMB signing on both the client and the server.",
            commands=[
                RemediationCommand(
                    shell="powershell",
                    command="Set-SmbClientConfiguration -RequireSecuritySignature $true -Force",
                    requires_admin=True,
                    reversible=True,
                    risk_note="May reduce throughput slightly.",
                )
            ],
            docs_url="https://learn.microsoft.com/windows-server/storage/file-server/smb-signing",
        ),
        references=["CIS Microsoft Windows 11 v3.0.0 2.3.9.2"],
        checked_at=utc_now_iso(),
        duration_ms=34,
    )


def test_utc_now_iso_matches_z_suffixed_format():
    assert _Z_TIMESTAMP.match(utc_now_iso())


def test_posture_check_round_trips_and_timestamp_is_z_suffixed():
    check = _sample_check()
    payload = json.loads(check.model_dump_json(by_alias=True))
    assert _Z_TIMESTAMP.match(payload["checked_at"])
    restored = PostureCheck.model_validate(payload)
    assert restored == check


def test_posture_report_round_trips_with_pass_alias_and_z_timestamp():
    check = _sample_check()
    report = PostureReport(
        generated_at=utc_now_iso(),
        scan_duration_ms=2140,
        score=68,
        grade="C",
        counts=Counts(**{"pass": 21, "warn": 6, "fail": 3, "error": 1, "skipped": 2}),
        categories=[CategoryScore(id="smb", label="SMB", score=55, checks=[check.id])],
        checks=[check],
    )
    payload = json.loads(report.model_dump_json(by_alias=True))
    assert _Z_TIMESTAMP.match(payload["generated_at"])
    # the wire format uses the literal key "pass", not "pass_"
    assert "pass" in payload["counts"]
    assert "pass_" not in payload["counts"]
    assert payload["counts"]["pass"] == 21

    restored = PostureReport.model_validate(payload)
    assert restored == report
    assert restored.counts.pass_ == 21


def test_security_score_response_round_trips_and_history_timestamps_are_z_suffixed():
    response = SecurityScoreResponse(
        generated_at=utc_now_iso(),
        overall=64,
        grade="C",
        components=[
            ScoreComponent(id="posture", label="Host configuration", score=68, weight=0.4, grade="C"),
            ScoreComponent(id="threats", label="Active threats", score=55, weight=0.35, grade="D"),
        ],
        history=[ScoreHistoryPoint(t=utc_now_iso(), overall=61)],
        top_wins=[TopWin(id="smb_signing_required", kind="posture", title="Require SMB signing", score_gain=8, effort="low")],
    )
    payload = json.loads(response.model_dump_json(by_alias=True))
    assert _Z_TIMESTAMP.match(payload["generated_at"])
    for point in payload["history"]:
        assert _Z_TIMESTAMP.match(point["t"])

    restored = SecurityScoreResponse.model_validate(payload)
    assert restored == response


def test_remediation_command_optional_risk_note_round_trips_as_null():
    cmd = RemediationCommand(shell="powershell", command="Get-Service WinRM", requires_admin=False, reversible=True)
    payload = json.loads(cmd.model_dump_json(by_alias=True))
    assert payload["risk_note"] is None
    assert RemediationCommand.model_validate(payload) == cmd
