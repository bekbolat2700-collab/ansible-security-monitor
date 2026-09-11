"""
Unit tests for ai_correlation_engine.py.

Run with: pytest tests/ -v

These tests exercise the pure logic (extract_technique_id, parse_falco_alerts,
classify) with synthetic data — no live Kubernetes cluster, Falco instance, or
Trivy/KICS reports required. They're what actually pin down the behavior of
the four-tier verdict system, rather than relying only on live CI runs to
notice a regression.

Note: importing ai_correlation_engine also imports ai_security_advisor, which
attempts a Vault lookup at 127.0.0.1:8200 at module load time. Locally and in
CI that connection is refused immediately (no listener), so it fails fast and
falls back to env vars — you'll see a one-line warning printed during test
collection, which is expected and harmless.
"""

import os
import sys
import json
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_correlation_engine import (
    extract_technique_id,
    parse_falco_alerts,
    classify,
    VERDICT_STATIC_ONLY,
    VERDICT_RUNTIME_DETECTED,
    VERDICT_COVERAGE_CONFIRMED,
    VERDICT_POTENTIAL_EXPLOITATION,
)


# ─────────────────────────────────────────────────────────────────────────
# extract_technique_id
# ─────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("text,expected", [
    ("T1552.001 - Unsecured Credentials: Credentials In Files", "T1552"),
    ("T1059 - Command and Scripting Interpreter", "T1059"),
    ("T1048", "T1048"),
    ("no technique mentioned here", None),
    ("", None),
    (None, None),
])
def test_extract_technique_id(text, expected):
    assert extract_technique_id(text) == expected


def test_extract_technique_id_matches_unmapped_finding_fallback():
    # mitre_mapping.get_mitre_info() falls back to "T0000 - Not mapped yet"
    # for finding titles it doesn't recognize. The regex must still match
    # a 4-digit technique id here, or every unmapped finding would silently
    # vanish from classify() instead of showing up as its own bucket.
    assert extract_technique_id("T0000 - Not mapped yet") == "T0000"


# ─────────────────────────────────────────────────────────────────────────
# parse_falco_alerts
# ─────────────────────────────────────────────────────────────────────────

def _write_falco_log(tmp_path, lines):
    path = tmp_path / "falco-events.json"
    path.write_text("\n".join(lines))
    return str(path)


def test_parse_falco_alerts_skips_non_json_banner_lines(tmp_path):
    lines = [
        "Falco version: 0.44.1 (x86_64)",
        "Falco initialized with configuration files:",
        json.dumps({
            "rule": "Read Sensitive File in Container",
            "priority": "Critical",
            "tags": ["container", "credentials", "T1552"],
            "output": "sensitive file read",
            "output_fields": {"container.name": "security-monitor"},
        }),
    ]
    alerts = parse_falco_alerts(_write_falco_log(tmp_path, lines))
    assert len(alerts) == 1
    assert alerts[0]["technique_id"] == "T1552"
    assert alerts[0]["priority"] == "CRITICAL"  # normalized to uppercase
    assert alerts[0]["target"] == "security-monitor"


def test_parse_falco_alerts_skips_alerts_without_mitre_tag(tmp_path):
    lines = [
        json.dumps({
            "rule": "Some rule with no MITRE tag",
            "priority": "Warning",
            "tags": ["container", "misc"],
            "output": "...",
            "output_fields": {},
        }),
    ]
    assert parse_falco_alerts(_write_falco_log(tmp_path, lines)) == []


def test_parse_falco_alerts_missing_file_returns_empty_list(tmp_path):
    missing = str(tmp_path / "does-not-exist.json")
    assert parse_falco_alerts(missing) == []


def test_parse_falco_alerts_ignores_malformed_json_line(tmp_path):
    lines = [
        "{not valid json",
        json.dumps({
            "rule": "r", "priority": "Warning", "tags": ["T1059"],
            "output": "o", "output_fields": {"container.name": "x"},
        }),
    ]
    alerts = parse_falco_alerts(_write_falco_log(tmp_path, lines))
    assert len(alerts) == 1


def test_parse_falco_alerts_target_priority_order(tmp_path):
    # container.name should win over container.image.repository and k8s.pod.name
    lines = [
        json.dumps({
            "rule": "r", "priority": "Warning", "tags": ["T1059"],
            "output": "o",
            "output_fields": {
                "container.name": "security-monitor",
                "container.image.repository": "some-other-image",
                "k8s.pod.name": "security-monitor-abc123",
            },
        }),
    ]
    alerts = parse_falco_alerts(_write_falco_log(tmp_path, lines))
    assert alerts[0]["target"] == "security-monitor"


def test_parse_falco_alerts_target_falls_back_to_unknown(tmp_path):
    lines = [
        json.dumps({"rule": "r", "priority": "Warning", "tags": ["T1059"], "output": "o", "output_fields": {}}),
    ]
    alerts = parse_falco_alerts(_write_falco_log(tmp_path, lines))
    assert alerts[0]["target"] == "unknown"


# ─────────────────────────────────────────────────────────────────────────
# classify() — the core four-tier verdict logic
# ─────────────────────────────────────────────────────────────────────────

def _static(title, source="KICS", severity="MEDIUM"):
    return {"title": title, "source": source, "severity": severity}


def _falco(technique_id, priority, rule="Some Rule", target="security-monitor"):
    return {
        "rule": rule, "priority": priority, "technique_id": technique_id,
        "target": target, "time": "", "output": "evidence output text",
    }


def test_classify_static_only_when_no_falco_match():
    findings = [_static("Container Capabilities Unrestricted")]
    results = classify(findings, [])
    assert len(results[VERDICT_STATIC_ONLY]) == 1
    assert results[VERDICT_STATIC_ONLY][0]["title"] == "Container Capabilities Unrestricted"
    assert len(results[VERDICT_RUNTIME_DETECTED]) == 0
    assert len(results[VERDICT_COVERAGE_CONFIRMED]) == 0
    assert len(results[VERDICT_POTENTIAL_EXPLOITATION]) == 0


def test_classify_runtime_detected_when_no_static_match():
    alerts = [_falco("T1059", "WARNING", rule="Shell Spawned in Container")]
    results = classify([], alerts)
    assert len(results[VERDICT_RUNTIME_DETECTED]) == 1
    entry = results[VERDICT_RUNTIME_DETECTED][0]
    assert entry["technique_id"] == "T1059"
    assert entry["count"] == 1
    assert "Shell Spawned in Container" in entry["rules"]


def test_classify_low_priority_match_is_coverage_confirmed_not_exploitation():
    findings = [_static("Shared Service Account")]  # maps to T1552.007
    alerts = [_falco("T1552", "WARNING", rule="Failed Sensitive File Access Attempt")]
    results = classify(findings, alerts)
    assert len(results[VERDICT_COVERAGE_CONFIRMED]) == 1
    assert len(results[VERDICT_POTENTIAL_EXPLOITATION]) == 0
    assert len(results[VERDICT_STATIC_ONLY]) == 0


@pytest.mark.parametrize("priority", ["CRITICAL", "ERROR", "EMERGENCY", "ALERT"])
def test_classify_high_priority_match_escalates_to_potential_exploitation(priority):
    findings = [_static("Passwords And Secrets - Generic Password", severity="HIGH")]
    alerts = [_falco("T1552", priority, rule="Read Sensitive File in Container")]
    results = classify(findings, alerts)
    assert len(results[VERDICT_POTENTIAL_EXPLOITATION]) == 1
    assert len(results[VERDICT_COVERAGE_CONFIRMED]) == 0


@pytest.mark.parametrize("priority", ["WARNING", "NOTICE", "INFORMATIONAL", "DEBUG"])
def test_classify_low_priority_never_escalates_to_exploitation(priority):
    findings = [_static("Passwords And Secrets - Generic Password", severity="HIGH")]
    alerts = [_falco("T1552", priority)]
    results = classify(findings, alerts)
    assert len(results[VERDICT_POTENTIAL_EXPLOITATION]) == 0
    assert len(results[VERDICT_COVERAGE_CONFIRMED]) == 1


def test_classify_multiple_static_findings_same_technique_each_get_own_entry():
    # e.g. the same KICS query firing on two different files (deployment.yaml
    # and the Helm template) — must NOT be silently deduplicated into one.
    findings = [_static("Shared Service Account"), _static("Shared Service Account")]
    alerts = [_falco("T1552", "WARNING")]
    results = classify(findings, alerts)
    assert len(results[VERDICT_COVERAGE_CONFIRMED]) == 2


def test_classify_falco_evidence_is_attached_to_correlated_finding():
    findings = [_static("Passwords And Secrets - Generic Password", severity="HIGH")]
    alerts = [_falco("T1552", "CRITICAL", rule="Read Sensitive File in Container")]
    results = classify(findings, alerts)
    entry = results[VERDICT_POTENTIAL_EXPLOITATION][0]
    assert entry["falco_evidence"][0]["rule"] == "Read Sensitive File in Container"
    assert entry["falco_evidence"][0]["priority"] == "CRITICAL"


def test_classify_empty_input_returns_all_empty_buckets():
    results = classify([], [])
    assert all(len(v) == 0 for v in results.values())


def test_classify_unrelated_techniques_do_not_cross_correlate():
    # A T1548 static finding and a T1552 Falco alert must stay in their own
    # lanes — technique matching must be exact, not "any signal present".
    findings = [_static("Container Capabilities Unrestricted")]  # T1548
    alerts = [_falco("T1552", "CRITICAL")]
    results = classify(findings, alerts)
    assert len(results[VERDICT_STATIC_ONLY]) == 1
    assert len(results[VERDICT_RUNTIME_DETECTED]) == 1
    assert len(results[VERDICT_POTENTIAL_EXPLOITATION]) == 0
    assert len(results[VERDICT_COVERAGE_CONFIRMED]) == 0


def test_classify_one_technique_can_produce_multiple_verdicts_at_once():
    # Realistic mixed case: one static finding with no runtime match (STATIC
    # ONLY), one that IS matched at low confidence (COVERAGE CONFIRMED), and
    # one Falco alert in a technique nothing static flagged (RUNTIME
    # DETECTED) — all three buckets should be populated independently in a
    # single classify() call.
    findings = [
        _static("Container Capabilities Unrestricted"),   # T1548, no Falco match
        _static("Shared Service Account"),                # T1552, low-priority match
    ]
    alerts = [
        _falco("T1552", "WARNING", rule="Failed Sensitive File Access Attempt"),
        _falco("T1072", "NOTICE", rule="Package Management in Container"),
    ]
    results = classify(findings, alerts)
    assert len(results[VERDICT_STATIC_ONLY]) == 1
    assert len(results[VERDICT_COVERAGE_CONFIRMED]) == 1
    assert len(results[VERDICT_RUNTIME_DETECTED]) == 1
    assert results[VERDICT_RUNTIME_DETECTED][0]["technique_id"] == "T1072"
