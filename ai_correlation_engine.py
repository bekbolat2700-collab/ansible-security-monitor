#!/usr/bin/env python3
"""
ai_correlation_engine.py

Cross-source correlation for the DevSecOps pipeline. Runs as the last
step of the ai-gatekeeper.yml job, after Falco has been installed into
the SAME k3d cluster as the real security-monitor deployment and a set
of controlled runtime scenarios has been executed against it.

This engine does NOT claim to prove exploitation. It classifies every
signal (static finding, runtime alert) into one of four confidence
levels, based only on what can actually be observed:

  🟢 STATIC ONLY               — a static scanner flagged this MITRE
                                  technique; Falco observed nothing in
                                  that technique family during the run.
  🟡 RUNTIME DETECTED           — Falco observed activity in a technique
                                  family that no static scanner flagged.
                                  Worth a look, but not a build-time
                                  weakness to fix.
  🔵 DETECTION COVERAGE CONFIRMED — a static finding and a Falco alert
                                  share the same MITRE technique family,
                                  on the actual security-monitor
                                  workload. This says: "the weakness
                                  class we flagged at build time is one
                                  our runtime layer can actually see."
                                  It does NOT mean the weakness itself
                                  was exploited.
  🔴 POTENTIAL EXPLOITATION PATH — same as above, but the Falco alert
                                  that fired is itself CRITICAL/ERROR
                                  priority — i.e. the rule didn't just
                                  see "a shell was opened", it saw
                                  direct interaction with a sensitive
                                  resource (credential file read, write
                                  to a binary directory). Still not
                                  proof the specific static finding was
                                  the vector — "potential", not
                                  "confirmed".

Technique matching uses the MITRE technique IDs (Txxxx) attached to
each static finding via mitre_mapping.get_mitre_info(), and the `tags`
field Falco attaches to each JSON alert when a rule tags itself with a
Txxxx code (see falco/falco-custom-rules.yaml).

Env vars (same convention as ai_security_advisor.py):
  GROQ_API_KEY, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, PUSHGATEWAY_URL
  (loaded the same way ai_security_advisor.py loads them — Vault first,
  env/.env fallback — since we import those constants from it.)

  FALCO_ALERTS_PATH — path to the Falco JSON-lines log captured with
  `kubectl logs -n falco ... > falco-events.json` while Falco is
  running with `json_output: true` (default: falco-events.json).
"""

import os
import re
import json
import time
import requests

from mitre_mapping import get_mitre_info
from ai_security_advisor import (
    parse_trivy_report,
    parse_kics_report,
    parse_tfsec_output,
    GROQ_API_KEY,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
    PUSHGATEWAY_URL,
    SEVERITY_WEIGHT,
    send_telegram,
)

FALCO_ALERTS_PATH = os.getenv("FALCO_ALERTS_PATH", "falco-events.json")
CORRELATION_REPORT_PATH = os.getenv("CORRELATION_REPORT_PATH", "correlation-report.json")

# Falco priorities that mean "direct interaction with a sensitive
# resource", not just "a process ran". Matches falco-custom-rules.yaml:
# Read Sensitive File = CRITICAL, Write Binary Directory = ERROR.
HIGH_CONFIDENCE_FALCO_PRIORITIES = {"CRITICAL", "ERROR", "EMERGENCY", "ALERT"}

TECHNIQUE_ID_RE = re.compile(r"T\d{4}")

VERDICT_STATIC_ONLY = "STATIC ONLY"
VERDICT_RUNTIME_DETECTED = "RUNTIME DETECTED"
VERDICT_COVERAGE_CONFIRMED = "DETECTION COVERAGE CONFIRMED"
VERDICT_POTENTIAL_EXPLOITATION = "POTENTIAL EXPLOITATION PATH"

VERDICT_EMOJI = {
    VERDICT_STATIC_ONLY: "🟢",
    VERDICT_RUNTIME_DETECTED: "🟡",
    VERDICT_COVERAGE_CONFIRMED: "🔵",
    VERDICT_POTENTIAL_EXPLOITATION: "🔴",
}


# ─────────────────────────────────────────────────────────────────────────
# Falco parsing
# ─────────────────────────────────────────────────────────────────────────

def extract_technique_id(text):
    """Pull the top-level MITRE technique id (e.g. 'T1552') out of a
    string like 'T1552.001 - Unsecured Credentials: ...' or a Falco
    tag list entry. Returns None if nothing matches."""
    if not text:
        return None
    match = TECHNIQUE_ID_RE.search(text)
    return match.group(0) if match else None


def parse_falco_alerts(path=FALCO_ALERTS_PATH):
    """
    Parse a Falco JSON-lines alert log (captured via `kubectl logs`
    while Falco runs with `json_output: true`) into normalized dicts:
      {"rule": ..., "priority": ..., "technique_id": ..., "target": ...,
       "output": ..., "raw_fields": {...}}

    Non-JSON lines (Falco startup banners, etc.) are silently skipped.
    Alerts whose rule carries no Txxxx tag are skipped — we can only
    correlate against a MITRE technique.
    """
    alerts = []
    if not os.path.exists(path):
        print(f"⚠️ Falco alerts file not found at {path} — skipping runtime correlation")
        return alerts

    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                tags = event.get("tags", []) or []
                technique_id = None
                for tag in tags:
                    technique_id = extract_technique_id(str(tag))
                    if technique_id:
                        break
                if not technique_id:
                    continue  # can't correlate an alert with no MITRE tag

                fields = event.get("output_fields", {}) or {}
                target = (
                    fields.get("container.name")
                    or fields.get("container.image.repository")
                    or fields.get("k8s.pod.name")
                    or "unknown"
                )

                alerts.append({
                    "rule": event.get("rule", "Unknown Falco Rule"),
                    "priority": (event.get("priority") or "").upper(),
                    "technique_id": technique_id,
                    "target": target,
                    "time": event.get("time", ""),
                    "output": event.get("output", ""),
                    "raw_fields": fields,
                })
    except Exception as e:
        print(f"⚠️ Falco parse error: {e}")

    return alerts


# ─────────────────────────────────────────────────────────────────────────
# Correlation
# ─────────────────────────────────────────────────────────────────────────

def classify(static_findings, falco_alerts):
    """
    Returns a dict:
      {
        "STATIC ONLY": [...],
        "RUNTIME DETECTED": [...],
        "DETECTION COVERAGE CONFIRMED": [...],
        "POTENTIAL EXPLOITATION PATH": [...],
      }
    Each entry in the COVERAGE/EXPLOITATION lists carries both the
    static finding(s) and the Falco alert(s) that produced the verdict.
    STATIC ONLY / RUNTIME DETECTED entries are single-sided (no
    corroboration was found either way).
    """
    for f in static_findings:
        f["_mitre"] = get_mitre_info(f["title"])
        f["_technique_id"] = extract_technique_id(f["_mitre"]["technique"])

    falco_by_technique = {}
    for alert in falco_alerts:
        falco_by_technique.setdefault(alert["technique_id"], []).append(alert)

    static_technique_ids = set()
    results = {
        VERDICT_STATIC_ONLY: [],
        VERDICT_RUNTIME_DETECTED: [],
        VERDICT_COVERAGE_CONFIRMED: [],
        VERDICT_POTENTIAL_EXPLOITATION: [],
    }

    for f in static_findings:
        tid = f["_technique_id"]
        static_technique_ids.add(tid)
        matched_alerts = falco_by_technique.get(tid, [])

        if not matched_alerts:
            results[VERDICT_STATIC_ONLY].append({
                "title": f["title"], "source": f["source"], "severity": f["severity"],
                "technique_id": tid, "mitre_tactic": f["_mitre"]["tactic"],
                "action": f["_mitre"]["action"],
            })
            continue

        high_confidence = any(a["priority"] in HIGH_CONFIDENCE_FALCO_PRIORITIES for a in matched_alerts)
        verdict = VERDICT_POTENTIAL_EXPLOITATION if high_confidence else VERDICT_COVERAGE_CONFIRMED

        results[verdict].append({
            "title": f["title"],
            "source": f["source"],
            "severity": f["severity"],
            "technique_id": tid,
            "mitre_tactic": f["_mitre"]["tactic"],
            "action": f["_mitre"]["action"],
            "falco_evidence": [
                {"rule": a["rule"], "priority": a["priority"], "target": a["target"], "output": a["output"][:200]}
                for a in matched_alerts
            ],
        })

    # Falco activity in technique families no static scanner flagged at all
    for tid, alerts in falco_by_technique.items():
        if tid not in static_technique_ids:
            results[VERDICT_RUNTIME_DETECTED].append({
                "technique_id": tid,
                "rules": sorted(set(a["rule"] for a in alerts)),
                "count": len(alerts),
                "target": alerts[0]["target"],
            })

    return results


# ─────────────────────────────────────────────────────────────────────────
# AI narrative
# ─────────────────────────────────────────────────────────────────────────

def build_narrative_context(results, max_items=6):
    lines = []
    for verdict in (VERDICT_POTENTIAL_EXPLOITATION, VERDICT_COVERAGE_CONFIRMED):
        for item in results[verdict][:max_items]:
            evidence = item["falco_evidence"][0]["output"] if item.get("falco_evidence") else ""
            lines.append(
                f"[{verdict}] {item['title']} ({item['source']}, {item['severity']}) "
                f"— technique {item['technique_id']} / {item['mitre_tactic']}\n"
                f"   Falco evidence: {evidence}"
            )
    return "\n".join(lines)


def ask_groq_correlation(context):
    if not GROQ_API_KEY:
        return "AI correlation narrative unavailable — no API key."
    if not context.strip():
        return "No coverage-confirmed or potential-exploitation findings to explain."

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a precise DevSecOps analyst. You receive findings where a "
                    "static scanner (build-time) and Falco (runtime) both flagged the "
                    "same MITRE ATT&CK technique on the actual deployed workload. "
                    "IMPORTANT: never claim a specific vulnerability was 'exploited' or "
                    "'confirmed exploited' — that is not what this data shows. Only say "
                    "that build-time and runtime evidence corroborate the same risk "
                    "category, and for POTENTIAL EXPLOITATION PATH items, note that the "
                    "runtime signal involved direct interaction with a sensitive "
                    "resource, which raises confidence but is not proof of exploitation "
                    "of that exact weakness. Max 5 sentences, ranked by severity."
                )
            },
            {"role": "user", "content": f"Findings:\n{context}\n\nSummarize what this evidence does and does not show."}
        ]
    }
    try:
        response = requests.post(url, headers=headers, json=payload)
        data = response.json()
        if "choices" not in data:
            print(f"⚠️ Groq API error {response.status_code}: {data}")
            return f"AI correlation narrative unavailable — Groq returned: {data.get('error', {}).get('message', data)}"
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"AI correlation error: {e}"


# ─────────────────────────────────────────────────────────────────────────
# Metrics / reporting
# ─────────────────────────────────────────────────────────────────────────

def push_correlation_metrics(results):
    lines = [
        "# HELP security_verdict_total Findings by correlation verdict\n"
        "# TYPE security_verdict_total gauge\n"
    ]
    metric_name_map = {
        VERDICT_STATIC_ONLY: "static_only",
        VERDICT_RUNTIME_DETECTED: "runtime_detected",
        VERDICT_COVERAGE_CONFIRMED: "detection_coverage_confirmed",
        VERDICT_POTENTIAL_EXPLOITATION: "potential_exploitation_path",
    }
    for verdict, label in metric_name_map.items():
        lines.append(f'security_verdict_total{{verdict="{label}"}} {len(results[verdict])}\n')

    lines.append(
        "# HELP security_correlation_last_run_timestamp Unix timestamp of last correlation run\n"
        "# TYPE security_correlation_last_run_timestamp gauge\n"
        f"security_correlation_last_run_timestamp {int(time.time()) * 1000}\n"
    )

    try:
        response = requests.post(
            f"{PUSHGATEWAY_URL}/metrics/job/ai_correlation_engine",
            data="".join(lines),
            headers={"Content-Type": "text/plain"},
        )
        print(f"Correlation metrics pushed: {response.status_code}")
    except Exception as e:
        print(f"⚠️ Prometheus push error: {e}")


def save_correlation_report(results, path=CORRELATION_REPORT_PATH):
    try:
        with open(path, "w") as f:
            json.dump({"generated_at": int(time.time()), "results": results}, f, indent=2)
        print(f"📄 Correlation report saved to {path}")
    except Exception as e:
        print(f"⚠️ Could not write correlation report: {e}")


# ─────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────

def main():
    _, _, trivy_findings = parse_trivy_report()
    _, _, _, kics_findings = parse_kics_report()
    _, _, tfsec_findings = parse_tfsec_output()
    static_findings = trivy_findings + kics_findings + tfsec_findings

    falco_alerts = parse_falco_alerts()

    results = classify(static_findings, falco_alerts)
    save_correlation_report(results)
    push_correlation_metrics(results)

    n_static_only = len(results[VERDICT_STATIC_ONLY])
    n_runtime_only = len(results[VERDICT_RUNTIME_DETECTED])
    n_coverage = len(results[VERDICT_COVERAGE_CONFIRMED])
    n_exploitation = len(results[VERDICT_POTENTIAL_EXPLOITATION])

    print(f"{VERDICT_EMOJI[VERDICT_STATIC_ONLY]} Static only: {n_static_only}")
    print(f"{VERDICT_EMOJI[VERDICT_RUNTIME_DETECTED]} Runtime detected (no static match): {n_runtime_only}")
    print(f"{VERDICT_EMOJI[VERDICT_COVERAGE_CONFIRMED]} Detection coverage confirmed: {n_coverage}")
    print(f"{VERDICT_EMOJI[VERDICT_POTENTIAL_EXPLOITATION]} Potential exploitation path: {n_exploitation}")

    if n_coverage == 0 and n_exploitation == 0:
        print("✅ No build-time findings corroborated by runtime signals this run.")
        return

    context = build_narrative_context(results)
    narrative = ask_groq_correlation(context)

    message = (
        "*🔗 AI Correlation Engine Report*\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        f"{VERDICT_EMOJI[VERDICT_STATIC_ONLY]} Static only: {n_static_only}\n"
        f"{VERDICT_EMOJI[VERDICT_RUNTIME_DETECTED]} Runtime detected only: {n_runtime_only}\n"
        f"{VERDICT_EMOJI[VERDICT_COVERAGE_CONFIRMED]} Detection coverage confirmed: {n_coverage}\n"
        f"{VERDICT_EMOJI[VERDICT_POTENTIAL_EXPLOITATION]} Potential exploitation path: {n_exploitation}\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        f"🤖 *Analysis:*\n{narrative}\n"
    )

    top_items = (
        results[VERDICT_POTENTIAL_EXPLOITATION][:3]
        + results[VERDICT_COVERAGE_CONFIRMED][:3 - len(results[VERDICT_POTENTIAL_EXPLOITATION][:3])]
    )
    if top_items:
        message += "\n🗺️ *Top correlated findings:*\n"
        for i, item in enumerate(top_items, 1):
            verdict = VERDICT_POTENTIAL_EXPLOITATION if item in results[VERDICT_POTENTIAL_EXPLOITATION] else VERDICT_COVERAGE_CONFIRMED
            message += (
                f"\n*{i}. {item['title']}* {VERDICT_EMOJI[verdict]} {verdict}\n"
                f" 📍 {item['mitre_tactic']} / {item['technique_id']}\n"
                f" ✅ {item['action']}\n"
            )

    print(message)
    send_telegram(message)

    if n_exploitation > 0:
        exit(1)  # runtime evidence of direct interaction with a sensitive resource — worth blocking on


if __name__ == "__main__":
    main()
