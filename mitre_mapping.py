# MITRE ATT&CK Mapping for DevSecOps findings
# Maps security findings to MITRE ATT&CK Tactics and Techniques

MITRE_MAPPING = {

    # ─── HIGH ───────────────────────────────────────────────────────────────
    "Passwords And Secrets - Generic Password": {
        "tactic": "TA0006 - Credential Access",
        "technique": "T1552.001 - Unsecured Credentials: Credentials In Files",
        "risk": "Hardcoded credentials can be extracted by any user with repo access",
        "action": "Move secrets to HashiCorp Vault or GitHub Secrets immediately"
    },
    "Privilege Escalation Allowed": {
        "tactic": "TA0004 - Privilege Escalation",
        "technique": "T1611 - Escape to Host",
        "risk": "Container can gain more privileges than parent process, enabling host escape",
        "action": "Set allowPrivilegeEscalation: false in securityContext"
    },

    # ─── MEDIUM ─────────────────────────────────────────────────────────────
    "Container Capabilities Unrestricted": {
        "tactic": "TA0004 - Privilege Escalation",
        "technique": "T1548 - Abuse Elevation Control Mechanism",
        "risk": "Unnecessary Linux capabilities increase attack surface inside container",
        "action": "Add capabilities.drop: [ALL] in securityContext"
    },
    "Container Running With Low UID": {
        "tactic": "TA0004 - Privilege Escalation",
        "technique": "T1611 - Escape to Host",
        "risk": "Low UID may conflict with host user table, enabling privilege escalation",
        "action": "Set runAsUser to value >= 1000"
    },
    "Container Running As Root": {
        "tactic": "TA0004 - Privilege Escalation",
        "technique": "T1611 - Escape to Host",
        "risk": "Root in container = root on host if container escape occurs",
        "action": "Set runAsNonRoot: true and runAsUser: 1000"
    },
    "Shared Service Account": {
        "tactic": "TA0008 - Lateral Movement",
        "technique": "T1552.007 - Unsecured Credentials: Container API",
        "risk": "Shared SA token allows lateral movement between workloads if pod is compromised",
        "action": "Create dedicated ServiceAccount per workload, disable automounting"
    },
    "Service Account Token Automount Not Disabled": {
        "tactic": "TA0008 - Lateral Movement",
        "technique": "T1552.007 - Unsecured Credentials: Container API",
        "risk": "Automounted token gives API access to anyone with exec in pod",
        "action": "Set automountServiceAccountToken: false"
    },
    "Healthcheck Not Set": {
        "tactic": "TA0040 - Impact",
        "technique": "T1499 - Endpoint Denial of Service",
        "risk": "Without healthcheck, unhealthy containers receive traffic causing service degradation",
        "action": "Add healthcheck in docker-compose or livenessProbe in Kubernetes"
    },
    "Memory Not Limited": {
        "tactic": "TA0040 - Impact",
        "technique": "T1499.004 - Application Exhaustion Flood",
        "risk": "Unlimited memory allows single container to cause OOM on host",
        "action": "Set resources.limits.memory in container spec"
    },
    "Security Opt Not Set": {
        "tactic": "TA0005 - Defense Evasion",
        "technique": "T1562 - Impair Defenses",
        "risk": "Missing security options reduce OS-level protections (seccomp, apparmor)",
        "action": "Add security_opt: [no-new-privileges:true] in docker-compose"
    },

    # ─── LOW ────────────────────────────────────────────────────────────────
    "Cpus Not Limited": {
        "tactic": "TA0040 - Impact",
        "technique": "T1499.004 - Application Exhaustion Flood",
        "risk": "Unlimited CPU allows resource exhaustion affecting other workloads",
        "action": "Set resources.limits.cpu in container spec"
    },
    "Image Without Digest": {
        "tactic": "TA0001 - Initial Access",
        "technique": "T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain",
        "risk": "Image tag can be overwritten with malicious content without digest pinning",
        "action": "Pin images to SHA256 digest: image@sha256:..."
    },
    "Unpinned Actions Full Length Commit SHA": {
        "tactic": "TA0001 - Initial Access",
        "technique": "T1195.002 - Supply Chain Compromise",
        "risk": "Unpinned GitHub Actions can be replaced with malicious versions (as seen with KICS action)",
        "action": "Pin actions to full commit SHA instead of version tag"
    },
    "Healthcheck Instruction Missing": {
        "tactic": "TA0040 - Impact",
        "technique": "T1499 - Endpoint Denial of Service",
        "risk": "Docker cannot detect unhealthy container state",
        "action": "Add HEALTHCHECK instruction to Dockerfile"
    },
    "Multiple RUN, ADD, COPY, Instructions Listed": {
        "tactic": "TA0001 - Initial Access",
        "technique": "T1195.002 - Supply Chain Compromise",
        "risk": "Multiple layers increase attack surface and image size",
        "action": "Combine RUN instructions with && to reduce layers"
    },
    "Pod or Container Without LimitRange": {
        "tactic": "TA0040 - Impact",
        "technique": "T1499.004 - Application Exhaustion Flood",
        "risk": "No namespace-level resource boundaries allow single workload to exhaust cluster",
        "action": "Create LimitRange policy for namespace"
    },
    "Pod or Container Without ResourceQuota": {
        "tactic": "TA0040 - Impact",
        "technique": "T1499.004 - Application Exhaustion Flood",
        "risk": "No quota allows namespace to consume unlimited cluster resources",
        "action": "Create ResourceQuota for namespace"
    },
    "Service Does Not Target Pod": {
        "tactic": "TA0040 - Impact",
        "technique": "T1565 - Data Manipulation",
        "risk": "Misconfigured service selector may route traffic to wrong pods",
        "action": "Verify service selector matches pod labels exactly"
    },
    "Image Pull Policy Of The Container Is Not Set To Always": {
        "tactic": "TA0001 - Initial Access",
        "technique": "T1195.002 - Supply Chain Compromise",
        "risk": "Cached outdated images may contain known vulnerabilities",
        "action": "Set imagePullPolicy: Always for production workloads"
    },
}


def get_mitre_info(finding_name: str) -> dict:
    """Get MITRE ATT&CK mapping for a finding name."""
    # Exact match first
    if finding_name in MITRE_MAPPING:
        return MITRE_MAPPING[finding_name]

    # Partial match
    for key, value in MITRE_MAPPING.items():
        if key.lower() in finding_name.lower() or finding_name.lower() in key.lower():
            return value

    return {
        "tactic": "TA0000 - Unknown",
        "technique": "T0000 - Not mapped yet",
        "risk": "Review finding manually",
        "action": "Check KICS documentation for remediation"
    }


def format_mitre_for_telegram(finding_name: str, severity: str) -> str:
    """Format MITRE mapping for Telegram message."""
    info = get_mitre_info(finding_name)
    return (
        f"*{severity}* | {finding_name}\n"
        f"  📍 {info['tactic']}\n"
        f"  🔧 {info['technique']}\n"
        f"  ⚠️ {info['risk']}\n"
        f"  ✅ {info['action']}"
    )


if __name__ == "__main__":
    # Test mapping
    test_findings = [
        "Passwords And Secrets - Generic Password",
        "Shared Service Account",
        "Container Capabilities Unrestricted",
        "Unpinned Actions Full Length Commit SHA",
    ]

    print("=== MITRE ATT&CK Mapping Test ===\n")
    for finding in test_findings:
        print(format_mitre_for_telegram(finding, "MEDIUM"))
        print()
