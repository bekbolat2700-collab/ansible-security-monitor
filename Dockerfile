FROM python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535

WORKDIR /app

# curl: needed so the runtime T1048 (network exfiltration) Falco rule has a
# real binary to detect. Deliberate, documented trade-off — python:3.11-slim
# ships neither curl nor wget, so without this the rule can never fire.
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY mitre_mapping.py .
COPY ai_security_advisor.py .
COPY debug_ci.py .

# Security: run as non-root user
RUN useradd -m -u 1000 appuser
USER appuser

CMD ["sh", "-c", "touch /tmp/ready /tmp/healthy; while true; do python3 ai_security_advisor.py || true; touch /tmp/ready /tmp/healthy; sleep 300; done"]
