FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY ai_security_advisor.py .
COPY debug_ci.py .

# Security: run as non-root user
RUN useradd -m -u 1000 appuser
USER appuser

CMD ["python3", "ai_security_advisor.py"]
