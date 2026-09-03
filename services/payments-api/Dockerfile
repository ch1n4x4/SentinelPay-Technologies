FROM python:3.11

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Create a non-root user and group, then change ownership of the working directory
RUN groupadd -r appgroup && \
    useradd -r -g appgroup -d /app -s /sbin/nologin appuser && \
    chown -R appuser:appgroup /app

# Added HEALTHCHECK for the application on port 8001
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/health')" || exit 1

# CK-02 & IV-05 — Enforce the non-root USER directive
USER appuser

EXPOSE 8001

CMD ["python", "-m", "app.main"]
