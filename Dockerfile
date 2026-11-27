# ScopeGuard — Stateless Zero-Dependency Python 3.12 GCS Review Portal
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    HOST=0.0.0.0

WORKDIR /app

# Copy only shared GCS reader libraries and stateless web portal assets
COPY plugins/scopeguard/lib/ /app/plugins/scopeguard/lib/
COPY portal/ /app/portal/

# Run as non-root user for container runtime hardening
RUN useradd --create-home --uid 10001 scopeguard && \
    chown -R scopeguard:scopeguard /app
USER scopeguard

EXPOSE 8080

CMD ["python3", "portal/server.py"]
