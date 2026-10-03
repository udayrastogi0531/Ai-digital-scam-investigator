FROM python:3.13-slim

# Local OCR support (the app falls back to a mock provider when tesseract is
# absent, but a real deployment wants it present).
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Migration tooling + application code.
COPY alembic.ini ./
COPY alembic ./alembic
COPY app ./app
COPY scripts ./scripts
COPY docker-entrypoint.sh ./

# Run as a non-root user.
RUN chmod +x ./docker-entrypoint.sh \
    && useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

# Bind to the port the host injects (Render/Railway/Heroku set PORT; default
# 10000 on Render).  Locally/compose there is no PORT, so 8000 is used.
ENV PORT=8000
EXPOSE 8000

# Liveness/readiness probe against the real health endpoint.  Shell form so
# $PORT expands; on Render this Docker HEALTHCHECK is ignored in favour of the
# platform health check path, but it stays correct anywhere the image is run.
HEALTHCHECK --interval=15s --timeout=5s --start-period=25s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:${PORT:-8000}/api/health', timeout=3).status == 200 else 1)"

# The entrypoint applies Alembic migrations, then execs the CMD.  Shell form so
# the host-provided $PORT is honoured without hardcoding it in the image.
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
