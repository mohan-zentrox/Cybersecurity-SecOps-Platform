FROM python:3.12-slim AS base

# Security: run as a non-root user (see docs/THREAT_MODEL.md).
RUN groupadd --gid 1000 aegis && useradd --uid 1000 --gid aegis --shell /bin/bash --create-home aegis

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY alembic ./alembic
COPY alembic.ini .

RUN chown -R aegis:aegis /app
USER aegis

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
