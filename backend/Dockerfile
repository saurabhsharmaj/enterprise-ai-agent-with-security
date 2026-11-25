# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv
COPY requirements.txt requirements-test.txt ./

# ---- runtime image (API + one-shot migrate job) ----------------------------------------------
FROM base AS runtime
RUN pip install -r requirements.txt && useradd --system --uid 10001 --no-create-home appuser
COPY alembic.ini ./
COPY migrations ./migrations
COPY app ./app
USER 10001
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]

# ---- test image -------------------------------------------------------------------------------
FROM base AS test
RUN pip install -r requirements-test.txt && useradd --system --uid 10001 --no-create-home appuser
COPY alembic.ini pytest.ini ./
COPY migrations ./migrations
COPY app ./app
COPY tests ./tests
USER 10001
CMD ["pytest", "-v"]
