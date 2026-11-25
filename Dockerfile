ARG PYTHON_IMAGE
ARG UV_IMAGE
FROM ${UV_IMAGE} AS uvtools
FROM ${PYTHON_IMAGE} AS runtime
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=uvtools /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock ./
COPY src/ ./src/
RUN uv sync --locked --no-dev --no-editable
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin appuser
USER 10001:10001
EXPOSE 8080
CMD [".venv/bin/uvicorn", "hmt_devsecops.http:app", "--app-dir", "src", "--host", "0.0.0.0", "--port", "8080"]
