FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 APP_HOST=0.0.0.0 APP_DATA_DIR=/data
WORKDIR /opt/portal
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 10001 portal \
    && useradd --uid 10001 --gid portal --no-create-home portal \
    && mkdir -p /data && chown portal:portal /data
COPY app app
COPY scripts scripts
COPY tests tests
COPY pytest.ini .
USER 10001:10001
EXPOSE 8000
CMD ["python", "-m", "app"]
