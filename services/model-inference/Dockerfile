# Build from repo root: docker build -f services/model-inference/Dockerfile .
# The model is not baked in: it is mounted at MODEL_DIR from the model store, pinned by sha256 (MODELS.json).
FROM python:3.11-slim-bookworm@sha256:0a310eeecf4e1f5a0743f9a6520c90c88d089c903ca5fd283f501e3a805f5f89 AS deps
COPY services/model-inference/requirements.txt /
RUN pip install --no-cache-dir --target /deps -r /requirements.txt

FROM gcr.io/distroless/python3-debian12:nonroot@sha256:7d1042ce588ab97019fe95c24ffca7bc5a82ccdac572511d5e09bda4435c89c5
WORKDIR /app
COPY --from=deps /deps /deps
COPY services/model-inference/app.py services/model-inference/mtls.py services/model-inference/l2.py ./
COPY internal/privacy/forbidden_fields.txt ./
ENV FORBIDDEN_FIELDS_FILE=/app/forbidden_fields.txt PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/deps
USER 65532:65532
EXPOSE 8080
HEALTHCHECK NONE
ENTRYPOINT ["python3", "/app/app.py"]
