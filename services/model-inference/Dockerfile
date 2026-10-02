# Build from repo root: docker build -f services/model-inference/Dockerfile .
FROM gcr.io/distroless/python3-debian12:nonroot@sha256:7d1042ce588ab97019fe95c24ffca7bc5a82ccdac572511d5e09bda4435c89c5
WORKDIR /app
COPY services/model-inference/app.py ./
COPY internal/privacy/forbidden_fields.txt ./
ENV FORBIDDEN_FIELDS_FILE=/app/forbidden_fields.txt PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65532:65532
EXPOSE 8080
HEALTHCHECK NONE
ENTRYPOINT ["python3", "/app/app.py"]
