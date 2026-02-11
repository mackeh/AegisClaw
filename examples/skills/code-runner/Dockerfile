FROM python:3.12-alpine
RUN apk add --no-cache bash coreutils && \
    adduser -D -u 1000 skill && \
    mkdir -p /workspace/output && chown skill:skill /workspace/output
COPY runner.py /app/runner.py
USER skill
WORKDIR /workspace
ENTRYPOINT ["python3", "/app/runner.py"]
