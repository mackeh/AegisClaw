FROM python:3.12-alpine
RUN apk add --no-cache git && \
    adduser -D -u 1000 skill
COPY stats.py /app/stats.py
USER skill
ENTRYPOINT ["python3", "/app/stats.py"]
