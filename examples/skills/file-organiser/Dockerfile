FROM python:3.12-alpine
RUN adduser -D -u 1000 skill
COPY organise.py /app/organise.py
USER skill
ENTRYPOINT ["python3", "/app/organise.py"]
