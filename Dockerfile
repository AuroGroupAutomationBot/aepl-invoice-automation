FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 appgroup \
    && useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py index.html ./
RUN chown -R appuser:appgroup /app

USER 10001:10001
EXPOSE 8080
CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080} --no-server-header"]
