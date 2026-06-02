FROM python:3.11-slim

# MIRAGE is deliberately vulnerable. This image is for LOCAL security research
# only -- never deploy it to a reachable network.

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV MIRAGE_LLM_PROVIDER=mock \
    MIRAGE_DB_PATH=/data/mirage.db \
    MIRAGE_HOST=0.0.0.0 \
    MIRAGE_PORT=8000

RUN mkdir -p /data

EXPOSE 8000

# Honour MIRAGE_SECURE / MIRAGE_LLM_PROVIDER from the environment.
CMD ["python", "run.py"]
