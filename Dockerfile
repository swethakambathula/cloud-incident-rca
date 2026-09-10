FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN apt-get update && apt-get install -y --no-install-recommends git sed \
    && rm -rf /var/lib/apt/lists/* \
    && chmod +x entrypoint.sh
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["./entrypoint.sh"]
