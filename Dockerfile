FROM node:22-alpine AS frontend-build
WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LOGINSIGHT_UPLOAD_ROOT=/app/data/uploads \
    LOGINSIGHT_DB_PATH=/app/data/loginsight.db
WORKDIR /app
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY backend/rules ./rules
COPY sample_logs ./sample_logs
COPY --from=frontend-build /frontend/dist ./static
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY docker/start.sh /usr/local/bin/start-loginsight
RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app/data/uploads \
    && chmod +x /usr/local/bin/start-loginsight
EXPOSE 8080
CMD ["/usr/local/bin/start-loginsight"]
