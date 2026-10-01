FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY app ./app
COPY scripts ./scripts
RUN chmod +x scripts/docker-entrypoint.sh

# TLS_CHECKER_DB: SQLite 数据库文件路径
# SEED_DEMO:      启动时是否写入演示数据（1/0）
# HOST/PORT:      监听地址与端口
ENV TLS_CHECKER_DB=/data/tls_checker.db \
    SEED_DEMO=1 \
    HOST=0.0.0.0 \
    PORT=8000

VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8000')+'/healthz',timeout=2)" || exit 1

ENTRYPOINT ["sh", "scripts/docker-entrypoint.sh"]
