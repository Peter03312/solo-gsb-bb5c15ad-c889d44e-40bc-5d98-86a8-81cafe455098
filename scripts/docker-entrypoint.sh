#!/bin/sh
# 容器入口：按需初始化演示数据后启动 API 服务。
set -e

PYTHON_BIN="$(command -v python || command -v python3)"

if [ "${SEED_DEMO:-1}" = "1" ]; then
    echo "[entrypoint] SEED_DEMO=1, seeding demo data..."
    "$PYTHON_BIN" -m scripts.seed_demo
fi

exec "$PYTHON_BIN" -m uvicorn app.main:app --host "${HOST:-0.0.0.0}" --port "${PORT:-8000}"
