"""SQLite 存储层。数据库路径由环境变量 TLS_CHECKER_DB 指定。"""
from __future__ import annotations

import contextlib
import os
import sqlite3

DB_PATH = os.environ.get("TLS_CHECKER_DB", "./data/tls_checker.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS trust_roots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    version     TEXT NOT NULL UNIQUE,
    pem         TEXT NOT NULL,
    cert_count  INTEGER NOT NULL,
    is_active   INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint_sha256  TEXT NOT NULL UNIQUE,
    label               TEXT,
    subject             TEXT NOT NULL,
    issuer              TEXT NOT NULL,
    san_dns             TEXT NOT NULL,          -- JSON 数组
    not_before          TEXT NOT NULL,
    not_after           TEXT NOT NULL,
    leaf_pem            TEXT NOT NULL,
    chain_pem           TEXT NOT NULL,          -- 导入的完整 PEM 链（叶子+中间证书）
    created_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS service_windows (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    domain                   TEXT NOT NULL,
    certificate_fingerprint  TEXT NOT NULL REFERENCES certificates(fingerprint_sha256),
    role                     TEXT NOT NULL CHECK (role IN ('current', 'planned')),
    start_utc                TEXT NOT NULL,
    end_utc                  TEXT NOT NULL,
    created_at               TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_windows_domain ON service_windows(domain);

CREATE TABLE IF NOT EXISTS plans (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    domain              TEXT NOT NULL,
    eval_start          TEXT NOT NULL,
    eval_end            TEXT NOT NULL,
    trust_root_version  TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'pending_review')),
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evaluations (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id             INTEGER NOT NULL REFERENCES plans(id),
    trust_root_version  TEXT NOT NULL,
    has_gaps            INTEGER NOT NULL,
    result_json         TEXT NOT NULL,
    created_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evaluations_plan ON evaluations(plan_id);

CREATE TABLE IF NOT EXISTS approvals (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id             INTEGER NOT NULL REFERENCES plans(id),
    trust_root_version  TEXT NOT NULL,
    cert_fingerprints   TEXT NOT NULL,          -- JSON 数组，批准时冻结
    verdict_json        TEXT NOT NULL,          -- 批准时冻结的判定结果
    superseded          INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approvals_plan ON approvals(plan_id);

-- 离线撤销快照：不可变的带版本 PEM CRL 集合
CREATE TABLE IF NOT EXISTS crl_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    version     TEXT NOT NULL UNIQUE,
    pem         TEXT NOT NULL,                  -- 原始 PEM bundle
    crl_count   INTEGER NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS crl_entries (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id              INTEGER NOT NULL REFERENCES crl_snapshots(id),
    issuer_dn                TEXT NOT NULL,     -- CRL issuer 标识名
    issuer_key_id            TEXT NOT NULL,     -- AKI hex；无 AKI 时为空串
    crl_number               INTEGER,           -- 无 cRLNumber 扩展时为 NULL
    this_update              TEXT NOT NULL,
    next_update              TEXT NOT NULL,
    revoked_count            INTEGER NOT NULL DEFAULT 0,
    pem                      TEXT NOT NULL       -- 单个 CRL 的 PEM
);
CREATE INDEX IF NOT EXISTS idx_crl_entries_snapshot ON crl_entries(snapshot_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_crl_entries_issuer
    ON crl_entries(snapshot_id, issuer_dn, issuer_key_id);
"""

# 既有库的轻量迁移：计划/评估/批准各增加撤销快照版本列（NULL = 未选择快照，
# 保持原评估与响应语义）。
_COLUMN_MIGRATIONS = (
    ("plans", "crl_snapshot_version", "TEXT"),
    ("evaluations", "crl_snapshot_version", "TEXT"),
    ("approvals", "crl_snapshot_version", "TEXT"),
)


def _migrate(conn) -> None:
    for table, column, decl in _COLUMN_MIGRATIONS:
        cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        if column not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def init_db() -> None:
    directory = os.path.dirname(os.path.abspath(DB_PATH))
    os.makedirs(directory, exist_ok=True)
    with connect() as conn:
        conn.executescript(_SCHEMA)
        _migrate(conn)


@contextlib.contextmanager
def connect():
    """打开一个连接，正常退出时提交，异常时回滚。"""
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
