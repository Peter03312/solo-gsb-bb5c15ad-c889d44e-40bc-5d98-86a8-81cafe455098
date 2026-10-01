"""请求体模型。时间戳必须显式携带时区（按 UTC 归一化存储）。"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


def _require_tz_utc(v: datetime) -> datetime:
    if v.tzinfo is None:
        raise ValueError(
            "timestamp must carry an explicit timezone, e.g. 2026-01-01T00:00:00Z"
        )
    return v.astimezone(timezone.utc)


def _norm_domain(v: str) -> str:
    d = v.strip().lower().rstrip(".")
    if not d or any(ch.isspace() for ch in d):
        raise ValueError("invalid domain name")
    return d


class TrustRootImport(BaseModel):
    version: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    pem: str = Field(min_length=1)


class CrlSnapshotImport(BaseModel):
    version: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    pem: str = Field(min_length=1)


class CertificateImport(BaseModel):
    pem: str = Field(min_length=1)
    label: Optional[str] = Field(default=None, max_length=128)


class ServiceWindowCreate(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    certificate_fingerprint: str = Field(min_length=64, max_length=64)
    role: Literal["current", "planned"]
    start: datetime
    end: datetime

    _tz = field_validator("start", "end")(_require_tz_utc)
    _dom = field_validator("domain")(_norm_domain)


class PlanCreate(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    eval_start: datetime
    eval_end: datetime
    trust_root_version: Optional[str] = Field(default=None, max_length=64)
    crl_snapshot_version: Optional[str] = Field(default=None, max_length=64)

    _tz = field_validator("eval_start", "eval_end")(_require_tz_utc)
    _dom = field_validator("domain")(_norm_domain)


class EvaluateRequest(BaseModel):
    trust_root_version: Optional[str] = Field(default=None, max_length=64)
    # 省略 → 沿用计划当前选择；显式 null → 取消快照、回到无快照语义；
    # 未知快照版本 → 404（不得静默按安全处理）。
    crl_snapshot_version: Optional[str] = Field(default=None, max_length=64)


class WindowChangeWindow(BaseModel):
    """窗口变更中待登记的新窗口（域名取自路径，整组仅限单一域名）。"""

    certificate_fingerprint: str = Field(min_length=64, max_length=64)
    role: Literal["current", "planned"]
    start: datetime
    end: datetime

    _tz = field_validator("start", "end")(_require_tz_utc)


class WindowChangeRequest(BaseModel):
    """按域名成组变更：撤下 delete_window_ids 中的旧窗口，登记 add_windows 新窗口。

    预演不改动任何数据并返回 commit_token；提交须携带该令牌，且至少包含
    一项删除或登记。
    """

    domain: str = Field(min_length=1, max_length=253)
    delete_window_ids: list[int] = Field(default_factory=list)
    add_windows: list[WindowChangeWindow] = Field(default_factory=list)
    commit_token: Optional[str] = Field(default=None, max_length=4096)

    _dom = field_validator("domain")(_norm_domain)
