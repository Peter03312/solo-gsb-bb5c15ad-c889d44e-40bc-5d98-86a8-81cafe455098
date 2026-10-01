"""FastAPI 路由层。"""
from __future__ import annotations

import contextlib

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse

from . import db, service
from .models import (
    CertificateImport,
    CrlSnapshotImport,
    EvaluateRequest,
    PlanCreate,
    ServiceWindowCreate,
    TrustRootImport,
    WindowChangeCommit,
    WindowChangePreview,
)

API = "/api/v1"


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    yield


app = FastAPI(
    title="TLS Certificate Renewal Verification Service",
    version="1.0.0",
    description=(
        "离线 TLS 证书换发核验服务：导入 PEM 证书链与分版本信任根，"
        "登记证书服务窗口，校验 X.509 链并评估指定区间内的证书覆盖断档，"
        "仅无断档计划可批准。"
    ),
    lifespan=lifespan,
)


@app.exception_handler(service.ApiError)
async def api_error_handler(request: Request, exc: service.ApiError):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.get("/")
def index():
    return {"service": app.title, "version": app.version, "docs": "/docs", "api": API}


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


# ----------------------------- 信任根版本 -----------------------------

@app.post(f"{API}/trust-roots", status_code=201, tags=["trust-roots"])
def import_trust_root(body: TrustRootImport):
    """导入一个版本的本地信任根（PEM  bundle，可含多张根证书）。

    首个导入的版本自动置为在用版本。PEM 格式错误返回 400，版本重复返回 409。
    """
    return service.import_trust_root(body.version, body.pem)


@app.get(f"{API}/trust-roots", tags=["trust-roots"])
def list_trust_roots():
    return {"items": service.list_trust_roots()}


@app.post(f"{API}/trust-roots/{{version}}/activate", tags=["trust-roots"])
def activate_trust_root(version: str):
    """切换在用信任根版本；冻结版本不一致的已批准计划转为待复核。"""
    return service.activate_trust_root(version)


# ----------------------------- 离线撤销快照（CRL） -----------------------------

@app.post(f"{API}/crl-snapshots", status_code=201, tags=["crl-snapshots"])
def import_crl_snapshot(body: CrlSnapshotImport):
    """导入带版本的一组 PEM CRL（不可变离线撤销快照）。

    服务逐张验证签名（须由已导入的 CA 证书签署且 cRLSign），并拒绝：
    重复版本（409）、同一签发者的冲突/重复列表（409）、
    无法解析或内容非法（400）、未知签发者（400）。
    """
    return service.import_crl_snapshot(body.version, body.pem)


@app.get(f"{API}/crl-snapshots", tags=["crl-snapshots"])
def list_crl_snapshots():
    return {"items": service.list_crl_snapshots()}


@app.get(f"{API}/crl-snapshots/{{version}}", tags=["crl-snapshots"])
def get_crl_snapshot(version: str):
    """查询快照详情（逐签发者的 thisUpdate/nextUpdate/撤销条数）。"""
    return service.get_crl_snapshot(version)


# ----------------------------- 证书 -----------------------------

@app.post(f"{API}/certificates", status_code=201, tags=["certificates"])
def import_certificate(body: CertificateImport):
    """导入 PEM 证书链（第一个块为叶子证书，其后为中间证书）。

    PEM 格式错误返回 400，证书指纹重复返回 409。
    """
    return service.import_certificate(body.pem, body.label)


@app.get(f"{API}/certificates", tags=["certificates"])
def list_certificates():
    return {"items": service.list_certificates()}


@app.get(f"{API}/certificates/{{fingerprint}}", tags=["certificates"])
def get_certificate(fingerprint: str):
    return service.get_certificate(fingerprint)


# ----------------------------- 服务窗口 -----------------------------

@app.post(f"{API}/service-windows", status_code=201, tags=["service-windows"])
def create_service_window(body: ServiceWindowCreate):
    """为域名登记证书服务窗口，UTC 半开区间 [start, end)。

    role: current=现用, planned=拟启用。窗口无效返回 400；
    窗口变动会使该域名下已批准计划转为待复核。
    """
    return service.create_window(
        body.domain, body.certificate_fingerprint, body.role, body.start, body.end
    )


@app.get(f"{API}/service-windows", tags=["service-windows"])
def list_service_windows(domain: str | None = Query(default=None)):
    return {"items": service.list_windows(domain)}


@app.delete(f"{API}/service-windows/{{window_id}}", tags=["service-windows"])
def delete_service_window(window_id: int):
    return service.delete_window(window_id)


# ----------------------------- 域名级窗口变更（预演 + 原子提交） -----------------------------

def _change_adds(body) -> list[dict]:
    return [
        {
            "fingerprint": a.certificate_fingerprint,
            "role": a.role,
            "start": a.start,
            "end": a.end,
        }
        for a in body.add_windows
    ]


@app.post(f"{API}/window-changes/preview", tags=["window-changes"])
def preview_window_change(body: WindowChangePreview):
    """预演一次域名级窗口变更（只读，不改动窗口/评估/批准历史）。

    输入待删除窗口 ID 与待登记窗口（证书指纹、角色、带时区起止时间），
    基于候选窗口集合按每个相关计划当前选定的信任根及可选 CRL 快照重算，
    返回各计划变更前后的断档区间、阻断原因与提交校验标识。
    空变更/重复删除/跨域删除/无效区间 → 400；未知窗口/证书指纹 → 404。
    """
    return service.preview_window_change(
        body.domain, body.delete_window_ids, _change_adds(body)
    )


@app.post(f"{API}/window-changes/commit", tags=["window-changes"])
def commit_window_change(body: WindowChangeCommit):
    """原子提交一次经预演的窗口变更（须携带预演返回的 change_token）。

    预演后域名窗口、相关计划状态或判定依据已变化 → 409（过期预演）；
    候选状态使任一当前已批准计划出现断档 → 409，整组拒绝、无部分变更；
    否则原子应用全部增删，相关已批准计划转待复核，历史冻结批准保留。
    """
    return service.commit_window_change(
        body.domain, body.change_token, body.delete_window_ids, _change_adds(body)
    )


# ----------------------------- 计划 / 评估 / 批准 -----------------------------

@app.post(f"{API}/plans", status_code=201, tags=["plans"])
def create_plan(body: PlanCreate):
    """创建换发计划并立即评估：评估区间内每一时刻至少一张证书
    处于服务窗口且通过 X.509 校验。返回全部断档区间与各证书不可用原因。

    可选 crl_snapshot_version：选择不可变的离线撤销快照；选择后评估还要求
    链上每张非根证书存在签发者 CRL 证据（在 [thisUpdate,nextUpdate) 内且
    未到撤销生效时刻），缺失/过期/已撤销时段计入断档。
    """
    return service.create_plan(
        body.domain,
        body.eval_start,
        body.eval_end,
        body.trust_root_version,
        body.crl_snapshot_version,
    )


@app.get(f"{API}/plans", tags=["plans"])
def list_plans(
    domain: str | None = Query(default=None),
    status: str | None = Query(default=None),
):
    return {"items": service.list_plans(domain, status)}


@app.get(f"{API}/plans/{{plan_id}}", tags=["plans"])
def get_plan(plan_id: int):
    return service.get_plan(plan_id)


@app.post(f"{API}/plans/{{plan_id}}/evaluate", tags=["plans"])
def evaluate_plan(plan_id: int, body: EvaluateRequest | None = None):
    """重新评估计划，可切换信任根版本与/或撤销快照。

    crl_snapshot_version 省略时沿用计划当前选择；显式传 null 取消快照；
    切换快照时已批准计划先转待复核（历史评估/批准保留）。
    """
    if body is None:
        return service.evaluate_plan(plan_id, None, None, snapshot_given=False)
    return service.evaluate_plan(
        plan_id,
        body.trust_root_version,
        body.crl_snapshot_version,
        snapshot_given="crl_snapshot_version" in body.model_fields_set,
    )


@app.post(f"{API}/plans/{{plan_id}}/approve", tags=["plans"])
def approve_plan(plan_id: int):
    """批准计划（仅无断档）。批准时冻结证书指纹、信任根版本与判定。"""
    return service.approve_plan(plan_id)


@app.get(f"{API}/plans/{{plan_id}}/evaluations", tags=["plans"])
def plan_evaluations(plan_id: int):
    """评估历史（全部保留）。"""
    return {"items": service.list_evaluations(plan_id)}


@app.get(f"{API}/plans/{{plan_id}}/approvals", tags=["plans"])
def plan_approvals(plan_id: int):
    """批准历史（含被取代的冻结判定，全部保留）。"""
    return {"items": service.list_approvals(plan_id)}
