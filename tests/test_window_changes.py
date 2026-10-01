"""域名级窗口变更：预演（只读）、提交校验标识、原子提交与阻断规则。"""
import pytest

from tests.helpers import make_ca, make_cert, make_crl, pem

DOMAIN = "rot.example.com"
EVAL_START = "2026-01-01T00:00:00Z"
EVAL_END = "2027-01-01T00:00:00Z"


@pytest.fixture()
def root(client):
    ca, ca_key = make_ca()
    client.post("/api/v1/trust-roots", json={"version": "v1", "pem": pem(ca)})
    return ca, ca_key


def _import_leaf(client, ca, ca_key, domain=DOMAIN, nb="2026-01-01", na="2027-01-01",
                 sans=None):
    leaf, _ = make_cert(ca, ca_key, domain, nb=nb, na=na,
                        sans=sans if sans is not None else [domain])
    r = client.post("/api/v1/certificates", json={"pem": pem(leaf)})
    assert r.status_code == 201, r.text
    return r.json()["fingerprint_sha256"], leaf


def _window(client, fp, start, end, role="current", domain=DOMAIN):
    r = client.post("/api/v1/service-windows", json={
        "domain": domain, "certificate_fingerprint": fp, "role": role,
        "start": start, "end": end,
    })
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _plan(client, domain=DOMAIN, start=EVAL_START, end=EVAL_END, snapshot=None):
    body = {"domain": domain, "eval_start": start, "eval_end": end}
    if snapshot is not None:
        body["crl_snapshot_version"] = snapshot
    r = client.post("/api/v1/plans", json=body)
    assert r.status_code == 201, r.text
    return r.json()["plan"]["id"]


def _approve(client, plan_id):
    r = client.post(f"/api/v1/plans/{plan_id}/approve")
    assert r.status_code == 200, r.text


def _add(fp, start, end, role="planned"):
    return {"certificate_fingerprint": fp, "role": role, "start": start, "end": end}


def _preview(client, domain=DOMAIN, delete=(), add=()):
    return client.post("/api/v1/window-changes/preview", json={
        "domain": domain, "delete_window_ids": list(delete), "add_windows": list(add),
    })


def _commit(client, token, domain=DOMAIN, delete=(), add=()):
    return client.post("/api/v1/window-changes/commit", json={
        "domain": domain, "change_token": token,
        "delete_window_ids": list(delete), "add_windows": list(add),
    })


def _window_ids(client, domain=DOMAIN):
    items = client.get("/api/v1/service-windows", params={"domain": domain}).json()["items"]
    return [w["id"] for w in items]


@pytest.fixture()
def approved_plan(client, root):
    """current [01-01,07-01) + planned [07-01,2027-01-01) 相接，计划已批准。"""
    ca, ca_key = root
    cur, _ = _import_leaf(client, ca, ca_key, na="2026-08-01")
    nxt, _ = _import_leaf(client, ca, ca_key, nb="2026-06-01", na="2027-02-01")
    w_cur = _window(client, cur, "2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z", "current")
    w_nxt = _window(client, nxt, "2026-07-01T00:00:00Z", "2027-01-01T00:00:00Z", "planned")
    plan_id = _plan(client)
    _approve(client, plan_id)
    return {"ca": ca, "ca_key": ca_key, "cur": cur, "nxt": nxt,
            "w_cur": w_cur, "w_nxt": w_nxt, "plan_id": plan_id}


# ---------------------------------------------------------------------------
# 预演：只读 + 前后断档对比
# ---------------------------------------------------------------------------

def test_preview_read_only_and_reports_before_after(client, approved_plan):
    ctx = approved_plan
    plan_id = ctx["plan_id"]
    evals_before = client.get(f"/api/v1/plans/{plan_id}/evaluations").json()["items"]
    approvals_before = client.get(f"/api/v1/plans/{plan_id}/approvals").json()["items"]
    windows_before = client.get("/api/v1/service-windows").json()["items"]

    # 预演：撤下 current 窗口且无接替 → 变更后出现断档，已批准计划被阻断
    r = _preview(client, delete=[ctx["w_cur"]])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["domain"] == DOMAIN
    assert body["change_token"].startswith("wc1.")
    assert body["would_block"] is True
    assert len(body["blocking_reasons"]) == 1
    assert f"plan #{plan_id}" in body["blocking_reasons"][0]
    assert [w["id"] for w in body["delete_windows"]] == [ctx["w_cur"]]

    rep = body["plans"][0]
    assert rep["plan_id"] == plan_id and rep["status"] == "approved"
    assert rep["trust_root_version"] == "v1" and rep["crl_snapshot_version"] is None
    assert rep["before"]["has_gaps"] is False and rep["before"]["gaps"] == []
    assert rep["after"]["has_gaps"] is True
    assert rep["after"]["gaps"] == [{"start": "2026-01-01T00:00:00.000Z",
                                     "end": "2026-07-01T00:00:00.000Z"}]
    assert rep["blocking_reasons"]

    # 预演不得改动窗口、评估或批准历史
    assert client.get("/api/v1/service-windows").json()["items"] == windows_before
    assert client.get(f"/api/v1/plans/{plan_id}/evaluations").json()["items"] == evals_before
    after_approvals = client.get(f"/api/v1/plans/{plan_id}/approvals").json()["items"]
    assert after_approvals == approvals_before
    assert client.get(f"/api/v1/plans/{plan_id}").json()["status"] == "approved"


def test_preview_replacement_change_is_gap_free(client, approved_plan):
    ctx = approved_plan
    # 撤下 current 窗口并登记等价接替窗口 → 无断档、不阻断
    r = _preview(client, delete=[ctx["w_cur"]], add=[
        _add(ctx["cur"], "2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z", "current"),
    ])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["would_block"] is False and body["blocking_reasons"] == []
    rep = body["plans"][0]
    assert rep["before"]["has_gaps"] is False
    assert rep["after"]["has_gaps"] is False
    # 候选新窗口尚无 id（未登记）
    new_reports = [c for c in rep["after"]["certificates"] if c["window_id"] is None]
    assert len(new_reports) == 1
    assert new_reports[0]["fingerprint"] == ctx["cur"]
    assert new_reports[0]["usable_intervals"] == [
        {"start": "2026-01-01T00:00:00.000Z", "end": "2026-07-01T00:00:00.000Z"}
    ]


# ---------------------------------------------------------------------------
# 提交：原子应用 + 待复核 + 历史保留
# ---------------------------------------------------------------------------

def test_commit_applies_atomically_and_marks_pending_review(client, approved_plan):
    ctx = approved_plan
    plan_id = ctx["plan_id"]
    change = dict(delete=[ctx["w_cur"]], add=[
        _add(ctx["cur"], "2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z", "current"),
    ])
    token = _preview(client, **change).json()["change_token"]

    r = _commit(client, token, **change)
    assert r.status_code == 200, r.text
    body = r.json()
    assert [w["id"] for w in body["deleted_windows"]] == [ctx["w_cur"]]
    assert len(body["created_windows"]) == 1
    assert body["created_windows"][0]["role"] == "current"
    assert body["plans_marked_pending_review"] == 1

    # 窗口集合已原子替换
    items = client.get("/api/v1/service-windows", params={"domain": DOMAIN}).json()["items"]
    assert {w["id"] for w in items} == {ctx["w_nxt"], body["created_windows"][0]["id"]}

    # 已批准计划转待复核；历史冻结批准置 superseded 且完整保留
    assert client.get(f"/api/v1/plans/{plan_id}").json()["status"] == "pending_review"
    approvals = client.get(f"/api/v1/plans/{plan_id}/approvals").json()["items"]
    assert len(approvals) == 1
    assert approvals[0]["superseded"] is True
    assert approvals[0]["verdict"]["has_gaps"] is False

    # 复核闭环：重新评估无断档后可再次批准
    ev = client.post(f"/api/v1/plans/{plan_id}/evaluate").json()
    assert ev["has_gaps"] is False
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 200


def test_commit_blocked_when_approved_plan_would_gap(client, approved_plan):
    """候选状态使已批准计划断档 → 整组拒绝，不产生任何部分变更。"""
    ctx = approved_plan
    plan_id = ctx["plan_id"]
    token = _preview(client, delete=[ctx["w_cur"]]).json()["change_token"]

    r = _commit(client, token, delete=[ctx["w_cur"]])
    assert r.status_code == 409, r.text
    assert "no changes applied" in r.json()["detail"]

    # 无部分变更：窗口未删、计划仍 approved、批准未取代
    assert _window_ids(client) == [ctx["w_cur"], ctx["w_nxt"]]
    assert client.get(f"/api/v1/plans/{plan_id}").json()["status"] == "approved"
    approvals = client.get(f"/api/v1/plans/{plan_id}/approvals").json()["items"]
    assert approvals[0]["superseded"] is False


def test_commit_gap_for_non_approved_plan_does_not_block(client, root):
    """候选状态只让非 approved 计划断档 → 不阻断，可提交。"""
    ca, ca_key = root
    cur, _ = _import_leaf(client, ca, ca_key, na="2026-08-01")
    w_cur = _window(client, cur, "2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z")
    plan_id = _plan(client)  # pending，未批准
    token = _preview(client, delete=[w_cur]).json()["change_token"]
    r = _commit(client, token, delete=[w_cur])
    assert r.status_code == 200, r.text
    assert r.json()["plans_marked_pending_review"] == 0
    assert client.get(f"/api/v1/plans/{plan_id}").json()["status"] == "pending"
    assert _window_ids(client) == []


# ---------------------------------------------------------------------------
# 提交校验标识：过期/不符即拒绝
# ---------------------------------------------------------------------------

def test_stale_token_after_window_change_rejected(client, approved_plan):
    ctx = approved_plan
    change = dict(delete=[ctx["w_cur"]], add=[
        _add(ctx["cur"], "2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z", "current"),
    ])
    token = _preview(client, **change).json()["change_token"]
    # 预演后窗口集合变化（任何途径）→ 标识失效
    client.delete(f"/api/v1/service-windows/{ctx['w_nxt']}")
    r = _commit(client, token, **change)
    assert r.status_code == 409
    assert "stale" in r.json()["detail"]


def test_stale_token_after_plan_state_change_rejected(client, root):
    ca, ca_key = root
    cur, _ = _import_leaf(client, ca, ca_key)
    w_cur = _window(client, cur, EVAL_START, EVAL_END)
    plan_id = _plan(client)
    change = dict(delete=[w_cur], add=[_add(cur, EVAL_START, EVAL_END, "current")])
    token = _preview(client, **change).json()["change_token"]
    _approve(client, plan_id)  # 计划状态 pending → approved
    r = _commit(client, token, **change)
    assert r.status_code == 409
    assert "stale" in r.json()["detail"]


def test_stale_token_after_decision_basis_change_rejected(client, approved_plan):
    """重选信任根版本（判定依据变化）→ 旧标识失效。"""
    ctx = approved_plan
    change = dict(delete=[ctx["w_cur"]], add=[
        _add(ctx["cur"], "2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z", "current"),
    ])
    token = _preview(client, **change).json()["change_token"]
    ca2, _ = make_ca("Root V2")
    client.post("/api/v1/trust-roots", json={"version": "v2", "pem": pem(ca2)})
    r = client.post(f"/api/v1/plans/{ctx['plan_id']}/evaluate",
                    json={"trust_root_version": "v2"})
    assert r.status_code == 200
    r = _commit(client, token, **change)
    assert r.status_code == 409
    assert "stale" in r.json()["detail"]


def test_token_bound_to_change_content(client, approved_plan):
    """标识绑定预演的变更内容：提交不同变更须重新预演。"""
    ctx = approved_plan
    token = _preview(client, delete=[ctx["w_cur"]], add=[
        _add(ctx["cur"], "2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z", "current"),
    ]).json()["change_token"]
    # 携带合法标识但提交与预演不同的变更内容 → 拒绝
    r = _commit(client, token, delete=[ctx["w_cur"]], add=[
        _add(ctx["cur"], "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z", "current"),
    ])
    assert r.status_code == 409
    assert _window_ids(client) == [ctx["w_cur"], ctx["w_nxt"]]


# ---------------------------------------------------------------------------
# 输入校验
# ---------------------------------------------------------------------------

def test_invalid_interval_rejected(client, approved_plan):
    ctx = approved_plan
    bad = _add(ctx["cur"], "2026-07-01T00:00:00Z", "2026-01-01T00:00:00Z", "current")
    r = _preview(client, add=[bad])
    assert r.status_code == 400
    assert "invalid time window" in r.json()["detail"]
    # 提交路径同样校验
    r = _commit(client, "wc1.whatever", add=[bad])
    assert r.status_code == 400


def test_cross_domain_delete_rejected(client, approved_plan, root):
    ca, ca_key = root
    other_fp, _ = _import_leaf(client, ca, ca_key, domain="other.example.com",
                               sans=["other.example.com"])
    other_w = _window(client, other_fp, EVAL_START, EVAL_END, domain="other.example.com")
    r = _preview(client, domain=DOMAIN, delete=[other_w])
    assert r.status_code == 400
    assert "other.example.com" in r.json()["detail"]
    assert "single domain" in r.json()["detail"]


def test_duplicate_delete_rejected(client, approved_plan):
    ctx = approved_plan
    r = _preview(client, delete=[ctx["w_cur"], ctx["w_cur"]])
    assert r.status_code == 400
    assert "duplicate delete window id" in r.json()["detail"]


def test_unknown_window_rejected(client, approved_plan):
    r = _preview(client, delete=[999999])
    assert r.status_code == 404
    assert "unknown service window id" in r.json()["detail"]
    r = _commit(client, "wc1.x", delete=[999999])
    assert r.status_code == 404


def test_unknown_fingerprint_rejected(client, approved_plan):
    r = _preview(client, add=[_add("0" * 64, EVAL_START, EVAL_END)])
    assert r.status_code == 404
    assert "unknown certificate fingerprint" in r.json()["detail"]
    r = _commit(client, "wc1.x", add=[_add("0" * 64, EVAL_START, EVAL_END)])
    assert r.status_code == 404


def test_empty_change_rejected(client, approved_plan):
    r = _preview(client)
    assert r.status_code == 400
    assert "empty window change" in r.json()["detail"]


def test_naive_datetime_rejected(client, approved_plan):
    ctx = approved_plan
    r = client.post("/api/v1/window-changes/preview", json={
        "domain": DOMAIN,
        "add_windows": [{"certificate_fingerprint": ctx["cur"], "role": "planned",
                         "start": "2026-01-01T00:00:00", "end": "2026-07-01T00:00:00Z"}],
    })
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# CRL 快照：预演按相关计划当前选定的快照重算
# ---------------------------------------------------------------------------

def test_preview_uses_plan_crl_snapshot(client, root):
    """带快照计划：预演按该计划当前选定的快照重算撤销证据与断档。"""
    ca, ca_key = root
    cur, _ = _import_leaf(client, ca, ca_key)
    nxt, nxt_leaf = _import_leaf(client, ca, ca_key, nb="2026-06-01", na="2027-02-01")
    w_cur = _window(client, cur, EVAL_START, "2026-07-01T00:00:00Z", "current")
    _window(client, nxt, "2026-07-01T00:00:00Z", EVAL_END, "planned")

    # 快照撤销接替证书（2026-08-01 生效）→ 带快照重算后 8 月起断档
    crl = make_crl(ca, ca_key, "2025-12-01", "2027-02-01",
                   revoked=[(nxt_leaf.serial_number, "2026-08-01", None)])
    r = client.post("/api/v1/crl-snapshots", json={"version": "snap1", "pem": crl})
    assert r.status_code == 201, r.text

    plan_id = _plan(client, snapshot="snap1")
    ev = client.get(f"/api/v1/plans/{plan_id}").json()["latest_evaluation"]
    assert ev["has_gaps"] is True  # 8 月起接替证书被撤销 → 断档

    # 预演：撤下 planned 窗口、登记另一张未被撤销的证书窗口 → 断档消除
    alt, _ = _import_leaf(client, ca, ca_key, nb="2026-06-01", na="2027-02-01")
    w_planned = [w for w in client.get("/api/v1/service-windows",
                                       params={"domain": DOMAIN}).json()["items"]
                 if w["role"] == "planned"][0]["id"]
    r = _preview(client, delete=[w_planned],
                 add=[_add(alt, "2026-07-01T00:00:00Z", EVAL_END, "planned")])
    assert r.status_code == 200, r.text
    rep = r.json()["plans"][0]
    assert rep["crl_snapshot_version"] == "snap1"
    assert rep["before"]["has_gaps"] is True
    assert rep["after"]["has_gaps"] is False
    # after 的逐证书报告带撤销证据（快照语义保持）
    assert all("revocation" in c for c in rep["after"]["certificates"])
