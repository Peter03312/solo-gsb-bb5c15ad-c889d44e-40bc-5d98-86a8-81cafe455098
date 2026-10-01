"""按域名成组窗口变更：预演、原子提交、阻断与过期令牌。"""
import pytest

from tests.helpers import make_ca, make_cert, make_crl, pem

DOMAIN = "renew.example.com"


@pytest.fixture()
def root(client):
    ca, ca_key = make_ca("Renew Root CA")
    client.post("/api/v1/trust-roots", json={"version": "v1", "pem": pem(ca)})
    return ca, ca_key


def _import_leaf(client, ca, ca_key, name, nb="2026-01-01", na="2027-01-01",
                 domain=DOMAIN):
    leaf, _ = make_cert(ca, ca_key, name, nb=nb, na=na, sans=[domain])
    r = client.post("/api/v1/certificates", json={"pem": pem(leaf), "label": name})
    assert r.status_code == 201, r.text
    return r.json()["fingerprint_sha256"], leaf


def _window(client, fp, start, end, role="current", domain=DOMAIN):
    r = client.post("/api/v1/service-windows", json={
        "domain": domain, "certificate_fingerprint": fp, "role": role,
        "start": start, "end": end,
    })
    assert r.status_code == 201, r.text
    return r.json()["id"]


@pytest.fixture()
def renewed_setup(client, root):
    """无断档且已批准的换发基底：cur [01-01,07-01) + planned [07-01,次年01-01)。"""
    ca, ca_key = root
    cur_fp, _ = _import_leaf(client, ca, ca_key, "cur", na="2026-08-01")
    nxt_fp, nxt_cert = _import_leaf(client, ca, ca_key, "next",
                                    nb="2026-06-01", na="2027-02-01")
    # 用于换发演练的替换证书：覆盖整个评估区间
    rep_fp, _ = _import_leaf(client, ca, ca_key, "replacement",
                             nb="2025-12-01", na="2027-06-01")
    # 只覆盖年中之后的替换证书：用于构造断档场景
    late_fp, _ = _import_leaf(client, ca, ca_key, "late",
                              nb="2026-06-01", na="2027-06-01")
    cur_w = _window(client, cur_fp, "2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z",
                    "current")
    nxt_w = _window(client, nxt_fp, "2026-07-01T00:00:00Z", "2027-01-01T00:00:00Z",
                    "planned")
    r = client.post("/api/v1/plans", json={
        "domain": DOMAIN,
        "eval_start": "2026-01-01T00:00:00Z",
        "eval_end": "2027-01-01T00:00:00Z",
    })
    plan_id = r.json()["plan"]["id"]
    assert r.json()["evaluation"]["has_gaps"] is False
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 200
    return {
        "cur_fp": cur_fp, "nxt_fp": nxt_fp, "rep_fp": rep_fp, "late_fp": late_fp,
        "nxt_cert": nxt_cert,
        "cur_w": cur_w, "nxt_w": nxt_w, "plan_id": plan_id,
    }


def _change_body(setup, delete, add_start, add_end, role="current", token=None,
                 fp=None):
    body = {
        "domain": DOMAIN,
        "delete_window_ids": [delete] if delete is not None else [],
        "add_windows": [{
            "certificate_fingerprint": fp or setup["rep_fp"],
            "role": role,
            "start": add_start,
            "end": add_end,
        }],
    }
    if token is not None:
        body["commit_token"] = token
    return body


# ----------------------------- 预演 -----------------------------

def test_preview_returns_before_after_and_token(client, renewed_setup):
    s = renewed_setup
    # 撤下旧 current 窗口，登记同证书提前 15 天开始的新 current 窗口
    body = _change_body(s, s["cur_w"], "2026-01-01T00:00:00Z",
                        "2026-07-01T00:00:00Z")
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["blocked"] is False
    assert out["commit_token"] and out["commit_token"].count(".") == 1
    plan = out["plans"][0]
    assert plan["plan_id"] == s["plan_id"]
    assert plan["approved"] is True
    assert plan["would_block"] is False
    assert plan["before"]["has_gaps"] is False and plan["before"]["gaps"] == []
    assert plan["after"]["has_gaps"] is False and plan["after"]["gaps"] == []
    # 候选集合 = 剩余窗口 + 待登记窗口
    ids = {w["id"] for w in out["candidate_windows"]}
    assert s["cur_w"] not in ids
    assert "new-1" in ids
    assert len(out["add_windows"]) == 1
    assert out["add_windows"][0]["temporary_id"] == "new-1"


def test_preview_detects_gap_after_change(client, renewed_setup):
    s = renewed_setup
    # 新 current 窗口 06-15 才开始，替换证书 06-01 才生效：与年初之间留出断档
    body = _change_body(s, s["cur_w"], "2026-06-15T00:00:00Z",
                        "2026-07-01T00:00:00Z", fp=s["late_fp"])
    out = client.post(
        f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body
    ).json()
    assert out["blocked"] is True
    plan = out["plans"][0]
    assert plan["would_block"] is True
    assert plan["before"]["has_gaps"] is False
    assert plan["after"]["has_gaps"] is True
    assert plan["after"]["gaps"] == [
        {"start": "2026-01-01T00:00:00.000Z", "end": "2026-06-15T00:00:00.000Z"}
    ]


def test_preview_does_not_mutate_anything(client, renewed_setup):
    s = renewed_setup
    ev_before = client.get(f"/api/v1/plans/{s['plan_id']}/evaluations").json()["items"]
    ap_before = client.get(f"/api/v1/plans/{s['plan_id']}/approvals").json()["items"]
    wins_before = client.get("/api/v1/service-windows", params={"domain": DOMAIN}).json()["items"]

    body = _change_body(s, s["cur_w"], "2026-06-15T00:00:00Z",
                        "2026-07-01T00:00:00Z",
                        fp=s["late_fp"])  # 预演为阻断场景
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body)
    assert r.status_code == 200

    wins_after = client.get("/api/v1/service-windows", params={"domain": DOMAIN}).json()["items"]
    ev_after = client.get(f"/api/v1/plans/{s['plan_id']}/evaluations").json()["items"]
    ap_after = client.get(f"/api/v1/plans/{s['plan_id']}/approvals").json()["items"]
    plan = client.get(f"/api/v1/plans/{s['plan_id']}").json()

    assert wins_after == wins_before
    assert len(ev_after) == len(ev_before)
    assert ap_after == ap_before
    assert plan["status"] == "approved"  # 预演不改计划状态


# ----------------------------- 提交：成功路径 -----------------------------

def test_commit_applies_atomically_and_marks_pending_review(client, renewed_setup):
    s = renewed_setup
    body = _change_body(s, s["cur_w"], "2026-01-01T00:00:00Z",
                        "2026-07-01T00:00:00Z")
    token = client.post(
        f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body
    ).json()["commit_token"]

    r = client.post(
        f"/api/v1/domains/{DOMAIN}/window-change/commit",
        json=_change_body(s, s["cur_w"], "2026-01-01T00:00:00Z",
                          "2026-07-01T00:00:00Z", token=token),
    )
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["applied"] is True
    assert [w["id"] for w in out["deleted_windows"]] == [s["cur_w"]]
    assert len(out["added_windows"]) == 1
    assert out["added_windows"][0]["certificate_fingerprint"] == s["rep_fp"]
    assert out["plans_marked_pending_review"] == 1
    assert out["plans"][0]["status"] == "pending_review"
    assert out["plans"][0]["has_gaps"] is False

    # 窗口层面：旧的已删、新的已登记
    wins = client.get("/api/v1/service-windows", params={"domain": DOMAIN}).json()["items"]
    ids = {w["id"] for w in wins}
    assert s["cur_w"] not in ids
    assert len(wins) == 2

    # 计划转待复核；冻结批准保留但被取代；评估历史不新增
    plan = client.get(f"/api/v1/plans/{s['plan_id']}").json()
    assert plan["status"] == "pending_review"
    approvals = client.get(f"/api/v1/plans/{s['plan_id']}/approvals").json()["items"]
    assert len(approvals) == 1
    assert approvals[0]["superseded"] is True
    assert approvals[0]["verdict"]["has_gaps"] is False
    evals = client.get(f"/api/v1/plans/{s['plan_id']}/evaluations").json()["items"]
    assert len(evals) == 1


def test_commit_add_only_does_not_require_delete(client, renewed_setup):
    s = renewed_setup
    # 仅追加一个更早开始的窗口（不删除）：候选无断档，可提交
    body = _change_body(s, None, "2025-12-01T00:00:00Z", "2026-01-01T00:00:00Z",
                        role="planned")
    token = client.post(
        f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body
    ).json()["commit_token"]
    body["commit_token"] = token
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/commit", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["deleted_windows"] == []
    assert len(r.json()["added_windows"]) == 1


# ----------------------------- 提交：整组阻断 -----------------------------

def test_commit_rejected_whole_group_when_approved_plan_gaps(client, renewed_setup):
    s = renewed_setup
    body = _change_body(s, s["cur_w"], "2026-06-15T00:00:00Z",
                        "2026-07-01T00:00:00Z",
                        fp=s["late_fp"])
    prev = client.post(
        f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body
    ).json()
    assert prev["blocked"] is True

    body["commit_token"] = prev["commit_token"]
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/commit", json=body)
    assert r.status_code == 409
    assert "coverage gaps" in r.json()["detail"]

    # 无部分变更：窗口集合与计划状态均保持
    wins = client.get("/api/v1/service-windows", params={"domain": DOMAIN}).json()["items"]
    assert {w["id"] for w in wins} == {s["cur_w"], s["nxt_w"]}
    plan = client.get(f"/api/v1/plans/{s['plan_id']}").json()
    assert plan["status"] == "approved"
    approvals = client.get(f"/api/v1/plans/{s['plan_id']}/approvals").json()["items"]
    assert approvals[0]["superseded"] is False


def test_gap_in_non_approved_plan_does_not_block(client, root):
    """pending 计划的断档只报告、不阻断提交；提交后状态保持 pending。"""
    ca, ca_key = root
    fp, _ = _import_leaf(client, ca, ca_key, "lonely",
                         nb="2026-02-01", na="2027-02-01")
    wid = _window(client, fp, "2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z")
    plan_id = client.post("/api/v1/plans", json={
        "domain": DOMAIN,
        "eval_start": "2026-01-01T00:00:00Z",
        "eval_end": "2027-01-01T00:00:00Z",
    }).json()["plan"]["id"]

    # 唯一窗口被撤下、新窗口 02-01 才开始（覆盖至评估终点）→ 仅 1 月断档，
    # 但计划从未批准
    body = _change_body({"rep_fp": fp}, wid, "2026-02-01T00:00:00Z",
                        "2027-01-01T00:00:00Z")
    prev = client.post(
        f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body
    ).json()
    assert prev["blocked"] is False
    p = prev["plans"][0]
    assert p["approved"] is False and p["would_block"] is False
    assert p["after"]["has_gaps"] is True
    assert p["after"]["gaps"] == [
        {"start": "2026-01-01T00:00:00.000Z", "end": "2026-02-01T00:00:00.000Z"}
    ]

    body["commit_token"] = prev["commit_token"]
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/commit", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["plans_marked_pending_review"] == 0
    assert client.get(f"/api/v1/plans/{plan_id}").json()["status"] == "pending"


# ----------------------------- 提交令牌：缺失/非法/过期/不匹配 -----------------------------

def test_commit_without_token_rejected(client, renewed_setup):
    s = renewed_setup
    body = _change_body(s, s["cur_w"], "2026-01-01T00:00:00Z",
                        "2026-07-01T00:00:00Z")
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/commit", json=body)
    assert r.status_code == 400
    assert "commit_token is required" in r.json()["detail"]


@pytest.mark.parametrize("bad_token", ["garbage", "abc.xyz", ".", "a.", ".b"])
def test_commit_with_malformed_token_rejected(client, renewed_setup, bad_token):
    s = renewed_setup
    body = _change_body(s, s["cur_w"], "2026-01-01T00:00:00Z",
                        "2026-07-01T00:00:00Z", token=bad_token)
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/commit", json=body)
    assert r.status_code == 400
    assert "commit token" in r.json()["detail"]


def test_token_signature_must_match(client, renewed_setup):
    s = renewed_setup
    body = _change_body(s, s["cur_w"], "2026-01-01T00:00:00Z",
                        "2026-07-01T00:00:00Z")
    token = client.post(
        f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body
    ).json()["commit_token"]
    body_part, _sig = token.split(".")
    body["commit_token"] = body_part + "." + ("0" * len(_sig))
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/commit", json=body)
    assert r.status_code == 400
    assert "signature mismatch" in r.json()["detail"]


def test_commit_payload_mismatch_rejected(client, renewed_setup):
    s = renewed_setup
    body = _change_body(s, s["cur_w"], "2026-01-01T00:00:00Z",
                        "2026-07-01T00:00:00Z")
    token = client.post(
        f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body
    ).json()["commit_token"]
    # 用同一令牌提交不同参数（新窗口开始时间变了）→ 409
    other = _change_body(s, s["cur_w"], "2026-01-02T00:00:00Z",
                         "2026-07-01T00:00:00Z", token=token)
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/commit", json=other)
    assert r.status_code == 409
    assert "do not match" in r.json()["detail"]
    # 失败后无变更
    wins = client.get("/api/v1/service-windows", params={"domain": DOMAIN}).json()["items"]
    assert {w["id"] for w in wins} == {s["cur_w"], s["nxt_w"]}


def test_token_stale_after_unrelated_window_change(client, renewed_setup):
    s = renewed_setup
    body = _change_body(s, s["cur_w"], "2026-01-01T00:00:00Z",
                        "2026-07-01T00:00:00Z")
    token = client.post(
        f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body
    ).json()["commit_token"]
    # 预演之后通过原有单窗口接口追加窗口 → 域名窗口状态变化
    r = client.post("/api/v1/service-windows", json={
        "domain": DOMAIN, "certificate_fingerprint": s["nxt_fp"], "role": "planned",
        "start": "2027-01-01T00:00:00Z", "end": "2027-02-01T00:00:00Z",
    })
    assert r.status_code == 201
    # 该变动本身已使计划转待复核
    body["commit_token"] = token
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/commit", json=body)
    assert r.status_code == 409
    assert "stale" in r.json()["detail"]


def test_token_stale_after_plan_status_change(client, root):
    ca, ca_key = root
    fp_a, _ = _import_leaf(client, ca, ca_key, "a", na="2027-02-01")
    _window(client, fp_a, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
    p1 = client.post("/api/v1/plans", json={
        "domain": DOMAIN, "eval_start": "2026-01-01T00:00:00Z",
        "eval_end": "2027-01-01T00:00:00Z"}).json()["plan"]["id"]
    client.post(f"/api/v1/plans/{p1}/approve")
    p2 = client.post("/api/v1/plans", json={
        "domain": DOMAIN, "eval_start": "2026-01-01T00:00:00Z",
        "eval_end": "2026-06-01T00:00:00Z"}).json()["plan"]["id"]

    body = {"domain": DOMAIN, "delete_window_ids": [], "add_windows": [{
        "certificate_fingerprint": fp_a, "role": "planned",
        "start": "2027-01-01T00:00:00Z", "end": "2027-06-01T00:00:00Z"}]}
    token = client.post(
        f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body
    ).json()["commit_token"]
    # 预演后批准了同域名另一个计划 → 相关计划状态变化
    assert client.post(f"/api/v1/plans/{p2}/approve").status_code == 200
    body["commit_token"] = token
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/commit", json=body)
    assert r.status_code == 409
    assert "stale" in r.json()["detail"]


def test_plain_reevaluation_does_not_invalidate_token(client, renewed_setup):
    """只新增评估历史（计划状态/信任根/快照未变）不应使预演过期。"""
    s = renewed_setup
    body = _change_body(s, s["cur_w"], "2026-01-01T00:00:00Z",
                        "2026-07-01T00:00:00Z")
    token = client.post(
        f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body
    ).json()["commit_token"]
    client.post(f"/api/v1/plans/{s['plan_id']}/evaluate")
    body["commit_token"] = token
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/commit", json=body)
    assert r.status_code == 200, r.text


def test_token_cannot_be_reused_after_commit(client, renewed_setup):
    s = renewed_setup
    body = _change_body(s, s["cur_w"], "2026-01-01T00:00:00Z",
                        "2026-07-01T00:00:00Z")
    token = client.post(
        f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body
    ).json()["commit_token"]
    body["commit_token"] = token
    assert client.post(
        f"/api/v1/domains/{DOMAIN}/window-change/commit", json=body
    ).status_code == 200
    # 再次使用同一令牌 → 域名窗口状态已变化 → 过期
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/commit", json=body)
    assert r.status_code == 409


def test_token_domain_scoped(client, renewed_setup):
    s = renewed_setup
    body = _change_body(s, s["cur_w"], "2026-01-01T00:00:00Z",
                        "2026-07-01T00:00:00Z")
    token = client.post(
        f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body
    ).json()["commit_token"]
    body["commit_token"] = token
    r = client.post(
        "/api/v1/domains/other.example.com/window-change/commit", json=body
    )
    assert r.status_code == 400  # body/path domain 不一致先报
    body2 = dict(body)
    body2["domain"] = "other.example.com"
    r = client.post(
        "/api/v1/domains/other.example.com/window-change/commit", json=body2
    )
    assert r.status_code == 409
    assert "different domain" in r.json()["detail"]


# ----------------------------- 请求校验 -----------------------------

def test_empty_change_rejected(client, renewed_setup):
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/preview", json={
        "domain": DOMAIN, "delete_window_ids": [], "add_windows": []})
    assert r.status_code == 400
    assert "empty window change" in r.json()["detail"]


def test_invalid_new_window_interval_rejected(client, renewed_setup):
    s = renewed_setup
    body = _change_body(s, None, "2026-07-01T00:00:00Z",
                        "2026-01-01T00:00:00Z")
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body)
    assert r.status_code == 400
    assert "invalid time window" in r.json()["detail"]
    # 空区间
    body["add_windows"][0]["end"] = "2026-07-01T00:00:00Z"
    body["add_windows"][0]["start"] = "2026-07-01T00:00:00Z"
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body)
    assert r.status_code == 400


def test_naive_datetime_rejected(client, renewed_setup):
    s = renewed_setup
    body = _change_body(s, None, "2026-01-01T00:00:00", "2026-07-01T00:00:00")
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body)
    assert r.status_code == 422


def test_offset_timezone_normalized_to_utc(client, renewed_setup):
    """带非 UTC 显式时区的时间戳按 UTC 归一化后再参与计算与签名。"""
    s = renewed_setup
    # +08:00 的 2026-01-01T08:00 即 UTC 2026-01-01T00:00；提交按同一参数应一致
    body = _change_body(s, None, "2025-12-01T08:00:00+08:00",
                        "2026-01-01T08:00:00+08:00", role="planned")
    prev = client.post(
        f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body
    ).json()
    assert prev["add_windows"][0]["start"] == "2025-12-01T00:00:00.000Z"
    assert prev["add_windows"][0]["end"] == "2026-01-01T00:00:00.000Z"
    body["commit_token"] = prev["commit_token"]
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/commit", json=body)
    assert r.status_code == 200, r.text
    got = r.json()["added_windows"][0]
    assert got["start"] == "2025-12-01T00:00:00.000Z"
    assert got["end"] == "2026-01-01T00:00:00.000Z"


def test_duplicate_delete_ids_rejected(client, renewed_setup):
    s = renewed_setup
    body = {"domain": DOMAIN, "delete_window_ids": [s["cur_w"], s["cur_w"]],
            "add_windows": []}
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body)
    assert r.status_code == 400
    assert "duplicate window ids" in r.json()["detail"]


def test_unknown_window_id_rejected(client, renewed_setup):
    body = {"domain": DOMAIN, "delete_window_ids": [99999], "add_windows": []}
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body)
    assert r.status_code == 404
    assert "unknown service window id 99999" in r.json()["detail"]


def test_cross_domain_window_rejected(client, renewed_setup):
    s = renewed_setup
    # 为另一个域名登记窗口，再在本域名变更中引用它 → 跨域 400
    other = client.post("/api/v1/service-windows", json={
        "domain": "other.example.com", "certificate_fingerprint": s["nxt_fp"],
        "role": "current",
        "start": "2026-01-01T00:00:00Z", "end": "2026-07-01T00:00:00Z"}).json()
    body = {"domain": DOMAIN, "delete_window_ids": [other["id"]], "add_windows": []}
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body)
    assert r.status_code == 400
    assert "single domain" in r.json()["detail"]


def test_unknown_certificate_fingerprint_rejected(client, renewed_setup):
    body = {"domain": DOMAIN, "delete_window_ids": [], "add_windows": [{
        "certificate_fingerprint": "f" * 64, "role": "current",
        "start": "2026-01-01T00:00:00Z", "end": "2026-07-01T00:00:00Z"}]}
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body)
    assert r.status_code == 404
    assert "unknown certificate fingerprint" in r.json()["detail"]


def test_body_domain_must_match_path(client, renewed_setup):
    s = renewed_setup
    body = _change_body(s, None, "2026-01-01T00:00:00Z",
                        "2026-07-01T00:00:00Z")
    r = client.post(
        "/api/v1/domains/other.example.com/window-change/preview", json=body
    )
    assert r.status_code == 400
    assert "does not match path domain" in r.json()["detail"]


# ----------------------------- CRL 快照按计划所选版本重算 -----------------------------

def test_preview_respects_plan_selected_crl_snapshot(client, root):
    ca, ca_key = root
    cur_fp, _ = _import_leaf(client, ca, ca_key, "crl-cur", na="2026-08-01")
    plan_fp, _ = _import_leaf(client, ca, ca_key, "crl-plan",
                              nb="2026-06-01", na="2027-02-01")
    rev_fp, rev_cert = _import_leaf(client, ca, ca_key, "crl-revoked",
                                    nb="2025-12-01", na="2027-06-01")
    cur_w = _window(client, cur_fp, "2026-01-01T00:00:00Z",
                    "2026-07-01T00:00:00Z", "current")
    _window(client, plan_fp, "2026-07-01T00:00:00Z", "2027-01-01T00:00:00Z",
            "planned")

    # 快照撤销的是“拟换上来”的证书（2026-03-01 生效）；它当前没有任何窗口，
    # 所以现状无断档、计划可批准。
    crl_pem = make_crl(
        ca, ca_key, "2025-12-01", "2027-02-01",
        revoked=[(rev_cert.serial_number, "2026-03-01", None)], number=1,
    )
    assert client.post("/api/v1/crl-snapshots",
                       json={"version": "s1", "pem": crl_pem}).status_code == 201
    plan_id = client.post("/api/v1/plans", json={
        "domain": DOMAIN, "eval_start": "2026-01-01T00:00:00Z",
        "eval_end": "2027-01-01T00:00:00Z", "crl_snapshot_version": "s1"}
    ).json()["plan"]["id"]
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 200

    # 变更：撤下干净的旧 current 窗口，换上已撤销证书的窗口 [01-01,07-01)
    # → 03-01 起断档，整组阻断。
    body = {"domain": DOMAIN, "delete_window_ids": [cur_w], "add_windows": [{
        "certificate_fingerprint": rev_fp, "role": "current",
        "start": "2026-01-01T00:00:00Z", "end": "2026-07-01T00:00:00Z"}]}
    prev = client.post(
        f"/api/v1/domains/{DOMAIN}/window-change/preview", json=body
    ).json()
    plan = prev["plans"][0]
    assert plan["crl_snapshot_version"] == "s1"
    assert plan["before"]["has_gaps"] is False
    assert plan["after"]["has_gaps"] is True
    assert plan["after"]["gaps"] == [
        {"start": "2026-03-01T00:00:00.000Z", "end": "2026-07-01T00:00:00.000Z"}
    ]
    assert any("revoked" in r for r in plan["after"]["blocking_reasons"])
    assert prev["blocked"] is True

    body["commit_token"] = prev["commit_token"]
    r = client.post(f"/api/v1/domains/{DOMAIN}/window-change/commit", json=body)
    assert r.status_code == 409
    wins = client.get("/api/v1/service-windows", params={"domain": DOMAIN}).json()["items"]
    assert cur_w in {w["id"] for w in wins}
    assert client.get(f"/api/v1/plans/{plan_id}").json()["status"] == "approved"
