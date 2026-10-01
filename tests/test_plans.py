"""评估、断档计算、批准与待复核流程测试。"""
import pytest

from tests.helpers import make_ca, make_cert, pem

DOMAIN = "svc.example.com"


@pytest.fixture()
def root(client):
    ca, ca_key = make_ca()
    client.post("/api/v1/trust-roots", json={"version": "v1", "pem": pem(ca)})
    return ca, ca_key


def _import_leaf(client, ca, ca_key, domain=DOMAIN, nb="2026-01-01", na="2027-01-01",
                 sans=None, issuer_cert=None, issuer_key=None, label=None):
    issuer_cert = issuer_cert or ca
    issuer_key = issuer_key or ca_key
    leaf, _ = make_cert(issuer_cert, issuer_key, domain, nb=nb, na=na,
                        sans=sans if sans is not None else [domain])
    chain = pem(leaf) if issuer_cert is ca else pem(leaf, issuer_cert)
    r = client.post("/api/v1/certificates", json={"pem": chain, "label": label})
    assert r.status_code == 201, r.text
    return r.json()["fingerprint_sha256"]


def _window(client, fp, start, end, role="current", domain=DOMAIN):
    r = client.post("/api/v1/service-windows", json={
        "domain": domain, "certificate_fingerprint": fp, "role": role,
        "start": start, "end": end,
    })
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _plan(client, domain=DOMAIN, start="2026-01-01T00:00:00Z", end="2027-01-01T00:00:00Z",
          version=None):
    body = {"domain": domain, "eval_start": start, "eval_end": end}
    if version:
        body["trust_root_version"] = version
    return client.post("/api/v1/plans", json=body)


def test_adjacent_windows_no_gap_and_approve(client, root):
    """窗口端点相接（end == start）不算断档，计划可批准并冻结。"""
    ca, ca_key = root
    cur = _import_leaf(client, ca, ca_key, na="2026-08-01", label="cur")
    nxt = _import_leaf(client, ca, ca_key, nb="2026-06-01", na="2027-02-01", label="next")
    _window(client, cur, "2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z", "current")
    _window(client, nxt, "2026-07-01T00:00:00Z", "2027-01-01T00:00:00Z", "planned")

    r = _plan(client)
    assert r.status_code == 201, r.text
    ev = r.json()["evaluation"]
    assert ev["has_gaps"] is False
    assert ev["gaps"] == []
    assert ev["trust_root_version"] == "v1"
    assert all(c["reasons"] == [] for c in ev["certificates"])
    plan_id = r.json()["plan"]["id"]

    r = client.post(f"/api/v1/plans/{plan_id}/approve")
    assert r.status_code == 200, r.text
    approval = r.json()["approval"]
    assert approval["trust_root_version"] == "v1"
    assert sorted(approval["cert_fingerprints"]) == sorted([cur, nxt])
    assert approval["verdict"]["has_gaps"] is False
    assert approval["superseded"] is False
    assert r.json()["plan"]["status"] == "approved"

    # 重复批准 → 409
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 409


def test_gap_detected_and_approve_rejected(client, root):
    ca, ca_key = root
    cur = _import_leaf(client, ca, ca_key, na="2026-07-01")
    nxt = _import_leaf(client, ca, ca_key, nb="2026-06-01", na="2027-02-01")
    _window(client, cur, "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z", "current")
    _window(client, nxt, "2026-06-15T00:00:00Z", "2027-01-01T00:00:00Z", "planned")

    r = _plan(client)
    ev = r.json()["evaluation"]
    assert ev["has_gaps"] is True
    assert ev["gaps"] == [{"start": "2026-06-01T00:00:00.000Z",
                           "end": "2026-06-15T00:00:00.000Z"}]

    r = client.post(f"/api/v1/plans/{r.json()['plan']['id']}/approve")
    assert r.status_code == 409
    assert "gap" in r.json()["detail"]


def test_san_mismatch_reason(client, root):
    ca, ca_key = root
    fp = _import_leaf(client, ca, ca_key, domain="other.example.com",
                      sans=["other.example.com"])
    _window(client, fp, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
    ev = _plan(client).json()["evaluation"]
    assert ev["has_gaps"] is True
    assert ev["gaps"] == [{"start": "2026-01-01T00:00:00.000Z",
                           "end": "2027-01-01T00:00:00.000Z"}]
    reasons = ev["certificates"][0]["reasons"]
    assert any("SAN" in r and "does not match" in r for r in reasons)
    assert ev["certificates"][0]["usable_intervals"] == []


def test_wildcard_san_matches(client, root):
    ca, ca_key = root
    fp = _import_leaf(client, ca, ca_key, sans=["*.example.com"])
    _window(client, fp, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
    ev = _plan(client).json()["evaluation"]
    assert ev["has_gaps"] is False


def test_expiry_inside_window_reason_and_gap(client, root):
    ca, ca_key = root
    fp = _import_leaf(client, ca, ca_key, na="2026-06-01")
    _window(client, fp, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
    ev = _plan(client).json()["evaluation"]
    cert = ev["certificates"][0]
    assert cert["usable_intervals"] == [{"start": "2026-01-01T00:00:00.000Z",
                                         "end": "2026-06-01T00:00:00.000Z"}]
    assert any("expires" in r for r in cert["reasons"])
    assert ev["gaps"] == [{"start": "2026-06-01T00:00:00.000Z",
                           "end": "2027-01-01T00:00:00.000Z"}]


def test_chain_incomplete_reason(client, root):
    """叶子证书由未导入信任根的 CA 签发 → 链不完整。"""
    other_ca, other_key = make_ca("Untrusted CA")
    fp = _import_leaf(client, other_ca, other_key)
    _window(client, fp, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
    ev = _plan(client).json()["evaluation"]
    reasons = ev["certificates"][0]["reasons"]
    assert any("chain incomplete" in r for r in reasons)


def test_non_ca_issuer_rejected(client, root):
    """签发者 basicConstraints CA=FALSE → CA 约束违规。"""
    ca, ca_key = root
    fake_inter, fake_key = make_cert(ca, ca_key, "Fake CA", is_ca=False)
    leaf, _ = make_cert(fake_inter, fake_key, DOMAIN, sans=[DOMAIN])
    r = client.post("/api/v1/certificates", json={"pem": pem(leaf, fake_inter)})
    fp = r.json()["fingerprint_sha256"]
    _window(client, fp, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
    ev = _plan(client).json()["evaluation"]
    reasons = ev["certificates"][0]["reasons"]
    assert any("CA constraint violation" in r and "CA=FALSE" in r for r in reasons)


def test_intermediate_chain_ok_and_path_length(client, root):
    ca, ca_key = root
    inter, inter_key = make_cert(ca, ca_key, "Inter CA", is_ca=True, path_length=0)
    fp = _import_leaf(client, ca, ca_key, issuer_cert=inter, issuer_key=inter_key)
    _window(client, fp, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
    assert _plan(client).json()["evaluation"]["has_gaps"] is False


def test_path_length_exceeded(client):
    """根 path_length=0 时，链中再出现中间 CA → 违规。"""
    ca, ca_key = make_ca(path_length=0)
    client.post("/api/v1/trust-roots", json={"version": "v1", "pem": pem(ca)})
    inter, inter_key = make_cert(ca, ca_key, "Inter CA", is_ca=True, path_length=0)
    leaf, _ = make_cert(inter, inter_key, DOMAIN, sans=[DOMAIN])
    r = client.post("/api/v1/certificates", json={"pem": pem(leaf, inter)})
    fp = r.json()["fingerprint_sha256"]
    _window(client, fp, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
    ev = _plan(client).json()["evaluation"]
    reasons = ev["certificates"][0]["reasons"]
    assert any("path length" in r for r in reasons)


def test_plan_unknown_trust_root_version_rejected(client, root):
    r = _plan(client, version="no-such-version")
    assert r.status_code == 404
    assert "unknown trust root version" in r.json()["detail"]


def test_plan_invalid_interval_rejected(client, root):
    r = _plan(client, start="2027-01-01T00:00:00Z", end="2026-01-01T00:00:00Z")
    assert r.status_code == 400


def test_window_change_marks_approved_plan_pending_review(client, root):
    ca, ca_key = root
    fp = _import_leaf(client, ca, ca_key)
    _window(client, fp, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
    plan_id = _plan(client).json()["plan"]["id"]
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 200

    # 新增窗口 → 已批准计划转待复核，历史批准保留且被取代
    fp2 = _import_leaf(client, ca, ca_key, nb="2026-06-01", na="2027-06-01")
    r = client.post("/api/v1/service-windows", json={
        "domain": DOMAIN, "certificate_fingerprint": fp2, "role": "planned",
        "start": "2026-06-01T00:00:00Z", "end": "2027-06-01T00:00:00Z",
    }).json()
    assert r["plans_marked_pending_review"] == 1

    plan = client.get(f"/api/v1/plans/{plan_id}").json()
    assert plan["status"] == "pending_review"
    approvals = client.get(f"/api/v1/plans/{plan_id}/approvals").json()["items"]
    assert len(approvals) == 1 and approvals[0]["superseded"] is True
    assert approvals[0]["verdict"]["has_gaps"] is False  # 历史判定保留

    # 复核：重新评估无断档后可再次批准
    r = client.post(f"/api/v1/plans/{plan_id}/evaluate")
    assert r.json()["has_gaps"] is False
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 200
    approvals = client.get(f"/api/v1/plans/{plan_id}/approvals").json()["items"]
    assert len(approvals) == 2
    assert [a["superseded"] for a in approvals] == [True, False]


def test_trust_root_reversion_marks_pending_review(client, root):
    ca, ca_key = root
    fp = _import_leaf(client, ca, ca_key)
    _window(client, fp, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
    plan_id = _plan(client).json()["plan"]["id"]
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 200

    # 导入并激活新版本信任根 → 冻结版本不一致的已批准计划转待复核
    ca2, _ = make_ca("Root V2")
    client.post("/api/v1/trust-roots", json={"version": "v2", "pem": pem(ca2)})
    r = client.post("/api/v1/trust-roots/v2/activate")
    assert r.status_code == 200
    assert r.json()["plans_marked_pending_review"] == 1
    assert client.get(f"/api/v1/plans/{plan_id}").json()["status"] == "pending_review"

    # 历史评估全部保留
    evals = client.get(f"/api/v1/plans/{plan_id}/evaluations").json()["items"]
    assert len(evals) == 1 and evals[0]["trust_root_version"] == "v1"

    # 用新版本复核：旧证书链不到新根 → 出现断档与原因
    r = client.post(f"/api/v1/plans/{plan_id}/evaluate", json={"trust_root_version": "v2"})
    ev = r.json()
    assert ev["trust_root_version"] == "v2"
    assert ev["has_gaps"] is True
    assert any("chain incomplete" in reason
               for reason in ev["certificates"][0]["reasons"])
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 409


def test_overlapping_windows_union(client, root):
    """两个窗口各自都有缺口，但并集覆盖全区间 → 无断档。"""
    ca, ca_key = root
    a = _import_leaf(client, ca, ca_key, na="2026-07-01")
    b = _import_leaf(client, ca, ca_key, nb="2026-06-01", na="2027-02-01")
    _window(client, a, "2026-01-01T00:00:00Z", "2026-08-01T00:00:00Z", "current")
    _window(client, b, "2026-05-01T00:00:00Z", "2027-01-01T00:00:00Z", "planned")
    ev = _plan(client).json()["evaluation"]
    assert ev["has_gaps"] is False


def test_window_outside_eval_interval(client, root):
    ca, ca_key = root
    fp = _import_leaf(client, ca, ca_key)
    _window(client, fp, "2025-01-01T00:00:00Z", "2025-06-01T00:00:00Z")
    ev = _plan(client).json()["evaluation"]
    assert ev["has_gaps"] is True
    assert any("does not overlap" in r for r in ev["certificates"][0]["reasons"])
