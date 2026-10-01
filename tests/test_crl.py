"""离线撤销快照（CRL）：导入校验、逐证书撤销证据、断档、切换与冻结。"""
import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tests.helpers import (
    make_ca, make_cert, make_crl, pem, cert_serial, t, tamper_crl_pem,
)

DOMAIN = "crl.example.com"
EVAL_START = "2026-01-01T00:00:00Z"
EVAL_END = "2027-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# 构造辅助
# ---------------------------------------------------------------------------

def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _crl_no_next_update(issuer_cert, issuer_key, last_update="2025-01-01",
                        next_update="2025-06-01"):
    # 先生成合法 CRL，再通过 DER 手术删除可选的 nextUpdate 字段
    return tamper_crl_pem(
        make_crl(issuer_cert, issuer_key, last_update, next_update),
        "drop_next_update",
    )


@pytest.fixture()
def root(client):
    ca, ca_key = make_ca("CRL Root CA")
    client.post("/api/v1/trust-roots", json={"version": "v1", "pem": pem(ca)})
    return ca, ca_key


def _import_leaf_obj(ca, ca_key, domain=DOMAIN, nb="2026-01-01", na="2027-01-01",
                     issuer_cert=None, issuer_key=None, sans=None):
    issuer_cert = issuer_cert or ca
    issuer_key = issuer_key or ca_key
    leaf, _ = make_cert(issuer_cert, issuer_key, domain, nb=nb, na=na,
                        sans=sans if sans is not None else [domain])
    return leaf


def _post_leaf(client, leaf, issuer_cert, ca):
    chain = pem(leaf) if issuer_cert is ca else pem(leaf, issuer_cert)
    r = client.post("/api/v1/certificates", json={"pem": chain})
    assert r.status_code == 201, r.text
    return r.json()["fingerprint_sha256"]


def _window(client, fp, start=EVAL_START, end=EVAL_END, role="current", domain=DOMAIN):
    r = client.post("/api/v1/service-windows", json={
        "domain": domain, "certificate_fingerprint": fp, "role": role,
        "start": start, "end": end,
    })
    assert r.status_code == 201, r.text


def _snapshot(client, version, crl_pem):
    return client.post("/api/v1/crl-snapshots",
                       json={"version": version, "pem": crl_pem})


def _plan(client, snapshot=None, domain=DOMAIN, start=EVAL_START, end=EVAL_END):
    body = {"domain": domain, "eval_start": start, "eval_end": end}
    if snapshot is not None:
        body["crl_snapshot_version"] = snapshot
    return client.post("/api/v1/plans", json=body)


def _setup_single_leaf(client, ca, ca_key, **kw):
    leaf = _import_leaf_obj(ca, ca_key, **kw)
    fp = _post_leaf(client, leaf, ca, ca)
    _window(client, fp)
    return leaf, fp


# ---------------------------------------------------------------------------
# 快照导入
# ---------------------------------------------------------------------------

def test_import_snapshot_ok(client, root):
    ca, ca_key = root
    r = _snapshot(client, "s1", make_crl(ca, ca_key, "2025-12-01", "2027-02-01",
                                         number=7))
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["version"] == "s1" and body["crl_count"] == 1
    item = body["items"][0]
    assert item["issuer"].endswith("CRL Root CA")
    assert item["crl_number"] == 7
    assert item["this_update"] == "2025-12-01T00:00:00.000Z"
    assert item["next_update"] == "2027-02-01T00:00:00.000Z"
    assert item["revoked_count"] == 0

    items = client.get("/api/v1/crl-snapshots").json()["items"]
    assert [x["version"] for x in items] == ["s1"]
    got = client.get("/api/v1/crl-snapshots/s1")
    assert got.status_code == 200 and got.json()["crl_count"] == 1
    assert client.get("/api/v1/crl-snapshots/nope").status_code == 404


def test_import_snapshot_bad_pem_rejected(client, root):
    r = _snapshot(client, "bad", "not a pem")
    assert r.status_code == 400 and "CRL" in r.json()["detail"]
    # 证书 PEM 不是 CRL
    ca, _ = root
    r = _snapshot(client, "bad2", pem(ca))
    assert r.status_code == 400
    # 块外垃圾
    r = _snapshot(client, "bad3",
                  make_crl(ca, root[1], "2026-01-01", "2027-01-01") + "GARBAGE")
    assert r.status_code == 400


def test_import_snapshot_unknown_issuer_rejected(client, root):
    # CA 证书尚未导入（新根）即导入其 CRL → 未知签发者
    other_ca, other_key = make_ca("Never Imported CA")
    r = _snapshot(client, "s", make_crl(other_ca, other_key, "2026-01-01", "2027-01-01"))
    assert r.status_code == 400
    assert "unknown" in r.json()["detail"].lower()


def test_import_snapshot_bad_signature_rejected(client, root):
    ca, ca_key = root
    # 同名不同密钥的 CA 签发的 CRL：DN 匹配但签名验证失败
    rogue_key = _key()
    rogue = (
        x509.CertificateBuilder()
        .subject_name(ca.subject)
        .issuer_name(ca.subject)
        .public_key(rogue_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(t("2025-01-01"))
        .not_valid_after(t("2035-01-01"))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(rogue_key, hashes.SHA256())
    )
    r = _snapshot(client, "s", make_crl(rogue, rogue_key, "2026-01-01", "2027-01-01"))
    assert r.status_code == 400
    assert "signature" in r.json()["detail"].lower()


def test_import_snapshot_missing_next_update_rejected(client, root):
    ca, ca_key = root
    r = _snapshot(client, "s", _crl_no_next_update(ca, ca_key))
    assert r.status_code == 400 and "nextUpdate" in r.json()["detail"]


def test_import_snapshot_this_after_next_rejected(client, root):
    ca, ca_key = root
    bad = tamper_crl_pem(make_crl(ca, ca_key, "2027-01-01", "2027-06-01"),
                         "swap_times")
    r = _snapshot(client, "s", bad)
    assert r.status_code == 400 and "after nextUpdate" in r.json()["detail"]


def test_import_snapshot_duplicate_version_rejected(client, root):
    ca, ca_key = root
    crl_pem = make_crl(ca, ca_key, "2025-12-01", "2027-02-01")
    assert _snapshot(client, "s1", crl_pem).status_code == 201
    assert _snapshot(client, "s1", crl_pem).status_code == 409


def test_import_snapshot_conflicting_and_duplicate_issuer_rejected(client, root):
    ca, ca_key = root
    c1 = make_crl(ca, ca_key, "2026-01-01", "2026-07-01", number=1)
    c2 = make_crl(ca, ca_key, "2026-07-01", "2027-01-01", number=2)
    r = _snapshot(client, "conf", c1 + c2)
    assert r.status_code == 409 and "conflicting CRLs" in r.json()["detail"]
    # 完全相同的重复 CRL 同样拒绝
    r = _snapshot(client, "dup", c1 + c1)
    assert r.status_code == 409 and "duplicate CRL" in r.json()["detail"]


def test_import_snapshot_issuer_without_crlsign_rejected(client):
    # 已导入的 CA 证书 keyUsage 不含 cRLSign → 其 CRL 拒绝
    key = _key()
    name = _name("No CRLSign CA")
    ca = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(t("2025-01-01"))
        .not_valid_after(t("2035-01-01"))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=False, encipher_only=None, decipher_only=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    client.post("/api/v1/trust-roots", json={"version": "v1", "pem": pem(ca)})
    r = _snapshot(client, "s", make_crl(ca, key, "2026-01-01", "2027-01-01"))
    assert r.status_code == 400 and "cRLSign" in r.json()["detail"]


def test_import_snapshot_second_root_its_own_crl_ok(client, root):
    # 两个已导入根各自的 CRL 共存于同一快照（不同签发者不冲突）
    ca, ca_key = root
    ca2, key2 = make_ca("Second Root")
    client.post("/api/v1/trust-roots", json={"version": "v2", "pem": pem(ca2)})
    r = _snapshot(
        client, "multi",
        make_crl(ca, ca_key, "2025-12-01", "2027-02-01")
        + make_crl(ca2, key2, "2025-12-01", "2027-02-01"),
    )
    assert r.status_code == 201 and r.json()["crl_count"] == 2


# ---------------------------------------------------------------------------
# 评估：撤销证据与断档
# ---------------------------------------------------------------------------

def test_snapshot_full_coverage_no_gap(client, root):
    ca, ca_key = root
    leaf, fp = _setup_single_leaf(client, ca, ca_key)
    _snapshot(client, "s1", make_crl(ca, ca_key, "2025-12-01", "2027-02-01"))
    r = _plan(client, "s1")
    assert r.status_code == 201, r.text
    ev = r.json()["evaluation"]
    assert ev["crl_snapshot_version"] == "s1"
    assert ev["has_gaps"] is False and ev["gaps"] == []
    cert = ev["certificates"][0]
    assert cert["usable_intervals"] == [
        {"start": "2026-01-01T00:00:00.000Z", "end": "2027-01-01T00:00:00.000Z"}]
    rev = cert["revocation"]
    assert len(rev) == 1  # 仅一张非根证书（叶子）
    assert rev[0]["subject"].endswith(DOMAIN)
    assert rev[0]["crl"]["this_update"].startswith("2025-12-01")
    assert rev[0]["crl"]["revoked"] is None
    assert rev[0]["reasons"] == []
    assert cert["reasons"] == []
    assert r.json()["plan"]["crl_snapshot_version"] == "s1"


def test_plan_without_snapshot_has_no_revocation_block(client, root):
    ca, ca_key = root
    _setup_single_leaf(client, ca, ca_key)
    ev = _plan(client).json()["evaluation"]
    assert ev["crl_snapshot_version"] is None
    assert "revocation" not in ev["certificates"][0]
    assert ev["has_gaps"] is False


def test_missing_issuer_crl_is_gap(client, root):
    ca, ca_key = root
    _setup_single_leaf(client, ca, ca_key)
    # 快照中只有另一张已导入根的 CRL，叶子签发者（v1 根）无 CRL → 全程断档
    other_ca, other_key = make_ca("Other Root")
    client.post("/api/v1/trust-roots", json={"version": "v2", "pem": pem(other_ca)})
    _snapshot(client, "s-other",
              make_crl(other_ca, other_key, "2025-12-01", "2027-02-01"))
    ev = _plan(client, "s-other").json()["evaluation"]
    assert ev["has_gaps"] is True
    assert ev["gaps"] == [{"start": "2026-01-01T00:00:00.000Z",
                           "end": "2027-01-01T00:00:00.000Z"}]
    assert ev["certificates"][0]["usable_intervals"] == []
    assert any("no CRL signed by issuer" in r
               for r in ev["certificates"][0]["reasons"])
    # 不得静默判安全：批准被拒
    plan_id = ev_domain_plan_id(client)
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 409


def ev_domain_plan_id(client, domain=DOMAIN):
    return client.get("/api/v1/plans", params={"domain": domain}).json()["items"][-1]["id"]


def test_expired_crl_creates_gap(client, root):
    ca, ca_key = root
    _setup_single_leaf(client, ca, ca_key)
    # CRL 仅在 2026-01-01..2026-04-01 有效 → 之后断档
    _snapshot(client, "s-exp", make_crl(ca, ca_key, "2026-01-01", "2026-04-01"))
    cert = _plan(client, "s-exp").json()["evaluation"]["certificates"][0]
    assert cert["usable_intervals"] == [
        {"start": "2026-01-01T00:00:00.000Z", "end": "2026-04-01T00:00:00.000Z"}]
    assert any("expires at" in r for r in cert["reasons"])
    assert any("coverage missing after that" in r for r in cert["reasons"])


def test_not_yet_valid_crl_creates_gap(client, root):
    ca, ca_key = root
    _setup_single_leaf(client, ca, ca_key)
    # CRL 2026-03-01 才生效 → 之前断档
    _snapshot(client, "s-fut", make_crl(ca, ca_key, "2026-03-01", "2027-02-01"))
    ev = _plan(client, "s-fut").json()["evaluation"]
    assert ev["gaps"] == [{"start": "2026-01-01T00:00:00.000Z",
                           "end": "2026-03-01T00:00:00.000Z"}]
    assert any("not valid until" in r for r in ev["certificates"][0]["reasons"])


def test_fully_expired_crl_is_gap(client, root):
    ca, ca_key = root
    _setup_single_leaf(client, ca, ca_key)
    _snapshot(client, "s-old", make_crl(ca, ca_key, "2025-01-01", "2025-06-01"))
    ev = _plan(client, "s-old").json()["evaluation"]
    assert ev["has_gaps"] is True
    assert any("expired at" in r for r in ev["certificates"][0]["reasons"])


def test_revoked_mid_window_splits_coverage(client, root):
    ca, ca_key = root
    leaf = _import_leaf_obj(ca, ca_key)
    fp = _post_leaf(client, leaf, ca, ca)
    _window(client, fp)
    serial = cert_serial(pem(leaf))
    _snapshot(client, "s-rev", make_crl(
        ca, ca_key, "2025-12-01", "2027-02-01",
        revoked=[(serial, "2026-06-01", x509.ReasonFlags.key_compromise)]))
    ev = _plan(client, "s-rev").json()["evaluation"]
    assert ev["has_gaps"] is True
    assert ev["gaps"] == [{"start": "2026-06-01T00:00:00.000Z",
                           "end": "2027-01-01T00:00:00.000Z"}]
    cert = ev["certificates"][0]
    assert cert["usable_intervals"] == [
        {"start": "2026-01-01T00:00:00.000Z", "end": "2026-06-01T00:00:00.000Z"}]
    member = cert["revocation"][0]
    assert member["crl"]["revoked"] == {
        "effective_at": "2026-06-01T00:00:00.000Z", "reason": "key_compromise"}
    assert any("revoked at 2026-06-01" in r for r in cert["reasons"])


def test_revoked_before_window_full_gap(client, root):
    ca, ca_key = root
    leaf = _import_leaf_obj(ca, ca_key)
    fp = _post_leaf(client, leaf, ca, ca)
    _window(client, fp)
    serial = cert_serial(pem(leaf))
    _snapshot(client, "s-rev", make_crl(
        ca, ca_key, "2025-12-01", "2027-02-01",
        revoked=[(serial, "2025-06-01", None)]))
    ev = _plan(client, "s-rev").json()["evaluation"]
    assert ev["gaps"] == [{"start": "2026-01-01T00:00:00.000Z",
                           "end": "2027-01-01T00:00:00.000Z"}]
    assert ev["certificates"][0]["usable_intervals"] == []


def test_endpoint_touch_is_not_gap(client, root):
    ca, ca_key = root
    leaf = _import_leaf_obj(ca, ca_key)
    fp = _post_leaf(client, leaf, ca, ca)
    _window(client, fp)
    serial = cert_serial(pem(leaf))
    # 撤销时刻恰好窗口/评估终点，且 nextUpdate 恰好终点 → 端点相接不断档
    _snapshot(client, "s-edge", make_crl(
        ca, ca_key, "2026-01-01", "2027-01-01",
        revoked=[(serial, "2027-01-01", None)]))
    ev = _plan(client, "s-edge").json()["evaluation"]
    assert ev["has_gaps"] is False, ev["gaps"]
    assert ev["certificates"][0]["usable_intervals"] == [
        {"start": "2026-01-01T00:00:00.000Z", "end": "2027-01-01T00:00:00.000Z"}]


def test_unknown_snapshot_rejected(client, root):
    ca, ca_key = root
    _setup_single_leaf(client, ca, ca_key)
    assert _plan(client, "nope").status_code == 404
    plan_id = _plan(client).json()["plan"]["id"]
    r = client.post(f"/api/v1/plans/{plan_id}/evaluate",
                    json={"crl_snapshot_version": "nope"})
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# 含中间证书的链
# ---------------------------------------------------------------------------

@pytest.fixture()
def chain_env(client):
    ca, ca_key = make_ca("CRL Root CA")
    client.post("/api/v1/trust-roots", json={"version": "v1", "pem": pem(ca)})
    inter, inter_key = make_cert(ca, ca_key, "CRL Inter CA", is_ca=True,
                                 path_length=0, nb="2025-06-01", na="2030-01-01")
    leaf = _import_leaf_obj(ca, ca_key, issuer_cert=inter, issuer_key=inter_key)
    fp = _post_leaf(client, leaf, inter, ca)
    _window(client, fp)
    return ca, ca_key, inter, inter_key, leaf


def test_chain_needs_crl_for_every_non_root_member(client, chain_env):
    ca, ca_key, inter, inter_key, leaf = chain_env
    # 只有根 CRL（覆盖中间证书），缺少中间 CA 给叶子的 CRL → 断档
    _snapshot(client, "s-partial", make_crl(ca, ca_key, "2025-12-01", "2027-02-01"))
    ev = _plan(client, "s-partial").json()["evaluation"]
    assert ev["has_gaps"] is True
    subjects = {m["subject"] for m in ev["certificates"][0]["revocation"]}
    assert any(DOMAIN in s for s in subjects)
    assert any("CRL Inter CA" in s for s in subjects)
    assert any("no CRL signed by issuer 'CN=CRL Inter CA'" in r
               for r in ev["certificates"][0]["reasons"])

    # 补齐两张 CRL → 无断档，两张非根证书都有证据
    _snapshot(client, "s-full",
              make_crl(ca, ca_key, "2025-12-01", "2027-02-01")
              + make_crl(inter, inter_key, "2025-12-01", "2027-02-01"))
    ev = _plan(client, "s-full").json()["evaluation"]
    assert ev["has_gaps"] is False
    assert len(ev["certificates"][0]["revocation"]) == 2
    assert ev["certificates"][0]["reasons"] == []


def test_revoked_intermediate_gaps_leaf(client, chain_env):
    ca, ca_key, inter, inter_key, leaf = chain_env
    inter_serial = cert_serial(pem(inter))
    _snapshot(client, "s-rev-inter",
              make_crl(ca, ca_key, "2025-12-01", "2027-02-01",
                       revoked=[(inter_serial, "2026-05-01", None)])
              + make_crl(inter, inter_key, "2025-12-01", "2027-02-01"))
    ev = _plan(client, "s-rev-inter").json()["evaluation"]
    # 中间证书在 2026-05-01 撤销 → 叶子窗口同时段断档
    assert ev["gaps"] == [{"start": "2026-05-01T00:00:00.000Z",
                           "end": "2027-01-01T00:00:00.000Z"}]


def test_revocation_intersects_cert_validity(client, root):
    # CRL 覆盖很宽，但证书 2026-06-01 到期 → 可用区间受有效期约束
    ca, ca_key = root
    leaf = _import_leaf_obj(ca, ca_key, na="2026-06-01")
    fp = _post_leaf(client, leaf, ca, ca)
    _window(client, fp)
    _snapshot(client, "s", make_crl(ca, ca_key, "2025-01-01", "2028-01-01"))
    ev = _plan(client, "s").json()["evaluation"]
    cert = ev["certificates"][0]
    assert cert["usable_intervals"] == [
        {"start": "2026-01-01T00:00:00.000Z", "end": "2026-06-01T00:00:00.000Z"}]
    assert ev["gaps"] == [{"start": "2026-06-01T00:00:00.000Z",
                           "end": "2027-01-01T00:00:00.000Z"}]
    assert any("expires" in r for r in cert["reasons"])


# ---------------------------------------------------------------------------
# 重评切换快照、待复核与历史冻结
# ---------------------------------------------------------------------------

def test_switch_snapshot_marks_approved_pending_review(client, root):
    ca, ca_key = root
    leaf, fp = _setup_single_leaf(client, ca, ca_key)
    serial = cert_serial(pem(leaf))
    _snapshot(client, "s1", make_crl(ca, ca_key, "2025-12-01", "2027-02-01"))
    _snapshot(client, "s2", make_crl(
        ca, ca_key, "2025-12-01", "2027-02-01",
        revoked=[(serial, "2026-03-01", None)]))

    plan_id = _plan(client, "s1").json()["plan"]["id"]
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 200

    # 切换到含撤销的快照 → 已批准计划先转待复核，冻结批准被取代
    r = client.post(f"/api/v1/plans/{plan_id}/evaluate",
                    json={"crl_snapshot_version": "s2"})
    assert r.status_code == 200
    ev = r.json()
    assert ev["crl_snapshot_version"] == "s2"
    assert ev["has_gaps"] is True
    plan = client.get(f"/api/v1/plans/{plan_id}").json()
    assert plan["status"] == "pending_review"
    assert plan["crl_snapshot_version"] == "s2"
    approvals = client.get(f"/api/v1/plans/{plan_id}/approvals").json()["items"]
    assert len(approvals) == 1
    assert approvals[0]["superseded"] is True
    assert approvals[0]["crl_snapshot_version"] == "s1"
    assert approvals[0]["verdict"]["crl_snapshot_version"] == "s1"

    # 有断档不可批准
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 409

    # 切回无撤销快照 → 无断档 → 可再次批准；历史评估/批准各自保留版本
    client.post(f"/api/v1/plans/{plan_id}/evaluate",
                json={"crl_snapshot_version": "s1"})
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 200
    evals = client.get(f"/api/v1/plans/{plan_id}/evaluations").json()["items"]
    assert [e["crl_snapshot_version"] for e in evals] == ["s1", "s2", "s1"]
    approvals = client.get(f"/api/v1/plans/{plan_id}/approvals").json()["items"]
    assert [a["crl_snapshot_version"] for a in approvals] == ["s1", "s1"]
    assert [a["superseded"] for a in approvals] == [True, False]


def test_omitted_snapshot_field_keeps_selection(client, root):
    ca, ca_key = root
    leaf, fp = _setup_single_leaf(client, ca, ca_key)
    _snapshot(client, "s1", make_crl(ca, ca_key, "2025-12-01", "2027-02-01"))
    plan_id = _plan(client, "s1").json()["plan"]["id"]
    # 空 body / 无 body 均沿用当前快照
    r = client.post(f"/api/v1/plans/{plan_id}/evaluate", json={})
    assert r.json()["crl_snapshot_version"] == "s1"
    r = client.post(f"/api/v1/plans/{plan_id}/evaluate")
    assert r.json()["crl_snapshot_version"] == "s1"


def test_explicit_null_clears_snapshot_and_reviews(client, root):
    ca, ca_key = root
    leaf, fp = _setup_single_leaf(client, ca, ca_key)
    _snapshot(client, "s1", make_crl(ca, ca_key, "2025-12-01", "2027-02-01"))
    plan_id = _plan(client, "s1").json()["plan"]["id"]
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 200
    # 显式 null 取消快照 → 已批准计划同样先转待复核，回到无快照语义
    r = client.post(f"/api/v1/plans/{plan_id}/evaluate",
                    json={"crl_snapshot_version": None})
    assert r.status_code == 200
    assert r.json()["crl_snapshot_version"] is None
    plan = client.get(f"/api/v1/plans/{plan_id}").json()
    assert plan["status"] == "pending_review"
    assert "revocation" not in r.json()["certificates"][0]
    # 复核后重新批准
    client.post(f"/api/v1/plans/{plan_id}/evaluate")
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 200


def test_legacy_plan_re_evaluate_stays_without_snapshot(client, root):
    ca, ca_key = root
    _setup_single_leaf(client, ca, ca_key)
    plan_id = _plan(client).json()["plan"]["id"]
    # 即便系统里存在快照，未选择快照的既有计划重评仍不带快照、响应无 revocation
    _snapshot(client, "s1", make_crl(ca, ca_key, "2025-01-01", "2025-06-01"))
    r = client.post(f"/api/v1/plans/{plan_id}/evaluate")
    assert r.json()["crl_snapshot_version"] is None
    assert r.json()["has_gaps"] is False
    assert "revocation" not in r.json()["certificates"][0]
