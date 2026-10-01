"""信任根与证书导入的校验规则测试。"""
from tests.helpers import fingerprint, make_ca, make_cert, pem


def _import_root(client, version="v1", pem_str=None):
    if pem_str is None:
        ca, _ = make_ca()
        pem_str = pem(ca)
    return client.post("/api/v1/trust-roots", json={"version": version, "pem": pem_str})


def test_health(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_import_trust_root_first_is_active(client):
    r = _import_root(client, "v1")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["version"] == "v1"
    assert body["is_active"] is True
    assert body["cert_count"] == 1

    ca2, _ = make_ca("Second Root")
    r = _import_root(client, "v2", pem(ca2))
    assert r.status_code == 201
    assert r.json()["is_active"] is False

    roots = client.get("/api/v1/trust-roots").json()["items"]
    assert [x["version"] for x in roots] == ["v1", "v2"]
    assert roots[0]["is_active"] is True and roots[1]["is_active"] is False


def test_import_trust_root_bad_pem_rejected(client):
    r = _import_root(client, "bad", "not a pem at all")
    assert r.status_code == 400
    assert "PEM" in r.json()["detail"]

    # PEM 块之外混入垃圾内容同样拒绝
    ca, _ = make_ca()
    r = _import_root(client, "bad2", pem(ca) + "\nGARBAGE\n")
    assert r.status_code == 400

    # 截断的 PEM 块
    r = _import_root(client, "bad3", "-----BEGIN CERTIFICATE-----\nMIIB\n")
    assert r.status_code == 400


def test_import_trust_root_duplicate_version_rejected(client):
    assert _import_root(client, "v1").status_code == 201
    r = _import_root(client, "v1")
    assert r.status_code == 409


def test_activate_unknown_trust_root_rejected(client):
    r = client.post("/api/v1/trust-roots/nope/activate")
    assert r.status_code == 404


def test_import_certificate_ok_and_duplicate_fingerprint(client):
    ca, ca_key = make_ca()
    assert _import_root(client, "v1", pem(ca)).status_code == 201
    leaf, _ = make_cert(ca, ca_key, "a.example.com", sans=["a.example.com"])
    r = client.post("/api/v1/certificates", json={"pem": pem(leaf), "label": "leaf-a"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["fingerprint_sha256"] == fingerprint(pem(leaf))
    assert body["san_dns"] == ["a.example.com"]
    assert body["chain_length"] == 1

    # 同一指纹重复导入 → 409
    r = client.post("/api/v1/certificates", json={"pem": pem(leaf)})
    assert r.status_code == 409

    got = client.get(f"/api/v1/certificates/{body['fingerprint_sha256']}")
    assert got.status_code == 200
    assert got.json()["subject"].endswith("a.example.com")


def test_import_certificate_bad_pem_rejected(client):
    r = client.post("/api/v1/certificates", json={"pem": "-----BEGIN CERTIFICATE-----\n@@@"})
    assert r.status_code == 400


def test_import_certificate_chain_with_intermediate(client):
    ca, ca_key = make_ca()
    inter, inter_key = make_cert(ca, ca_key, "Intermediate CA", is_ca=True, path_length=0)
    leaf, _ = make_cert(inter, inter_key, "b.example.com", sans=["b.example.com"])
    r = client.post("/api/v1/certificates", json={"pem": pem(leaf, inter)})
    assert r.status_code == 201
    assert r.json()["chain_length"] == 2
