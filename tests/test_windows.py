"""服务窗口登记与校验规则测试。"""
import pytest

from tests.helpers import make_ca, make_cert, pem


@pytest.fixture()
def cert_fp(client):
    ca, ca_key = make_ca()
    client.post("/api/v1/trust-roots", json={"version": "v1", "pem": pem(ca)})
    leaf, _ = make_cert(ca, ca_key, "w.example.com", sans=["w.example.com"])
    r = client.post("/api/v1/certificates", json={"pem": pem(leaf)})
    return r.json()["fingerprint_sha256"]


def _window(client, fp, start="2026-01-01T00:00:00Z", end="2026-07-01T00:00:00Z",
            domain="w.example.com", role="current"):
    return client.post("/api/v1/service-windows", json={
        "domain": domain,
        "certificate_fingerprint": fp,
        "role": role,
        "start": start,
        "end": end,
    })


def test_create_window_ok(client, cert_fp):
    r = _window(client, cert_fp)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["domain"] == "w.example.com"
    assert body["role"] == "current"
    assert body["start"] == "2026-01-01T00:00:00.000Z"
    assert body["plans_marked_pending_review"] == 0

    items = client.get("/api/v1/service-windows", params={"domain": "w.example.com"}).json()["items"]
    assert len(items) == 1


def test_create_window_invalid_interval_rejected(client, cert_fp):
    # 结束早于开始
    r = _window(client, cert_fp, start="2026-07-01T00:00:00Z", end="2026-01-01T00:00:00Z")
    assert r.status_code == 400
    assert "invalid time window" in r.json()["detail"]
    # 开始等于结束（空窗口）
    r = _window(client, cert_fp, start="2026-01-01T00:00:00Z", end="2026-01-01T00:00:00Z")
    assert r.status_code == 400


def test_create_window_naive_datetime_rejected(client, cert_fp):
    r = _window(client, cert_fp, start="2026-01-01T00:00:00", end="2026-07-01T00:00:00")
    assert r.status_code == 422


def test_create_window_unknown_certificate_rejected(client):
    r = _window(client, "0" * 64)
    assert r.status_code == 404


def test_delete_window(client, cert_fp):
    wid = _window(client, cert_fp).json()["id"]
    r = client.delete(f"/api/v1/service-windows/{wid}")
    assert r.status_code == 200
    assert client.get("/api/v1/service-windows").json()["items"] == []
    assert client.delete(f"/api/v1/service-windows/{wid}").status_code == 404
