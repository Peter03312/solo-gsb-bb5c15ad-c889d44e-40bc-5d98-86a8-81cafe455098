"""业务逻辑：信任根版本、证书链、服务窗口、CRL 撤销快照、评估计划与批准。"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import certutils, coverage, crlutils, db


class ApiError(Exception):
    """转换为 HTTP 响应的业务错误。"""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


_write_lock = threading.RLock()


# ---------------------------------------------------------------------------
# 时间工具
# ---------------------------------------------------------------------------

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_z(dt: datetime) -> str:
    """UTC ISO-8601，固定毫秒宽度，可按字典序排序比较。"""
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# 序列化
# ---------------------------------------------------------------------------

def _trust_root_dict(row) -> dict:
    return {
        "version": row["version"],
        "cert_count": row["cert_count"],
        "is_active": bool(row["is_active"]),
        "created_at": row["created_at"],
    }


def _cert_dict(row) -> dict:
    return {
        "fingerprint_sha256": row["fingerprint_sha256"],
        "label": row["label"],
        "subject": row["subject"],
        "issuer": row["issuer"],
        "san_dns": json.loads(row["san_dns"]),
        "not_before": row["not_before"],
        "not_after": row["not_after"],
        "created_at": row["created_at"],
    }


def _window_dict(row) -> dict:
    return {
        "id": row["id"],
        "domain": row["domain"],
        "certificate_fingerprint": row["certificate_fingerprint"],
        "role": row["role"],
        "start": row["start_utc"],
        "end": row["end_utc"],
        "created_at": row["created_at"],
    }


def _plan_dict(row) -> dict:
    return {
        "id": row["id"],
        "domain": row["domain"],
        "eval_start": row["eval_start"],
        "eval_end": row["eval_end"],
        "trust_root_version": row["trust_root_version"],
        "crl_snapshot_version": row["crl_snapshot_version"],
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _snapshot_dict(row) -> dict:
    return {
        "version": row["version"],
        "crl_count": row["crl_count"],
        "created_at": row["created_at"],
    }


def _crl_entry_dict(row) -> dict:
    return {
        "issuer": row["issuer_dn"],
        "issuer_key_id": row["issuer_key_id"],
        "crl_number": row["crl_number"],
        "this_update": row["this_update"],
        "next_update": row["next_update"],
        "revoked_count": row["revoked_count"],
    }


def _approval_dict(row) -> dict:
    return {
        "id": row["id"],
        "plan_id": row["plan_id"],
        "trust_root_version": row["trust_root_version"],
        "crl_snapshot_version": row["crl_snapshot_version"],
        "cert_fingerprints": json.loads(row["cert_fingerprints"]),
        "verdict": json.loads(row["verdict_json"]),
        "superseded": bool(row["superseded"]),
        "created_at": row["created_at"],
    }


# ---------------------------------------------------------------------------
# 待复核标记（历史判定保留，仅置 superseded）
# ---------------------------------------------------------------------------

def _mark_plans_pending_review(conn, query: str, params: tuple) -> int:
    ids = [r["id"] for r in conn.execute(query, params).fetchall()]
    ts = iso_z(now_utc())
    for pid in ids:
        conn.execute(
            "UPDATE plans SET status = 'pending_review', updated_at = ? WHERE id = ?",
            (ts, pid),
        )
        conn.execute(
            "UPDATE approvals SET superseded = 1 WHERE plan_id = ? AND superseded = 0",
            (pid,),
        )
    return len(ids)


def _mark_domain_plans_pending_review(conn, domain: str) -> int:
    return _mark_plans_pending_review(
        conn,
        "SELECT id FROM plans WHERE status = 'approved' AND domain = ?",
        (domain,),
    )


# ---------------------------------------------------------------------------
# 信任根版本
# ---------------------------------------------------------------------------

def import_trust_root(version: str, pem: str) -> dict:
    try:
        roots = certutils.parse_pem_chain(pem)
    except certutils.PemParseError as exc:
        raise ApiError(400, f"invalid trust root PEM bundle: {exc}") from exc
    subjects = sorted({c.subject.rfc4514_string() for c in roots})
    ts = iso_z(now_utc())
    with _write_lock, db.connect() as conn:
        if conn.execute(
            "SELECT 1 FROM trust_roots WHERE version = ?", (version,)
        ).fetchone():
            raise ApiError(409, f"trust root version '{version}' already exists")
        is_first = (
            conn.execute("SELECT COUNT(*) AS c FROM trust_roots").fetchone()["c"] == 0
        )
        conn.execute(
            "INSERT INTO trust_roots (version, pem, cert_count, is_active, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (version, pem, len(roots), 1 if is_first else 0, ts),
        )
    return {
        "version": version,
        "cert_count": len(roots),
        "subjects": subjects,
        "is_active": is_first,
        "created_at": ts,
    }


def list_trust_roots() -> list[dict]:
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT * FROM trust_roots ORDER BY id"
        ).fetchall()
    return [_trust_root_dict(r) for r in rows]


def activate_trust_root(version: str) -> dict:
    """切换在用的信任根版本；与冻结版本不一致的已批准计划转为待复核。"""
    with _write_lock, db.connect() as conn:
        row = conn.execute(
            "SELECT * FROM trust_roots WHERE version = ?", (version,)
        ).fetchone()
        if row is None:
            raise ApiError(404, f"unknown trust root version '{version}'")
        if row["is_active"]:
            return {
                "version": version,
                "is_active": True,
                "plans_marked_pending_review": 0,
            }
        conn.execute("UPDATE trust_roots SET is_active = 0")
        conn.execute(
            "UPDATE trust_roots SET is_active = 1 WHERE version = ?", (version,)
        )
        affected = _mark_plans_pending_review(
            conn,
            "SELECT id FROM plans WHERE status = 'approved' AND id IN ("
            "  SELECT plan_id FROM approvals"
            "  WHERE superseded = 0 AND trust_root_version != ?"
            ")",
            (version,),
        )
    return {
        "version": version,
        "is_active": True,
        "plans_marked_pending_review": affected,
    }


def _active_version(conn) -> str | None:
    row = conn.execute(
        "SELECT version FROM trust_roots WHERE is_active = 1 ORDER BY id LIMIT 1"
    ).fetchone()
    return row["version"] if row else None


# ---------------------------------------------------------------------------
# 离线撤销快照（不可变）
# ---------------------------------------------------------------------------

def _ca_pool(conn):
    """汇总全部信任根版本与已导入链中的 CA 证书，供快照导入时验证 CRL 签名。

    返回 {指纹: cert}，只保留具备 CA 基本约束的证书（叶子不可能签发 CRL）。
    """
    pool: dict[str, x509.Certificate] = {}

    def add(cert) -> None:
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            return
        if not bc.ca:
            return
        pool.setdefault(certutils.fingerprint_sha256(cert), cert)

    for row in conn.execute("SELECT pem FROM trust_roots").fetchall():
        for cert in certutils.parse_pem_chain(row["pem"]):
            add(cert)
    for row in conn.execute("SELECT chain_pem FROM certificates").fetchall():
        for cert in certutils.parse_pem_chain(row["chain_pem"])[1:]:
            add(cert)
    return pool


def _validate_crl_for_import(crl, ca_pool):
    """对单个 CRL 做内容与签名验证，返回 (issuer_key, crl_number, 信息行)。"""
    if crl.next_update_utc is None:
        raise ApiError(400, "CRL is missing nextUpdate (indefinite expiry not accepted)")
    if crl.last_update_utc > crl.next_update_utc:
        raise ApiError(
            400,
            f"CRL thisUpdate {iso_z(crl.last_update_utc)} is after nextUpdate"
            f" {iso_z(crl.next_update_utc)}",
        )
    issuer_dn = crl.issuer.rfc4514_string()
    candidates = [
        cert
        for cert in ca_pool.values()
        if cert.subject == crl.issuer and crlutils.crl_aki_matches(crl, cert)
    ]
    signer = next(
        (c for c in candidates if crlutils.verify_crl_issued_by(crl, c)), None
    )
    if signer is None:
        if not candidates:
            raise ApiError(
                400,
                f"CRL issuer '{issuer_dn}' is unknown: no matching CA certificate"
                " imported (import its CA certificate before the snapshot)",
            )
        raise ApiError(
            400, f"CRL signature verification failed for issuer '{issuer_dn}'"
        )
    try:
        ku = signer.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        ku = None
    if ku is not None and not ku.crl_sign:
        raise ApiError(
            400,
            f"issuer '{issuer_dn}' keyUsage lacks cRLSign; it cannot sign a CRL",
        )
    number = crlutils.crl_number(crl)
    revoked = list(crl)
    return (
        crlutils.issuer_key(crl),
        number,
        {
            "issuer_dn": issuer_dn,
            "issuer_key_id": crlutils.issuer_key(crl)[1],
            "number": number,
            "this_update": iso_z(crl.last_update_utc),
            "next_update": iso_z(crl.next_update_utc),
            "revoked_count": len(revoked),
            "pem": crlutils.crl_to_pem(crl),
        },
    )


def import_crl_snapshot(version: str, pem: str) -> dict:
    """导入带版本的一组 PEM CRL。

    - 拒绝重复版本（409）；
    - 无法解析、缺 nextUpdate、thisUpdate 晚于 nextUpdate → 400；
    - 签名必须由已导入的 CA 证书验证通过（cRLSign），未知签发者 → 400；
    - 同一签发者（DN + AKI）出现两个不同 CRL → 409 冲突列表；
      完全相同的重复 CRL 同样拒绝（409）。
    """
    try:
        crls = crlutils.parse_pem_crls(pem)
    except crlutils.PemCrlError as exc:
        raise ApiError(400, f"invalid CRL PEM bundle: {exc}") from exc
    with _write_lock, db.connect() as conn:
        if conn.execute(
            "SELECT 1 FROM crl_snapshots WHERE version = ?", (version,)
        ).fetchone():
            raise ApiError(409, f"CRL snapshot version '{version}' already exists")
        ca_pool = _ca_pool(conn)
        seen: dict[tuple[str, str], bytes] = {}
        entries = []
        for idx, crl in enumerate(crls, start=1):
            key, _number, info = _validate_crl_for_import(crl, ca_pool)
            der = crl.public_bytes(serialization.Encoding.DER)
            if key in seen:
                if seen[key] == der:
                    raise ApiError(
                        409,
                        f"duplicate CRL for issuer '{key[0]}' in snapshot"
                        " (identical CRL appears more than once)",
                    )
                raise ApiError(
                    409,
                    f"conflicting CRLs for issuer '{key[0]}' in snapshot:"
                    " a snapshot may contain only one CRL per issuer",
                )
            seen[key] = der
            info["idx"] = idx
            entries.append(info)
        ts = iso_z(now_utc())
        cur = conn.execute(
            "INSERT INTO crl_snapshots (version, pem, crl_count, created_at)"
            " VALUES (?, ?, ?, ?)",
            (version, pem, len(crls), ts),
        )
        snapshot_id = cur.lastrowid
        for info in entries:
            conn.execute(
                "INSERT INTO crl_entries (snapshot_id, issuer_dn, issuer_key_id,"
                " crl_number, this_update, next_update, revoked_count, pem)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    snapshot_id,
                    info["issuer_dn"],
                    info["issuer_key_id"],
                    info["number"],
                    info["this_update"],
                    info["next_update"],
                    info["revoked_count"],
                    info["pem"],
                ),
            )
        row = conn.execute(
            "SELECT * FROM crl_snapshots WHERE id = ?", (snapshot_id,)
        ).fetchone()
        entry_rows = conn.execute(
            "SELECT * FROM crl_entries WHERE snapshot_id = ? ORDER BY id", (snapshot_id,)
        ).fetchall()
    result = _snapshot_dict(row)
    result["items"] = [_crl_entry_dict(r) for r in entry_rows]
    return result


def list_crl_snapshots() -> list[dict]:
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT * FROM crl_snapshots ORDER BY id"
        ).fetchall()
    return [_snapshot_dict(r) for r in rows]


def get_crl_snapshot(version: str) -> dict:
    with db.connect() as conn:
        row = conn.execute(
            "SELECT * FROM crl_snapshots WHERE version = ?", (version,)
        ).fetchone()
        if row is None:
            raise ApiError(404, f"unknown CRL snapshot version '{version}'")
        entries = conn.execute(
            "SELECT * FROM crl_entries WHERE snapshot_id = ? ORDER BY id", (row["id"],)
        ).fetchall()
    result = _snapshot_dict(row)
    result["items"] = [_crl_entry_dict(r) for r in entries]
    return result


def _load_snapshot(conn, version: str | None):
    """载入快照条目（按签发者键索引）。version 为 None 表示不使用快照。"""
    if version is None:
        return None
    snap = conn.execute(
        "SELECT * FROM crl_snapshots WHERE version = ?", (version,)
    ).fetchone()
    if snap is None:
        raise ApiError(404, f"unknown CRL snapshot version '{version}'")
    by_issuer: dict[tuple[str, str], list] = {}
    rows = conn.execute(
        "SELECT * FROM crl_entries WHERE snapshot_id = ?", (snap["id"],)
    ).fetchall()
    for row in rows:
        try:
            crl = crlutils.parse_pem_crls(row["pem"])[0]
        except crlutils.PemCrlError as exc:
            # 存储内容不可解析属于内部不一致：绝不静默放行
            raise ApiError(
                500,
                f"stored CRL for issuer '{row['issuer_dn']}' is unreadable: {exc}",
            ) from exc
        by_issuer.setdefault((row["issuer_dn"], row["issuer_key_id"]), []).append(
            (row, crl)
        )
    return {"version": version, "by_issuer": by_issuer}


# ---------------------------------------------------------------------------
# 证书链导入
# ---------------------------------------------------------------------------

def import_certificate(pem: str, label: str | None) -> dict:
    try:
        chain = certutils.parse_pem_chain(pem)
    except certutils.PemParseError as exc:
        raise ApiError(400, f"invalid certificate PEM chain: {exc}") from exc
    leaf = chain[0]
    fp = certutils.fingerprint_sha256(leaf)
    ts = iso_z(now_utc())
    with _write_lock, db.connect() as conn:
        if conn.execute(
            "SELECT 1 FROM certificates WHERE fingerprint_sha256 = ?", (fp,)
        ).fetchone():
            raise ApiError(
                409, f"certificate with fingerprint {fp} already imported"
            )
        conn.execute(
            "INSERT INTO certificates (fingerprint_sha256, label, subject, issuer,"
            " san_dns, not_before, not_after, leaf_pem, chain_pem, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                fp,
                label,
                leaf.subject.rfc4514_string(),
                leaf.issuer.rfc4514_string(),
                json.dumps(certutils.san_dns_names(leaf)),
                iso_z(leaf.not_valid_before_utc),
                iso_z(leaf.not_valid_after_utc),
                certutils.to_pem(leaf),
                pem,
                ts,
            ),
        )
    return {
        "fingerprint_sha256": fp,
        "label": label,
        "subject": leaf.subject.rfc4514_string(),
        "issuer": leaf.issuer.rfc4514_string(),
        "san_dns": certutils.san_dns_names(leaf),
        "not_before": iso_z(leaf.not_valid_before_utc),
        "not_after": iso_z(leaf.not_valid_after_utc),
        "chain_length": len(chain),
        "created_at": ts,
    }


def list_certificates() -> list[dict]:
    with db.connect() as conn:
        rows = conn.execute("SELECT * FROM certificates ORDER BY id").fetchall()
    return [_cert_dict(r) for r in rows]


def get_certificate(fingerprint: str) -> dict:
    with db.connect() as conn:
        row = conn.execute(
            "SELECT * FROM certificates WHERE fingerprint_sha256 = ?", (fingerprint,)
        ).fetchone()
    if row is None:
        raise ApiError(404, f"unknown certificate fingerprint '{fingerprint}'")
    result = _cert_dict(row)
    result["chain_pem"] = row["chain_pem"]
    return result


# ---------------------------------------------------------------------------
# 服务窗口
# ---------------------------------------------------------------------------

def create_window(
    domain: str, fingerprint: str, role: str, start: datetime, end: datetime
) -> dict:
    if start >= end:
        raise ApiError(
            400,
            "invalid time window: start "
            f"{iso_z(start)} must be before end {iso_z(end)}",
        )
    with _write_lock, db.connect() as conn:
        if not conn.execute(
            "SELECT 1 FROM certificates WHERE fingerprint_sha256 = ?", (fingerprint,)
        ).fetchone():
            raise ApiError(404, f"unknown certificate fingerprint '{fingerprint}'")
        ts = iso_z(now_utc())
        cur = conn.execute(
            "INSERT INTO service_windows"
            " (domain, certificate_fingerprint, role, start_utc, end_utc, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (domain, fingerprint, role, iso_z(start), iso_z(end), ts),
        )
        affected = _mark_domain_plans_pending_review(conn, domain)
        row = conn.execute(
            "SELECT * FROM service_windows WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
    result = _window_dict(row)
    result["plans_marked_pending_review"] = affected
    return result


def list_windows(domain: str | None) -> list[dict]:
    with db.connect() as conn:
        if domain:
            rows = conn.execute(
                "SELECT * FROM service_windows WHERE domain = ? ORDER BY start_utc, id",
                (domain,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM service_windows ORDER BY domain, start_utc, id"
            ).fetchall()
    return [_window_dict(r) for r in rows]


def delete_window(window_id: int) -> dict:
    with _write_lock, db.connect() as conn:
        row = conn.execute(
            "SELECT * FROM service_windows WHERE id = ?", (window_id,)
        ).fetchone()
        if row is None:
            raise ApiError(404, f"unknown service window id {window_id}")
        conn.execute("DELETE FROM service_windows WHERE id = ?", (window_id,))
        affected = _mark_domain_plans_pending_review(conn, row["domain"])
    return {"deleted": _window_dict(row), "plans_marked_pending_review": affected}


# ---------------------------------------------------------------------------
# 评估
# ---------------------------------------------------------------------------

def _short_subject(cert) -> str:
    cn = cert.subject.rfc4514_string()
    return cn.split(",", 1)[0] if "," in cn else cn


def _crl_sign_ok(ca) -> bool:
    try:
        ku = ca.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return True
    return ku.crl_sign


def _revocation_evidence(child, issuer, snapshot, w_start, w_end):
    """为链上一张非根证书解析其签发者 CRL 证据。

    返回 (成员报告, 该成员的撤销可用区间列表)。缺失/过期/已撤销均计入断档。
    """
    subj = issuer.subject.rfc4514_string()
    member = {
        "subject": child.subject.rfc4514_string(),
        "issuer": subj,
        "serial_number": format(child.serial_number, "X"),
        "crl": None,
        "reasons": [],
    }
    reasons: list[str] = []
    clean: list[tuple[datetime, datetime]] = []
    label = _short_subject(child)

    candidates = snapshot["by_issuer"].get(crlutils.issuer_key(issuer), [])
    # issuer_key 含 SKI；CRL 无 AKI 时再按 DN 兜底匹配
    if not candidates:
        candidates = [
            pair
            for key, pairs in snapshot["by_issuer"].items()
            if key[0] == issuer.subject.rfc4514_string()
            for pair in pairs
        ]
        candidates = [
            (row, crl) for row, crl in candidates if crlutils.crl_aki_matches(crl, issuer)
        ]
    matched = [
        (row, crl)
        for row, crl in candidates
        if crlutils.verify_crl_issued_by(crl, issuer)
    ]
    if not matched:
        reason = (
            f"no CRL signed by issuer '{subj}' found in snapshot"
            f" '{snapshot['version']}'"
        )
        reasons.append(reason)
        member["reasons"].append(reason)
        return member, clean, [f"{label}: {reason}"]
    if len({r["id"] for r, _ in matched}) > 1:
        # 存储层已保证同签发者唯一；防御性处理，绝不静默选择
        reason = f"multiple CRLs for issuer '{subj}' in snapshot"
        reasons.append(reason)
        member["reasons"].append(reason)
        return member, clean, [f"{label}: {reason}"]

    row, crl = matched[0]
    if not _crl_sign_ok(issuer):
        reason = f"issuer '{subj}' keyUsage lacks cRLSign"
        reasons.append(reason)
        member["reasons"].append(reason)
        return member, clean, [f"{label}: {reason}"]

    tu = crl.last_update_utc
    nu = crl.next_update_utc
    member["crl"] = {
        "issuer": subj,
        "crl_number": row["crl_number"],
        "this_update": iso_z(tu),
        "next_update": iso_z(nu),
        "revoked": None,
    }
    valid: list[tuple[datetime, datetime]] = []
    if nu <= w_start:
        reasons.append(
            f"CRL from issuer '{subj}' expired at {iso_z(nu)},"
            f" before window start {iso_z(w_start)}"
        )
    elif tu >= w_end:
        reasons.append(
            f"CRL from issuer '{subj}' not valid until {iso_z(tu)},"
            f" after window end {iso_z(w_end)}"
        )
    else:
        s, e = max(tu, w_start), min(nu, w_end)
        if s < e:
            valid.append((s, e))
        if tu > w_start:
            reasons.append(
                f"CRL from issuer '{subj}' not valid until {iso_z(tu)},"
                f" after window start {iso_z(w_start)}: coverage missing before that"
            )
        if nu < w_end:
            reasons.append(
                f"CRL from issuer '{subj}' expires at {iso_z(nu)},"
                f" before window end {iso_z(w_end)}: coverage missing after that"
            )

    rc = crl.get_revoked_certificate_by_serial_number(child.serial_number)
    revoked_at: datetime | None = None
    if rc is not None:
        revoked_at = rc.revocation_date_utc
        rreason = crlutils.revoked_reason(rc)
        member["crl"]["revoked"] = {
            "effective_at": iso_z(revoked_at),
            "reason": rreason,
        }

    # 撤销可用区间 = CRL 有效且尚未到撤销生效时刻；[thisUpdate, nextUpdate) 半开，
    # 撤销时刻本身起不可用。端点相接（revoked_at == 某边界）不算断档。
    for s, e in valid:
        if revoked_at is not None:
            e2 = min(e, revoked_at)
            if s < e2:
                clean.append((s, e2))
        else:
            if s < e:
                clean.append((s, e))

    if revoked_at is not None:
        reasons.append(
            f"certificate {label} (serial {format(child.serial_number, 'X')})"
            f" revoked at {iso_z(revoked_at)}"
        )

    member["reasons"] = reasons
    flat = [f"{label}: {r}" for r in reasons]
    return member, clean, flat


def _assess_window(window, cert_row, roots, domain, eval_start, eval_end, snapshot=None):
    """评估单个服务窗口：返回 (报告, 可用区间列表)。

    可用区间 = 窗口 ∩ 评估区间 ∩ 证书链有效期（启用快照时再 ∩ 逐证书
    撤销可用区间），且证书须通过全部 X.509 校验。
    """
    w_start = max(parse_ts(window["start_utc"]), eval_start)
    w_end = min(parse_ts(window["end_utc"]), eval_end)
    reasons: list[str] = []
    intervals: list[tuple[datetime, datetime]] = []
    sans: list[str] = json.loads(cert_row["san_dns"]) if cert_row else []
    revocation: list[dict] = []

    if cert_row is None:
        reasons.append(
            f"certificate {window['certificate_fingerprint']} not found in inventory"
        )
    else:
        try:
            certs = certutils.parse_pem_chain(cert_row["chain_pem"])
            leaf, intermediates = certs[0], certs[1:]
            sans = certutils.san_dns_names(leaf)
            if not sans:
                raise certutils.ChainValidationError(
                    "leaf certificate has no DNS subjectAltName"
                )
            if not certutils.san_matches(sans, domain):
                raise certutils.ChainValidationError(
                    f"SAN {sans} does not match domain '{domain}'"
                )
            chain = certutils.build_chain(leaf, intermediates, roots)
        except certutils.PemParseError as exc:
            reasons.append(f"stored certificate PEM unreadable: {exc}")
        except certutils.ChainValidationError as exc:
            reasons.append(str(exc))
        else:
            if w_start >= w_end:
                reasons.append("service window does not overlap the evaluation interval")
            else:
                nb, na = certutils.chain_validity_interval(chain)
                s, e = max(w_start, nb), min(w_end, na)
                valid_intervals: list[tuple[datetime, datetime]] = (
                    [(s, e)] if s < e else []
                )
                if nb > w_start:
                    reasons.append(
                        f"certificate chain not valid until {iso_z(nb)},"
                        f" after window start {iso_z(w_start)}"
                    )
                if na < w_end:
                    reasons.append(
                        f"certificate chain expires at {iso_z(na)},"
                        f" before window end {iso_z(w_end)}"
                    )
                if not valid_intervals and not reasons:
                    reasons.append(
                        "certificate validity does not overlap the service window"
                    )

                if snapshot is not None:
                    # 链上每张非根证书（叶子 + 中间证书）都必须有签发者 CRL；
                    # 撤销可用 = 全体成员干净时段的交集（缺一即断档）。
                    acc: list[tuple[datetime, datetime]] | None = None
                    for idx in range(len(chain) - 1):
                        member, clean, flat = _revocation_evidence(
                            chain[idx], chain[idx + 1], snapshot, w_start, w_end
                        )
                        revocation.append(member)
                        reasons.extend(flat)
                        acc = clean if acc is None else coverage.intersect(acc, clean)
                    valid_intervals = [
                        (max(s, cs), min(e, ce))
                        for s, e in valid_intervals
                        for cs, ce in (acc or [])
                        if max(s, cs) < min(e, ce)
                    ]

                intervals = valid_intervals

    report = {
        "window_id": window["id"],
        "fingerprint": window["certificate_fingerprint"],
        "role": window["role"],
        "window": {"start": window["start_utc"], "end": window["end_utc"]},
        "subject": cert_row["subject"] if cert_row else None,
        "sans": sans,
        "usable_intervals": [
            {"start": iso_z(s), "end": iso_z(e)} for s, e in intervals
        ],
        "reasons": reasons,
    }
    if snapshot is not None:
        report["revocation"] = revocation
    return report, intervals


def _compute_evaluation(
    conn,
    domain,
    eval_start,
    eval_end,
    version,
    snapshot_version,
    windows_override=None,
) -> dict:
    """纯计算：按给定信任根版本与可选 CRL 快照评估域名窗口覆盖情况。

    windows_override 非空时使用候选窗口集合（窗口变更预演用，不落库）；
    元素需与 service_windows 行同样提供下标访问。不写评估历史。
    """
    root_row = conn.execute(
        "SELECT * FROM trust_roots WHERE version = ?", (version,)
    ).fetchone()
    if root_row is None:
        raise ApiError(404, f"unknown trust root version '{version}'")
    roots = certutils.parse_pem_chain(root_row["pem"])
    snapshot = _load_snapshot(conn, snapshot_version)
    if windows_override is not None:
        windows = windows_override
    else:
        windows = conn.execute(
            "SELECT * FROM service_windows WHERE domain = ? ORDER BY start_utc, id",
            (domain,),
        ).fetchall()

    usable: list[tuple[datetime, datetime]] = []
    reports = []
    for w in windows:
        cert_row = conn.execute(
            "SELECT * FROM certificates WHERE fingerprint_sha256 = ?",
            (w["certificate_fingerprint"],),
        ).fetchone()
        report, intervals = _assess_window(
            w, cert_row, roots, domain, eval_start, eval_end, snapshot
        )
        usable.extend(intervals)
        reports.append(report)

    gaps = coverage.compute_gaps(eval_start, eval_end, usable)
    return {
        "domain": domain,
        "eval_start": iso_z(eval_start),
        "eval_end": iso_z(eval_end),
        "trust_root_version": version,
        "crl_snapshot_version": snapshot_version,
        "has_gaps": bool(gaps),
        "gaps": [{"start": iso_z(s), "end": iso_z(e)} for s, e in gaps],
        "certificates": reports,
        "evaluated_at": iso_z(now_utc()),
    }


def _evaluate(conn, plan_id, domain, eval_start, eval_end, version, snapshot_version) -> dict:
    """评估并写入评估历史（计划创建/重评使用）。"""
    result = _compute_evaluation(
        conn, domain, eval_start, eval_end, version, snapshot_version
    )
    conn.execute(
        "INSERT INTO evaluations (plan_id, trust_root_version, crl_snapshot_version,"
        " has_gaps, result_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (
            plan_id,
            version,
            snapshot_version,
            1 if result["has_gaps"] else 0,
            json.dumps(result),
            iso_z(now_utc()),
        ),
    )
    conn.execute(
        "UPDATE plans SET updated_at = ? WHERE id = ?", (iso_z(now_utc()), plan_id)
    )
    return result


# ---------------------------------------------------------------------------
# 计划与批准
# ---------------------------------------------------------------------------

def _get_plan(conn, plan_id: int):
    row = conn.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
    if row is None:
        raise ApiError(404, f"unknown plan id {plan_id}")
    return row


def create_plan(
    domain: str,
    eval_start: datetime,
    eval_end: datetime,
    trust_root_version: str | None,
    crl_snapshot_version: str | None = None,
) -> dict:
    if eval_start >= eval_end:
        raise ApiError(
            400,
            "invalid evaluation interval: eval_start "
            f"{iso_z(eval_start)} must be before eval_end {iso_z(eval_end)}",
        )
    with _write_lock, db.connect() as conn:
        version = trust_root_version or _active_version(conn)
        if version is None:
            raise ApiError(
                400,
                "no trust root version specified and no trust root version is active",
            )
        if not conn.execute(
            "SELECT 1 FROM trust_roots WHERE version = ?", (version,)
        ).fetchone():
            raise ApiError(404, f"unknown trust root version '{version}'")
        if crl_snapshot_version is not None and not conn.execute(
            "SELECT 1 FROM crl_snapshots WHERE version = ?", (crl_snapshot_version,)
        ).fetchone():
            raise ApiError(
                404, f"unknown CRL snapshot version '{crl_snapshot_version}'"
            )
        ts = iso_z(now_utc())
        cur = conn.execute(
            "INSERT INTO plans (domain, eval_start, eval_end, trust_root_version,"
            " crl_snapshot_version, status, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)",
            (
                domain,
                iso_z(eval_start),
                iso_z(eval_end),
                version,
                crl_snapshot_version,
                ts,
                ts,
            ),
        )
        plan_id = cur.lastrowid
        evaluation = _evaluate(
            conn, plan_id, domain, eval_start, eval_end, version, crl_snapshot_version
        )
        plan = _get_plan(conn, plan_id)
    return {"plan": _plan_dict(plan), "evaluation": evaluation}


def evaluate_plan(
    plan_id: int,
    trust_root_version: str | None,
    crl_snapshot_version: str | None = None,
    snapshot_given: bool = False,
) -> dict:
    """重新评估计划。

    - 快照参数省略时沿用计划当前选择；显式传 null 取消快照（回到无快照语义）；
    - 切换快照（含启用/取消）时，已批准计划须先转待复核，冻结批准被取代；
    - 历史评估与历史批准保留各自的快照版本与判定。
    """
    with _write_lock, db.connect() as conn:
        plan = _get_plan(conn, plan_id)
        version = trust_root_version or plan["trust_root_version"]
        if not conn.execute(
            "SELECT 1 FROM trust_roots WHERE version = ?", (version,)
        ).fetchone():
            raise ApiError(404, f"unknown trust root version '{version}'")
        if snapshot_given:
            new_snapshot = crl_snapshot_version
        else:
            new_snapshot = plan["crl_snapshot_version"]
        if new_snapshot is not None and not conn.execute(
            "SELECT 1 FROM crl_snapshots WHERE version = ?", (new_snapshot,)
        ).fetchone():
            raise ApiError(404, f"unknown CRL snapshot version '{new_snapshot}'")

        ts = iso_z(now_utc())
        if version != plan["trust_root_version"] or new_snapshot != plan["crl_snapshot_version"]:
            conn.execute(
                "UPDATE plans SET trust_root_version = ?, crl_snapshot_version = ?,"
                " updated_at = ? WHERE id = ?",
                (version, new_snapshot, ts, plan_id),
            )
        if (
            new_snapshot != plan["crl_snapshot_version"]
            and plan["status"] == "approved"
        ):
            conn.execute(
                "UPDATE plans SET status = 'pending_review' WHERE id = ?", (plan_id,)
            )
            conn.execute(
                "UPDATE approvals SET superseded = 1 WHERE plan_id = ?"
                " AND superseded = 0",
                (plan_id,),
            )
        result = _evaluate(
            conn,
            plan_id,
            plan["domain"],
            parse_ts(plan["eval_start"]),
            parse_ts(plan["eval_end"]),
            version,
            new_snapshot,
        )
    result["plan_id"] = plan_id
    return result


def approve_plan(plan_id: int) -> dict:
    """批准计划：仅无断档时可批准，并冻结证书指纹、信任根版本与判定。"""
    with _write_lock, db.connect() as conn:
        plan = _get_plan(conn, plan_id)
        if plan["status"] == "approved":
            raise ApiError(409, "plan is already approved")
        ev = conn.execute(
            "SELECT * FROM evaluations WHERE plan_id = ? ORDER BY id DESC LIMIT 1",
            (plan_id,),
        ).fetchone()
        if ev is None:
            raise ApiError(409, "plan has no evaluation; run evaluate first")
        verdict = json.loads(ev["result_json"])
        if verdict["has_gaps"]:
            raise ApiError(
                409,
                f"plan has {len(verdict['gaps'])} coverage gap(s);"
                " only gap-free plans can be approved",
            )
        fps = sorted(
            {
                r["certificate_fingerprint"]
                for r in conn.execute(
                    "SELECT DISTINCT certificate_fingerprint FROM service_windows"
                    " WHERE domain = ?",
                    (plan["domain"],),
                ).fetchall()
            }
        )
        ts = iso_z(now_utc())
        cur = conn.execute(
            "INSERT INTO approvals (plan_id, trust_root_version, crl_snapshot_version,"
            " cert_fingerprints, verdict_json, superseded, created_at)"
            " VALUES (?, ?, ?, ?, ?, 0, ?)",
            (
                plan_id,
                ev["trust_root_version"],
                ev["crl_snapshot_version"],
                json.dumps(fps),
                ev["result_json"],
                ts,
            ),
        )
        conn.execute(
            "UPDATE plans SET status = 'approved', updated_at = ? WHERE id = ?",
            (ts, plan_id),
        )
        approval = conn.execute(
            "SELECT * FROM approvals WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
        plan = _get_plan(conn, plan_id)
    return {"plan": _plan_dict(plan), "approval": _approval_dict(approval)}


def get_plan(plan_id: int) -> dict:
    with db.connect() as conn:
        plan = _get_plan(conn, plan_id)
        ev = conn.execute(
            "SELECT * FROM evaluations WHERE plan_id = ? ORDER BY id DESC LIMIT 1",
            (plan_id,),
        ).fetchone()
        approvals = conn.execute(
            "SELECT * FROM approvals WHERE plan_id = ? ORDER BY id", (plan_id,)
        ).fetchall()
    result = _plan_dict(plan)
    result["latest_evaluation"] = json.loads(ev["result_json"]) if ev else None
    result["approvals"] = [_approval_dict(a) for a in approvals]
    return result


def list_plans(domain: str | None, status: str | None) -> list[dict]:
    sql = "SELECT * FROM plans"
    clauses, params = [], []
    if domain:
        clauses.append("domain = ?")
        params.append(domain)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id"
    with db.connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_plan_dict(r) for r in rows]


def list_evaluations(plan_id: int) -> list[dict]:
    with db.connect() as conn:
        _get_plan(conn, plan_id)
        rows = conn.execute(
            "SELECT * FROM evaluations WHERE plan_id = ? ORDER BY id", (plan_id,)
        ).fetchall()
    return [
        {
            "id": r["id"],
            "plan_id": r["plan_id"],
            "trust_root_version": r["trust_root_version"],
            "crl_snapshot_version": r["crl_snapshot_version"],
            "has_gaps": bool(r["has_gaps"]),
            "result": json.loads(r["result_json"]),
            "created_at": r["created_at"],
        }
        for r in rows
    ]


def list_approvals(plan_id: int) -> list[dict]:
    with db.connect() as conn:
        _get_plan(conn, plan_id)
        rows = conn.execute(
            "SELECT * FROM approvals WHERE plan_id = ? ORDER BY id", (plan_id,)
        ).fetchall()
    return [_approval_dict(r) for r in rows]


# ---------------------------------------------------------------------------
# 按域名成组窗口变更：预演 → 原子提交
# ---------------------------------------------------------------------------

_META_HMAC_KEY = "window_change_hmac_secret"


def _hmac_secret(conn) -> bytes:
    """取（必要时惰性生成）预演提交令牌的服务器端 HMAC 密钥。

    该密钥仅写入 app_meta，不属于窗口/评估/批准历史，不影响业务数据。
    """
    row = conn.execute(
        "SELECT value FROM app_meta WHERE key = ?", (_META_HMAC_KEY,)
    ).fetchone()
    if row is not None:
        return row["value"].encode("ascii")
    secret = secrets.token_hex(32)
    conn.execute(
        "INSERT OR IGNORE INTO app_meta (key, value) VALUES (?, ?)",
        (_META_HMAC_KEY, secret),
    )
    row = conn.execute(
        "SELECT value FROM app_meta WHERE key = ?", (_META_HMAC_KEY,)
    ).fetchone()
    return row["value"].encode("ascii")


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _canonical_change(domain: str, delete_ids: list[int], add_windows) -> bytes:
    """变更请求的规范化载荷（时间统一为 UTC 毫秒 Z，删除 ID 排序）。"""
    payload = {
        "domain": domain,
        "delete_window_ids": sorted(set(delete_ids)),
        "add_windows": [
            {
                "certificate_fingerprint": w[0].lower(),
                "role": w[1],
                "start": iso_z(w[2]),
                "end": iso_z(w[3]),
            }
            for w in add_windows
        ],
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _window_state_hash(conn, domain: str) -> str:
    rows = conn.execute(
        "SELECT id, certificate_fingerprint, role, start_utc, end_utc"
        " FROM service_windows WHERE domain = ? ORDER BY id",
        (domain,),
    ).fetchall()
    h = hashlib.sha256()
    for r in rows:
        h.update(
            f"{r['id']}|{r['certificate_fingerprint']}|{r['role']}|"
            f"{r['start_utc']}|{r['end_utc']}\n".encode("utf-8")
        )
    return h.hexdigest()


def _plan_state_hash(conn, domain: str) -> str:
    # 仅纳入会改变判定前提或需触发待复核的字段；纯重评（只更新评估历史与
    # updated_at）不使未提交预演失效。
    rows = conn.execute(
        "SELECT id, status, trust_root_version, crl_snapshot_version,"
        " eval_start, eval_end FROM plans WHERE domain = ? ORDER BY id",
        (domain,),
    ).fetchall()
    h = hashlib.sha256()
    for r in rows:
        h.update(
            f"{r['id']}|{r['status']}|{r['trust_root_version']}|"
            f"{r['crl_snapshot_version']}|{r['eval_start']}|{r['eval_end']}\n"
            .encode("utf-8")
        )
    return h.hexdigest()


def _issue_change_token(
    conn,
    domain: str,
    delete_ids: list[int],
    add_windows,
    window_hash: str,
    plan_hash: str,
) -> str:
    claims = {
        "d": domain,
        "p": _canonical_change(domain, delete_ids, add_windows).decode("utf-8"),
        "w": window_hash,
        "pl": plan_hash,
        "n": secrets.token_hex(8),
    }
    body = _b64e(
        json.dumps(claims, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    sig = _b64e(hmac.new(_hmac_secret(conn), body.encode("ascii"), hashlib.sha256).digest())
    return f"{body}.{sig}"


def _parse_change_token(conn, token: str) -> dict:
    """校验并解码提交令牌；格式或签名错误一律拒绝（400）。"""
    parts = token.split(".")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ApiError(400, "invalid commit token: malformed")
    body, sig = parts
    expected = _b64e(
        hmac.new(_hmac_secret(conn), body.encode("ascii"), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(sig, expected):
        raise ApiError(400, "invalid commit token: signature mismatch")
    try:
        claims = json.loads(_b64d(body))
    except Exception as exc:
        raise ApiError(400, "invalid commit token: malformed") from exc
    for key in ("d", "p", "w", "pl"):
        if not isinstance(claims.get(key), str):
            raise ApiError(400, "invalid commit token: malformed claims")
    return claims


def _validate_change(conn, domain: str, delete_ids: list[int], add_windows) -> dict:
    """校验成组窗口变更请求，返回待删窗口行（按 id）。

    无效区间 → 400；跨域或重复删除 → 400；
    未知窗口 ID / 未知证书指纹 → 404。
    """
    if not delete_ids and not add_windows:
        raise ApiError(
            400,
            "empty window change: at least one window id to delete or one window"
            " to add is required",
        )
    if len(delete_ids) != len(set(delete_ids)):
        dupes = sorted({wid for wid in delete_ids if delete_ids.count(wid) > 1})
        raise ApiError(
            400, f"duplicate window ids in delete_window_ids: {dupes}"
        )

    rows_by_id: dict[int, object] = {}
    for wid in set(delete_ids):
        row = conn.execute(
            "SELECT * FROM service_windows WHERE id = ?", (wid,)
        ).fetchone()
        if row is None:
            raise ApiError(404, f"unknown service window id {wid}")
        if row["domain"] != domain:
            raise ApiError(
                400,
                f"window id {wid} belongs to domain '{row['domain']}',"
                f" not to '{domain}': window changes are scoped to a single domain",
            )
        rows_by_id[wid] = row

    for idx, w in enumerate(add_windows, start=1):
        fp, role, start, end = w
        if start >= end:
            raise ApiError(
                400,
                f"add_windows[{idx}] invalid time window: start {iso_z(start)}"
                f" must be before end {iso_z(end)}",
            )
        if not conn.execute(
            "SELECT 1 FROM certificates WHERE fingerprint_sha256 = ?", (fp,)
        ).fetchone():
            raise ApiError(
                404,
                f"add_windows[{idx}] unknown certificate fingerprint '{fp}'",
            )
    return rows_by_id


def _candidate_windows(conn, domain: str, delete_ids: set[int], add_windows) -> list:
    """候选窗口集合 = 该域名现存窗口（剔除待删）+ 待登记窗口（未落库）。"""
    rows = conn.execute(
        "SELECT * FROM service_windows WHERE domain = ? ORDER BY start_utc, id",
        (domain,),
    ).fetchall()
    windows = [dict(r) for r in rows if r["id"] not in delete_ids]
    ts = iso_z(now_utc())
    for idx, w in enumerate(add_windows, start=1):
        fp, role, start, end = w
        windows.append(
            {
                "id": f"new-{idx}",
                "domain": domain,
                "certificate_fingerprint": fp,
                "role": role,
                "start_utc": iso_z(start),
                "end_utc": iso_z(end),
                "created_at": ts,
            }
        )
    windows.sort(key=lambda r: (r["start_utc"], str(r["id"])))
    return windows


def _blocking_reasons(evaluation: dict) -> list[str]:
    seen: set[str] = set()
    reasons: list[str] = []
    for cert in evaluation["certificates"]:
        for reason in cert.get("reasons", []):
            if reason not in seen:
                seen.add(reason)
                reasons.append(reason)
    return reasons


def _recompute_plan(conn, plan, candidate) -> dict:
    """按计划当前选定的信任根版本与可选 CRL 快照重算（不写历史）。"""
    return _compute_evaluation(
        conn,
        plan["domain"],
        parse_ts(plan["eval_start"]),
        parse_ts(plan["eval_end"]),
        plan["trust_root_version"],
        plan["crl_snapshot_version"],
        windows_override=candidate,
    )


def preview_window_change(domain: str, delete_ids: list[int], add_windows) -> dict:
    """预演按域名的成组窗口增删：不改动窗口、评估或批准历史。

    返回各相关计划变更前后的断档区间与阻断原因，以及提交所需的令牌。
    """
    with _write_lock, db.connect() as conn:
        _validate_change(conn, domain, delete_ids, add_windows)
        plans = conn.execute(
            "SELECT * FROM plans WHERE domain = ? ORDER BY id", (domain,)
        ).fetchall()
        candidate = _candidate_windows(conn, domain, set(delete_ids), add_windows)

        changes = []
        blocked = False
        for plan in plans:
            before = _compute_evaluation(
                conn,
                plan["domain"],
                parse_ts(plan["eval_start"]),
                parse_ts(plan["eval_end"]),
                plan["trust_root_version"],
                plan["crl_snapshot_version"],
            )
            after = _recompute_plan(conn, plan, candidate)
            approved = plan["status"] == "approved"
            would_block = approved and after["has_gaps"]
            blocked = blocked or would_block
            changes.append(
                {
                    "plan_id": plan["id"],
                    "status": plan["status"],
                    "trust_root_version": plan["trust_root_version"],
                    "crl_snapshot_version": plan["crl_snapshot_version"],
                    "approved": approved,
                    "would_block": would_block,
                    "before": {
                        "has_gaps": before["has_gaps"],
                        "gaps": before["gaps"],
                        "blocking_reasons": _blocking_reasons(before),
                    },
                    "after": {
                        "has_gaps": after["has_gaps"],
                        "gaps": after["gaps"],
                        "blocking_reasons": _blocking_reasons(after),
                    },
                }
            )

        window_hash = _window_state_hash(conn, domain)
        plan_hash = _plan_state_hash(conn, domain)
        token = _issue_change_token(
            conn, domain, delete_ids, add_windows, window_hash, plan_hash
        )
        return {
            "domain": domain,
            "delete_window_ids": sorted(set(delete_ids)),
            "add_windows": [
                {
                    "temporary_id": f"new-{idx}",
                    "certificate_fingerprint": w[0],
                    "role": w[1],
                    "start": iso_z(w[2]),
                    "end": iso_z(w[3]),
                }
                for idx, w in enumerate(add_windows, start=1)
            ],
            "candidate_windows": [
                {
                    "id": w["id"],
                    "certificate_fingerprint": w["certificate_fingerprint"],
                    "role": w["role"],
                    "start": w["start_utc"],
                    "end": w["end_utc"],
                }
                for w in candidate
            ],
            "blocked": blocked,
            "plans": changes,
            "commit_token": token,
        }


def commit_window_change(domain: str, delete_ids: list[int], add_windows, token: str | None) -> dict:
    """携带预演令牌原子提交成组窗口增删。

    - 令牌缺失/非法 → 400；载荷不一致或域名窗口/相关计划状态、判定前提已变化
      （预演过期）→ 409；待删窗口已不存在 → 404；
    - 候选状态使任一当前已批准计划出现断档 → 整组 409 拒绝，无部分变更；
    - 否则原子应用全部增删，相关已批准计划转待复核，冻结批准历史保留。
    """
    if not token:
        raise ApiError(
            400,
            "commit_token is required: run POST /window-change/preview first",
        )
    with _write_lock, db.connect() as conn:
        claims = _parse_change_token(conn, token)
        if claims["d"] != domain:
            raise ApiError(
                409, "stale window change: token was issued for a different domain"
            )
        expected_payload = _canonical_change(domain, delete_ids, add_windows).decode(
            "utf-8"
        )
        if not hmac.compare_digest(claims["p"], expected_payload):
            raise ApiError(
                409,
                "stale window change: change parameters do not match the previewed"
                " change; re-run preview for the current parameters",
            )

        # 先判定预演是否过期（窗口/计划状态在预演后已变化）→ 409；
        # 再校验待删窗口存在性、跨域与区间合法性（404/400）。
        if claims["w"] != _window_state_hash(conn, domain):
            raise ApiError(
                409,
                "stale window change: domain service windows changed after the"
                " preview was issued; re-run preview",
            )
        if claims["pl"] != _plan_state_hash(conn, domain):
            raise ApiError(
                409,
                "stale window change: a related plan status or evaluation basis"
                " changed after the preview was issued; re-run preview",
            )

        rows_by_id = _validate_change(conn, domain, delete_ids, add_windows)

        plans = conn.execute(
            "SELECT * FROM plans WHERE domain = ? ORDER BY id", (domain,)
        ).fetchall()
        candidate = _candidate_windows(conn, domain, set(delete_ids), add_windows)
        after_by_plan: dict[int, dict] = {}
        blocking: list[dict] = []
        for plan in plans:
            after = _recompute_plan(conn, plan, candidate)
            after_by_plan[plan["id"]] = after
            if plan["status"] == "approved" and after["has_gaps"]:
                blocking.append(
                    {
                        "plan_id": plan["id"],
                        "gaps": after["gaps"],
                        "blocking_reasons": _blocking_reasons(after),
                    }
                )
        if blocking:
            raise ApiError(
                409,
                "window change rejected: candidate state leaves "
                f"{len(blocking)} currently approved plan(s) with coverage"
                f" gaps: {json.dumps(blocking, ensure_ascii=False)}",
            )

        # 校验通过：同一事务内原子应用全部增删；任何异常均整体回滚。
        ts = iso_z(now_utc())
        for wid in set(delete_ids):
            conn.execute("DELETE FROM service_windows WHERE id = ?", (wid,))
        added_ids = []
        for w in add_windows:
            fp, role, start, end = w
            cur = conn.execute(
                "INSERT INTO service_windows"
                " (domain, certificate_fingerprint, role, start_utc, end_utc, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (domain, fp, role, iso_z(start), iso_z(end), ts),
            )
            added_ids.append(cur.lastrowid)
        marked = _mark_domain_plans_pending_review(conn, domain)

        deleted = [_window_dict(rows_by_id[wid]) for wid in set(delete_ids)]
        added_rows = conn.execute(
            "SELECT * FROM service_windows WHERE id IN (%s) ORDER BY id"
            % ",".join("?" for _ in added_ids),
            added_ids,
        ).fetchall() if added_ids else []
        plans_after = [
            {
                "plan_id": plan["id"],
                "status": (
                    "pending_review" if plan["status"] == "approved" else plan["status"]
                ),
                "has_gaps": after_by_plan[plan["id"]]["has_gaps"],
                "gaps": after_by_plan[plan["id"]]["gaps"],
                "blocking_reasons": _blocking_reasons(after_by_plan[plan["id"]]),
            }
            for plan in plans
        ]
        return {
            "domain": domain,
            "applied": True,
            "deleted_windows": deleted,
            "added_windows": [_window_dict(r) for r in added_rows],
            "plans_marked_pending_review": marked,
            "plans": plans_after,
        }
