"""业务逻辑：信任根版本、证书链、服务窗口、CRL 撤销快照、评估计划与批准。"""
from __future__ import annotations

import hashlib
import json
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
    windows=None,
) -> dict:
    """纯评估计算：读取信任根/快照/证书与窗口集合，不写入任何历史。

    windows 为 None 时使用库中该域名的当前窗口集合；否则使用给定的候选
    集合（元素为含 id/certificate_fingerprint/role/start_utc/end_utc 的
    映射，候选新窗口的 id 为 None）。供计划评估与窗口变更预演共用。
    """
    root_row = conn.execute(
        "SELECT * FROM trust_roots WHERE version = ?", (version,)
    ).fetchone()
    if root_row is None:
        raise ApiError(404, f"unknown trust root version '{version}'")
    roots = certutils.parse_pem_chain(root_row["pem"])
    snapshot = _load_snapshot(conn, snapshot_version)
    if windows is None:
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
    """评估计划并写入评估历史（窗口变更预演复用 _compute_evaluation，不写历史）。"""
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
# 域名级窗口变更（预演 + 原子提交）
# ---------------------------------------------------------------------------

def _candidate_windows(conn, domain: str, delete_ids: set[int], adds: list[dict]) -> list[dict]:
    """当前窗口集合应用增删后的候选集合（候选新窗口的 id 为 None）。"""
    rows = conn.execute(
        "SELECT * FROM service_windows WHERE domain = ? ORDER BY start_utc, id",
        (domain,),
    ).fetchall()
    candidates: list[dict] = [
        {
            "id": r["id"],
            "domain": r["domain"],
            "certificate_fingerprint": r["certificate_fingerprint"],
            "role": r["role"],
            "start_utc": r["start_utc"],
            "end_utc": r["end_utc"],
        }
        for r in rows
        if r["id"] not in delete_ids
    ]
    for add in adds:
        candidates.append(
            {
                "id": None,
                "domain": domain,
                "certificate_fingerprint": add["fingerprint"],
                "role": add["role"],
                "start_utc": iso_z(add["start"]),
                "end_utc": iso_z(add["end"]),
            }
        )
    candidates.sort(key=lambda w: (w["start_utc"], w["id"] is None, w["id"] or 0))
    return candidates


def _validate_window_change(conn, domain: str, delete_ids: list[int], adds: list[dict]):
    """校验变更集，返回 (待删除窗口行列表, 候选窗口集合)。

    空变更/重复删除/跨域删除/无效区间 → 400；未知窗口/证书指纹 → 404。
    """
    if not delete_ids and not adds:
        raise ApiError(400, "empty window change: nothing to delete or add")
    seen: set[int] = set()
    dups: list[int] = []
    for wid in delete_ids:
        if wid in seen and wid not in dups:
            dups.append(wid)
        seen.add(wid)
    if dups:
        raise ApiError(400, f"duplicate delete window id(s): {sorted(dups)}")
    deleted = []
    for wid in delete_ids:
        row = conn.execute(
            "SELECT * FROM service_windows WHERE id = ?", (wid,)
        ).fetchone()
        if row is None:
            raise ApiError(404, f"unknown service window id {wid}")
        if row["domain"] != domain:
            raise ApiError(
                400,
                f"service window id {wid} belongs to domain '{row['domain']}';"
                f" a window change is scoped to a single domain ('{domain}')",
            )
        deleted.append(row)
    for add in adds:
        if add["start"] >= add["end"]:
            raise ApiError(
                400,
                "invalid time window: start "
                f"{iso_z(add['start'])} must be before end {iso_z(add['end'])}",
            )
        if not conn.execute(
            "SELECT 1 FROM certificates WHERE fingerprint_sha256 = ?",
            (add["fingerprint"],),
        ).fetchone():
            raise ApiError(
                404, f"unknown certificate fingerprint '{add['fingerprint']}'"
            )
    return deleted, _candidate_windows(conn, domain, set(delete_ids), adds)


def _window_change_token(conn, domain: str, delete_ids: list[int], adds: list[dict]) -> str:
    """提交校验标识：绑定变更内容与预演时的判定依据。

    判定依据 = 该域名当前窗口集合 + 相关计划的状态及其当前选定的
    信任根版本 / CRL 快照版本。预演后任一变化（窗口增删、计划状态流转、
    重选信任根或快照、相关计划增删）都会使标识失效，提交被拒绝。
    """
    windows = conn.execute(
        "SELECT * FROM service_windows WHERE domain = ? ORDER BY id", (domain,)
    ).fetchall()
    plans = conn.execute(
        "SELECT * FROM plans WHERE domain = ? ORDER BY id", (domain,)
    ).fetchall()
    material = {
        "domain": domain,
        "change": {
            "delete_window_ids": sorted(delete_ids),
            "add_windows": sorted(
                [a["fingerprint"], a["role"], iso_z(a["start"]), iso_z(a["end"])]
                for a in adds
            ),
        },
        "windows": [
            [w["id"], w["certificate_fingerprint"], w["role"],
             w["start_utc"], w["end_utc"]]
            for w in windows
        ],
        "plans": [
            [p["id"], p["status"], p["trust_root_version"],
             p["crl_snapshot_version"], p["eval_start"], p["eval_end"]]
            for p in plans
        ],
    }
    blob = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return "wc1." + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _blocking_reasons(conn, domain: str, candidates: list[dict]) -> list[str]:
    """候选窗口集合下，当前已批准计划会出现的断档（整组阻断原因）。"""
    reasons: list[str] = []
    plans = conn.execute(
        "SELECT * FROM plans WHERE domain = ? AND status = 'approved' ORDER BY id",
        (domain,),
    ).fetchall()
    for p in plans:
        after = _compute_evaluation(
            conn,
            domain,
            parse_ts(p["eval_start"]),
            parse_ts(p["eval_end"]),
            p["trust_root_version"],
            p["crl_snapshot_version"],
            windows=candidates,
        )
        if after["has_gaps"]:
            gap_str = ", ".join(
                f"[{g['start']}, {g['end']})" for g in after["gaps"]
            )
            reasons.append(
                f"plan #{p['id']} is approved and the change would open"
                f" {len(after['gaps'])} coverage gap(s): {gap_str}"
            )
    return reasons


def preview_window_change(domain: str, delete_ids: list[int], adds: list[dict]) -> dict:
    """预演一次域名级窗口变更（只读：不改动窗口、评估或批准历史）。

    基于候选窗口集合，按每个相关计划当前选定的信任根版本与可选 CRL
    快照重算变更前后的断档；返回逐计划对比、阻断原因与提交校验标识。
    """
    with db.connect() as conn:
        deleted, candidates = _validate_window_change(conn, domain, delete_ids, adds)
        plans = conn.execute(
            "SELECT * FROM plans WHERE domain = ? ORDER BY id", (domain,)
        ).fetchall()
        plan_reports = []
        blocking: list[str] = []
        for p in plans:
            eval_start, eval_end = parse_ts(p["eval_start"]), parse_ts(p["eval_end"])
            before = _compute_evaluation(
                conn, domain, eval_start, eval_end,
                p["trust_root_version"], p["crl_snapshot_version"],
            )
            after = _compute_evaluation(
                conn, domain, eval_start, eval_end,
                p["trust_root_version"], p["crl_snapshot_version"],
                windows=candidates,
            )
            reasons: list[str] = []
            if p["status"] == "approved" and after["has_gaps"]:
                gap_str = ", ".join(
                    f"[{g['start']}, {g['end']})" for g in after["gaps"]
                )
                reasons.append(
                    f"plan #{p['id']} is approved and the change would open"
                    f" {len(after['gaps'])} coverage gap(s): {gap_str}"
                )
                blocking.extend(reasons)
            plan_reports.append(
                {
                    "plan_id": p["id"],
                    "status": p["status"],
                    "trust_root_version": p["trust_root_version"],
                    "crl_snapshot_version": p["crl_snapshot_version"],
                    "before": before,
                    "after": after,
                    "blocking_reasons": reasons,
                }
            )
        token = _window_change_token(conn, domain, delete_ids, adds)
    return {
        "domain": domain,
        "change_token": token,
        "would_block": bool(blocking),
        "blocking_reasons": blocking,
        "delete_windows": [_window_dict(r) for r in deleted],
        "add_windows": [
            {
                "certificate_fingerprint": a["fingerprint"],
                "role": a["role"],
                "start": iso_z(a["start"]),
                "end": iso_z(a["end"]),
            }
            for a in adds
        ],
        "plans": plan_reports,
    }


def commit_window_change(
    domain: str, change_token: str, delete_ids: list[int], adds: list[dict]
) -> dict:
    """原子提交一次经预演的窗口变更。

    - 预演后域名窗口、相关计划状态或判定依据已变化（标识失效）→ 409；
    - 候选状态使任一当前已批准计划出现断档 → 409，整组拒绝、无部分变更；
    - 否则同一事务内应用全部增删，相关已批准计划转待复核，
      历史冻结批准置 superseded 并完整保留。
    """
    with _write_lock, db.connect() as conn:
        deleted, candidates = _validate_window_change(conn, domain, delete_ids, adds)
        current_token = _window_change_token(conn, domain, delete_ids, adds)
        if change_token != current_token:
            raise ApiError(
                409,
                "stale or mismatched preview token: windows, related plan status"
                " or decision basis changed since the preview (or the change"
                " differs from the previewed one); run preview again",
            )
        blocking = _blocking_reasons(conn, domain, candidates)
        if blocking:
            raise ApiError(
                409,
                "window change rejected, no changes applied: " + "; ".join(blocking),
            )
        ts = iso_z(now_utc())
        for row in deleted:
            conn.execute("DELETE FROM service_windows WHERE id = ?", (row["id"],))
        created = []
        for add in adds:
            cur = conn.execute(
                "INSERT INTO service_windows"
                " (domain, certificate_fingerprint, role, start_utc, end_utc, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    domain,
                    add["fingerprint"],
                    add["role"],
                    iso_z(add["start"]),
                    iso_z(add["end"]),
                    ts,
                ),
            )
            created.append(
                _window_dict(
                    conn.execute(
                        "SELECT * FROM service_windows WHERE id = ?", (cur.lastrowid,)
                    ).fetchone()
                )
            )
        affected = _mark_domain_plans_pending_review(conn, domain)
    return {
        "domain": domain,
        "deleted_windows": [_window_dict(r) for r in deleted],
        "created_windows": created,
        "plans_marked_pending_review": affected,
    }
