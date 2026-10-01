"""离线生成演示用 CA 与证书，并初始化一份完整的演示数据：

- 信任根版本 demo-root-v1（自动激活）
- demo.example.com：现用 + 拟启用证书，窗口首尾相接，无断档 → 计划创建并批准
- demo-gap.example.com：两窗口之间留有 14 天断档 → 计划保持 pending，演示断档报告

幂等：若 demo-root-v1 已存在则跳过。
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app import db, service

UTC = timezone.utc
ROOT_VERSION = "demo-root-v1"


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_root_ca(cn: str, nb: datetime, na: datetime):
    key = _key()
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ops Demo"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def make_leaf(ca_cert, ca_key, domain: str, nb: datetime, na: datetime):
    key = _key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ops Demo"),
                    x509.NameAttribute(NameOID.COMMON_NAME, domain),
                ]
            )
        )
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


def make_crl(root_cert, root_key, last_update: str, next_update: str,
             revoked=None, number=None):
    """构造一张由根 CA 离线签发的 PEM CRL。

    revoked: [(serial:int, revocation_date:str, reason|None), ...]
    """
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root_cert.subject)
        .last_update(t(last_update))
        .next_update(t(next_update))
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
    )
    if number is not None:
        builder = builder.add_extension(x509.CRLNumber(number), critical=False)
    for serial, rev_date, reason in revoked or []:
        rc = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(t(rev_date))
        )
        if reason is not None:
            rc = rc.add_extension(x509.CRLReason(reason), critical=False)
        builder = builder.add_revoked_certificate(rc.build())
    return (
        builder.sign(root_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode("ascii")
    )


def pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def t(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=UTC)


def main() -> None:
    db.init_db()
    with db.connect() as conn:
        if conn.execute(
            "SELECT 1 FROM trust_roots WHERE version = ?", (ROOT_VERSION,)
        ).fetchone():
            print(f"[seed] trust root '{ROOT_VERSION}' already exists, skip seeding")
            return

    root, root_key = make_root_ca("Demo Root CA", t("2025-01-01"), t("2035-01-01"))
    service.import_trust_root(ROOT_VERSION, pem(root))
    print(f"[seed] trust root '{ROOT_VERSION}' imported and activated")

    scenarios = [
        # (域名, 现用窗口, 拟启用窗口, 现用证书有效期, 拟启用证书有效期)
        (
            "demo.example.com",
            ("2026-01-01", "2026-07-01"),
            ("2026-07-01", "2027-01-01"),
            ("2026-01-01", "2026-08-01"),
            ("2026-06-01", "2027-02-01"),
        ),
        (
            "demo-gap.example.com",
            ("2026-01-01", "2026-06-01"),
            ("2026-06-15", "2027-01-01"),
            ("2026-01-01", "2026-07-01"),
            ("2026-06-10", "2027-02-01"),
        ),
    ]

    current_serials: dict[str, int] = {}
    for domain, cur_win, plan_win, cur_val, plan_val in scenarios:
        cur_cert, _ = make_leaf(root, root_key, domain, t(cur_val[0]), t(cur_val[1]))
        plan_cert, _ = make_leaf(root, root_key, domain, t(plan_val[0]), t(plan_val[1]))
        current_serials[domain] = cur_cert.serial_number
        cur_fp = service.import_certificate(pem(cur_cert), f"{domain}-current")[
            "fingerprint_sha256"
        ]
        plan_fp = service.import_certificate(pem(plan_cert), f"{domain}-planned")[
            "fingerprint_sha256"
        ]
        service.create_window(domain, cur_fp, "current", t(cur_win[0]), t(cur_win[1]))
        service.create_window(domain, plan_fp, "planned", t(plan_win[0]), t(plan_win[1]))
        created = service.create_plan(domain, t("2026-01-01"), t("2027-01-01"), None)
        plan_id = created["plan"]["id"]
        has_gaps = created["evaluation"]["has_gaps"]
        print(
            f"[seed] {domain}: plan #{plan_id} evaluated, has_gaps={has_gaps},"
            f" gaps={created['evaluation']['gaps']}"
        )
        if not has_gaps:
            service.approve_plan(plan_id)
            print(f"[seed] {domain}: plan #{plan_id} approved")
        else:
            print(f"[seed] {domain}: plan #{plan_id} left pending (gaps exist)")

    # 两个不可变的离线撤销快照（默认不绑定任何计划，仅供演示选用）：
    # - demo-crl-2026Q1：CRL 覆盖整个评估区间且无撤销 → 选用后仍无断档
    # - demo-crl-2026Q1-revoked：撤销 demo.example.com 现用证书（2026-03-01 生效）
    #   → 选用后 2026-03-01 起断档
    good_crl = make_crl(root, root_key, "2025-12-01", "2027-02-01", revoked=[],
                        number=1)
    service.import_crl_snapshot("demo-crl-2026Q1", good_crl)
    print("[seed] CRL snapshot 'demo-crl-2026Q1' imported (no revocations)")

    revoked_crl = make_crl(
        root,
        root_key,
        "2025-12-01",
        "2027-02-01",
        revoked=[
            (
                current_serials["demo.example.com"],
                "2026-03-01",
                x509.ReasonFlags.key_compromise,
            )
        ],
        number=2,
    )
    service.import_crl_snapshot("demo-crl-2026Q1-revoked", revoked_crl)
    print(
        "[seed] CRL snapshot 'demo-crl-2026Q1-revoked' imported"
        " (revokes demo.example.com current cert at 2026-03-01)"
    )

    print("[seed] done")


if __name__ == "__main__":
    main()
