"""PEM CRL 解析、签名验证与撤销证据工具。

撤销快照（CRL snapshot）是一组带版本的离线 PEM CRL。本模块提供：

- 严格的 PEM CRL 解析（块外出现任何非空白内容即拒绝）；
- 签发者匹配（issuer DN + AKI/SKI）与签名验证；
- CRL 覆盖区间 [thisUpdate, nextUpdate) 与撤销生效时刻提取。
"""
from __future__ import annotations

import re

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID


class PemCrlError(Exception):
    """PEM CRL 载荷无法解析或 CRL 内容非法时抛出。"""


_CRL_BLOCK_RE = re.compile(
    r"-----BEGIN X509 CRL-----.*?-----END X509 CRL-----", re.DOTALL
)


def parse_pem_crls(pem: str) -> list[x509.CertificateRevocationList]:
    """解析包含一个或多个 PEM CRL 的文本（严格模式，与证书 PEM 同规则）。"""
    if not isinstance(pem, str) or not pem.strip():
        raise PemCrlError("empty PEM payload")
    blocks = _CRL_BLOCK_RE.findall(pem)
    if not blocks:
        raise PemCrlError("no PEM X509 CRL block found")
    remainder = _CRL_BLOCK_RE.sub("", pem)
    if remainder.strip():
        raise PemCrlError("unexpected data outside PEM CRL blocks")
    crls: list[x509.CertificateRevocationList] = []
    for i, block in enumerate(blocks, start=1):
        try:
            crls.append(x509.load_pem_x509_crl(block.encode("ascii")))
        except Exception as exc:  # cryptography 的各类解析异常统一收敛
            raise PemCrlError(f"CRL block #{i} is malformed: {exc}") from exc
    return crls


def crl_to_pem(crl: x509.CertificateRevocationList) -> str:
    return crl.public_bytes(serialization.Encoding.PEM).decode("ascii")


def authority_key_identifier(crl: x509.CertificateRevocationList) -> bytes | None:
    try:
        ext = crl.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        ).value
    except x509.ExtensionNotFound:
        return None
    return ext.key_identifier


def subject_key_identifier(cert: x509.Certificate) -> bytes | None:
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        ).value
    except x509.ExtensionNotFound:
        return None
    return ext.digest


def issuer_key(cert_or_crl) -> tuple[str, str]:
    """同一签发者身份键：(issuer DN, AKI hex 或空串)。

    同一签发者密钥滚动（新 SKI）产生的 CRL 不算冲突；DN 与 AKI 均相同的
    两个 CRL 才视为同一签发者列表。
    """
    if isinstance(cert_or_crl, x509.Certificate):
        dn = cert_or_crl.subject.rfc4514_string()
        aki = subject_key_identifier(cert_or_crl)
    else:
        dn = cert_or_crl.issuer.rfc4514_string()
        aki = authority_key_identifier(cert_or_crl)
    return (dn, aki.hex() if aki else "")


def crl_aki_matches(crl: x509.CertificateRevocationList, issuer: x509.Certificate) -> bool:
    """CRL 的 AKI 与签发者证书 SKI 一致则视为匹配；任一缺失则不据此排除。"""
    aki = authority_key_identifier(crl)
    if aki is None:
        return True
    ski = subject_key_identifier(issuer)
    if ski is None:
        return True
    return aki == ski


def verify_crl_issued_by(
    crl: x509.CertificateRevocationList, issuer: x509.Certificate
) -> bool:
    """验证 CRL 由 issuer 签署：issuer DN 相等、AKI 匹配、签名有效。"""
    if crl.issuer != issuer.subject:
        return False
    if not crl_aki_matches(crl, issuer):
        return False
    try:
        return crl.is_signature_valid(issuer.public_key())
    except Exception:
        return False


def crl_number(crl: x509.CertificateRevocationList) -> int | None:
    try:
        ext = crl.extensions.get_extension_for_class(x509.CRLNumber).value
    except x509.ExtensionNotFound:
        return None
    return ext.crl_number


def revoked_reason(rc: x509.RevokedCertificate) -> str:
    try:
        reason = rc.extensions.get_extension_for_class(x509.CRLReason).value.reason
        return reason.name
    except x509.ExtensionNotFound:
        return "unspecified"
