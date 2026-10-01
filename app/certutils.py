"""PEM 解析、签名链构建与 X.509 校验工具。"""
from __future__ import annotations

import re
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID


class PemParseError(Exception):
    """PEM 载荷无法解析为证书时抛出。"""


class ChainValidationError(Exception):
    """证书链未通过 X.509 校验时抛出。"""


_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)


def parse_pem_chain(pem: str) -> list[x509.Certificate]:
    """解析一段包含一个或多个 PEM 证书的文本。

    严格模式：PEM 块之外存在任何非空白内容即视为格式错误。
    返回顺序与文本中出现顺序一致（约定第一个为叶子证书）。
    """
    if not isinstance(pem, str) or not pem.strip():
        raise PemParseError("empty PEM payload")
    blocks = _PEM_BLOCK_RE.findall(pem)
    if not blocks:
        raise PemParseError("no PEM certificate block found")
    remainder = _PEM_BLOCK_RE.sub("", pem)
    if remainder.strip():
        raise PemParseError("unexpected data outside PEM certificate blocks")
    certs: list[x509.Certificate] = []
    for i, block in enumerate(blocks, start=1):
        try:
            certs.append(x509.load_pem_x509_certificate(block.encode("ascii")))
        except Exception as exc:  # cryptography 抛出的各类解析异常统一收敛
            raise PemParseError(f"certificate block #{i} is malformed: {exc}") from exc
    return certs


def to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def fingerprint_sha256(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def san_dns_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    return list(ext.value.get_values_for_type(x509.DNSName))


def san_matches(sans: list[str], domain: str) -> bool:
    """精确匹配或单标签通配符（*.example.com 匹配 foo.example.com）。"""
    d = domain.lower().rstrip(".")
    for pattern in sans:
        p = pattern.lower().rstrip(".")
        if p.startswith("*."):
            suffix = p[1:]  # ".example.com"
            head = d[: -len(suffix)] if d.endswith(suffix) else ""
            if head and "." not in head:
                return True
        elif p == d:
            return True
    return False


def _verify_issued_by(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    if child.issuer != issuer.subject:
        return False
    try:
        child.verify_directly_issued_by(issuer)
        return True
    except Exception:
        return False


def build_chain(
    leaf: x509.Certificate,
    intermediates: list[x509.Certificate],
    roots: list[x509.Certificate],
) -> list[x509.Certificate]:
    """从叶子证书出发构建到信任根的签名链并校验 CA 约束。

    返回 [leaf, intermediate..., root]。签名无法验证或找不到签发者时
    抛出 ChainValidationError。
    """
    chain = [leaf]
    seen = {fingerprint_sha256(leaf)}
    while True:
        current = chain[-1]
        issuer = next((r for r in roots if _verify_issued_by(current, r)), None)
        if issuer is not None:
            chain.append(issuer)
            break
        issuer = next(
            (
                c
                for c in intermediates
                if fingerprint_sha256(c) not in seen and _verify_issued_by(current, c)
            ),
            None,
        )
        if issuer is None:
            raise ChainValidationError(
                "signature chain incomplete: no trusted issuer found for "
                f"'{current.subject.rfc4514_string()}'"
            )
        chain.append(issuer)
        seen.add(fingerprint_sha256(issuer))
        if len(chain) > 16:
            raise ChainValidationError("signature chain too long (possible loop)")
    _validate_ca_constraints(chain)
    return chain


def _validate_ca_constraints(chain: list[x509.Certificate]) -> None:
    """校验链中每个签发者（chain[1:]）的 CA 约束。

    - 必须带 basicConstraints 且 CA=TRUE；
    - pathLength 限制其下游 CA 证书数量；
    - 若带 keyUsage，必须包含 keyCertSign。
    """
    for idx, ca in enumerate(chain[1:], start=1):
        subj = ca.subject.rfc4514_string()
        try:
            bc = ca.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        except x509.ExtensionNotFound:
            raise ChainValidationError(
                f"CA constraint violation: '{subj}' has no basicConstraints extension"
            ) from None
        if not bc.ca:
            raise ChainValidationError(
                f"CA constraint violation: '{subj}' basicConstraints CA=FALSE"
            )
        subordinate_cas = idx - 1  # 该签发者下游的 CA 证书数量（不含叶子）
        if bc.path_length is not None and subordinate_cas > bc.path_length:
            raise ChainValidationError(
                f"CA constraint violation: path length of '{subj}' "
                f"({bc.path_length}) exceeded by {subordinate_cas} subordinate CA(s)"
            )
        try:
            ku = ca.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        except x509.ExtensionNotFound:
            ku = None
        if ku is not None and not ku.key_cert_sign:
            raise ChainValidationError(
                f"CA constraint violation: '{subj}' keyUsage lacks keyCertSign"
            )


def chain_validity_interval(
    chain: list[x509.Certificate],
) -> tuple[datetime, datetime]:
    """整条链共同有效的时间区间 [not_before, not_after)。"""
    not_before = max(c.not_valid_before_utc for c in chain)
    not_after = min(c.not_valid_after_utc for c in chain)
    return not_before, not_after
