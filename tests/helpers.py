"""测试辅助：离线生成 CA / 中间证书 / 叶子证书。"""
from __future__ import annotations

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

UTC = timezone.utc

def t(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=UTC)


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=None,
        decipher_only=None,
    )


def make_ca(cn="Test Root CA", nb="2025-01-01", na="2035-01-01", path_length=None):
    key = _key()
    name = _name(cn)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(t(nb))
        .not_valid_after(t(na))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def make_cert(
    issuer_cert,
    issuer_key,
    cn,
    nb="2026-01-01",
    na="2027-01-01",
    sans=None,
    is_ca=False,
    path_length=None,
):
    key = _key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(t(nb))
        .not_valid_after(t(na))
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=path_length if is_ca else None),
            critical=True,
        )
    )
    if is_ca:
        builder = builder.add_extension(_ca_key_usage(), critical=True)
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256()), key


def pem(*certs) -> str:
    return "".join(
        c.public_bytes(serialization.Encoding.PEM).decode("ascii") for c in certs
    )


def fingerprint(pem_str: str) -> str:
    import hashlib
    import re

    block = re.search(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem_str, re.S
    ).group(0)
    cert = x509.load_pem_x509_certificate(block.encode())
    return cert.fingerprint(hashes.SHA256()).hex()


# ---------------------------------------------------------------------------
# CRL 构造辅助
# ---------------------------------------------------------------------------

def make_crl(
    issuer_cert,
    issuer_key,
    last_update,
    next_update,
    revoked=None,
    number=None,
    add_aki=True,
):
    """构造一张（可选含撤销条目/AKI/CRLNumber 的）DER→PEM CRL。

    revoked: [(serial:int, revocation_date:str, reason|None), ...]
    日期字符串按 UTC 解析（"2026-06-01" 或完整 ISO）。
    """
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(t(last_update))
        .next_update(t(next_update))
    )
    for serial, rev_date, reason in revoked or []:
        rc = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(t(rev_date))
        )
        if reason is not None:
            rc = rc.add_extension(x509.CRLReason(reason), critical=False)
        builder = builder.add_revoked_certificate(rc.build())
    if number is not None:
        builder = builder.add_extension(x509.CRLNumber(number), critical=False)
    if add_aki:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256()).public_bytes(
        serialization.Encoding.PEM
    ).decode("ascii")


def cert_serial(cert_pem: str) -> int:
    import re

    block = re.search(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", cert_pem, re.S
    ).group(0)
    return x509.load_pem_x509_certificate(block.encode()).serial_number


# ---------------------------------------------------------------------------
# 畸形 CRL 的 DER 手术（标准 builder 会拒绝生成这些非法结构）
# ---------------------------------------------------------------------------

def _der_tlv(data: bytes, offset: int) -> tuple[int, bytes, bytes, int]:
    """解析一个 DER TLV，返回 (标签, 内容, 完整 TLV, 下一偏移)。"""
    tag = data[offset]
    length = data[offset + 1]
    idx = offset + 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[idx : idx + n], "big")
        idx += n
    value = data[idx : idx + length]
    return tag, value, data[offset : idx + length], idx + length


def _der_children(content: bytes) -> list[bytes]:
    out, off = [], 0
    while off < len(content):
        _, _, tlv, off = _der_tlv(content, off)
        out.append(tlv)
    return out


def _is_time_tlv(tlv: bytes) -> bool:
    return tlv[0] in (0x17, 0x18)  # UTCTime / GeneralizedTime


def _tamper_tbs(tbs_content: bytes, mode: str) -> bytes:
    children = _der_children(tbs_content)
    time_idx = [i for i, c in enumerate(children) if _is_time_tlv(c)]
    if mode == "drop_next_update":
        # 约定第二个时间字段为可选的 nextUpdate
        del children[time_idx[1]]
    elif mode == "swap_times":
        i, j = time_idx[0], time_idx[1]
        children[i], children[j] = children[j], children[i]
    else:  # pragma: no cover
        raise ValueError(mode)
    return b"".join(children)


def tamper_crl_pem(crl_pem: str, mode: str) -> str:
    """对 CRL 做底层 DER 手术：'drop_next_update' / 'swap_times'。

    改后签名必然失效；仅用于断言服务在签名校验之前即拒绝内容非法的 CRL。
    """
    import base64
    import re

    b64 = "".join(
        re.findall(
            r"-----BEGIN X509 CRL-----(.*?)-----END X509 CRL-----", crl_pem, re.S
        )[0].split()
    )
    der = base64.b64decode(b64)
    _, crl_content, _, _ = _der_tlv(der, 0)
    crl_children = _der_children(crl_content)
    _, tbs_content, _, _ = _der_tlv(crl_children[0], 0)
    new_tbs_value = _tamper_tbs(tbs_content, mode)
    # 用新内容重建 TBSCertList（SEQUENCE, 0x30），外层其余部分原样保留
    def enc_len(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        body = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(body)]) + body

    new_tbs = b"\x30" + enc_len(len(new_tbs_value)) + new_tbs_value
    rebuilt = b"\x30" + enc_len(len(new_tbs) + sum(map(len, crl_children[1:])))
    rebuilt += new_tbs + b"".join(crl_children[1:])
    body = base64.encodebytes(rebuilt).decode("ascii")
    return "-----BEGIN X509 CRL-----\n" + body + "-----END X509 CRL-----\n"
