import hashlib
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from src.configs.pki_config import (
    ExtendedKeyUsage,
    PkiConfig,
    SubjectAlternativeNamesConfig,
    SubjectConfig,
)
from src.tasks.pki.schemas import AuthorityMaterial, ManifestCertificate


def build_subject(config: SubjectConfig) -> x509.Name:
    attributes: list[x509.NameAttribute[str]] = []
    if config.country is not None:
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, config.country))
    if config.state is not None:
        attributes.append(
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config.state)
        )
    if config.locality is not None:
        attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, config.locality))
    attributes.append(
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.organization)
    )
    if config.organizational_unit is not None:
        attributes.append(
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, config.organizational_unit
            )
        )
    attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, config.common_name))
    return x509.Name(attributes)


def build_alternative_names(
    config: SubjectAlternativeNamesConfig,
) -> list[x509.GeneralName]:
    names: list[x509.GeneralName] = [x509.DNSName(name) for name in config.dns]
    names.extend(x509.IPAddress(address) for address in config.ip)
    names.extend(x509.UniformResourceIdentifier(str(uri)) for uri in config.uri)
    return names


def extended_key_usage_oid(usage: ExtendedKeyUsage) -> x509.ObjectIdentifier:
    match usage:
        case ExtendedKeyUsage.SERVER_AUTH:
            return ExtendedKeyUsageOID.SERVER_AUTH
        case ExtendedKeyUsage.CLIENT_AUTH:
            return ExtendedKeyUsageOID.CLIENT_AUTH


def authority_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def certificate_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def signing_chain(issuer: AuthorityMaterial) -> tuple[x509.Certificate, ...]:
    non_root_parents = tuple(
        certificate
        for certificate in issuer.parent_chain
        if certificate.subject != certificate.issuer
    )
    return (issuer.certificate, *non_root_parents)


def config_hash(config: PkiConfig) -> str:
    return hashlib.sha256(config.model_dump_json().encode()).hexdigest()


def manifest_entry(
    certificate: x509.Certificate,
    name: str,
    kind: Literal["authority", "certificate"],
) -> ManifestCertificate:
    return ManifestCertificate(
        name=name,
        kind=kind,
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        expires_at=certificate.not_valid_after_utc,
    )
