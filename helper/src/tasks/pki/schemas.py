from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar, Literal

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import BaseModel, ConfigDict

from src.configs.pki_config import CertificateAuthorityConfig


class ManifestCertificate(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")

    name: str
    kind: Literal["authority", "certificate"]
    fingerprint_sha256: str
    expires_at: datetime


class PkiManifest(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")

    version: Literal[1]
    config_sha256: str
    certificates: list[ManifestCertificate]


@dataclass(frozen=True)
class AuthorityMaterial:
    config: CertificateAuthorityConfig
    private_key: rsa.RSAPrivateKey
    certificate: x509.Certificate
    parent_chain: tuple[x509.Certificate, ...]


@dataclass(frozen=True)
class Pkcs12Passwords:
    keystore: bytes
    truststore: bytes
