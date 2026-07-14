from pathlib import Path
from typing import final

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from src.configs.pki_config import (
    CertificateAuthorityConfig,
    EntityName,
    PkiConfig,
)
from src.tasks.pki.schemas import AuthorityMaterial, PkiManifest


@final
class PkiLoadService:
    def __init__(self, config: PkiConfig) -> None:
        self._config: PkiConfig = config

    def load_manifest(self, output_directory: Path) -> PkiManifest:
        path = output_directory / "manifest.json"
        return PkiManifest.model_validate_json(path.read_text(encoding="utf-8"))

    def load_authorities(
        self, output_directory: Path
    ) -> dict[EntityName, AuthorityMaterial]:
        authority_by_name: dict[EntityName, CertificateAuthorityConfig] = {
            authority.name: authority for authority in self._config.authorities
        }
        loaded: dict[EntityName, AuthorityMaterial] = {}
        for authority in self._config.authorities:
            _ = self._load_authority(
                authority, authority_by_name, loaded, output_directory
            )
        return loaded

    def load_private_key(self, path: Path) -> rsa.RSAPrivateKey:
        private_key = serialization.load_pem_private_key(
            path.read_bytes(), password=None
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError(f"Expected RSA private key: {path}")
        return private_key

    def load_certificate(self, path: Path) -> x509.Certificate:
        return x509.load_pem_x509_certificate(path.read_bytes())

    def load_certificate_chain(self, path: Path) -> tuple[x509.Certificate, ...]:
        return tuple(x509.load_pem_x509_certificates(path.read_bytes()))

    def load_password_values(self, output_directory: Path) -> dict[str, bytes]:
        path = output_directory / "passwords.env"
        values: dict[str, bytes] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if not separator or not key or not value or key in values:
                raise ValueError(f"Invalid PKCS#12 password file: {path}")
            values[key] = value.encode()
        return values

    def _load_authority(
        self,
        config: CertificateAuthorityConfig,
        authority_by_name: dict[EntityName, CertificateAuthorityConfig],
        loaded: dict[EntityName, AuthorityMaterial],
        output_directory: Path,
    ) -> AuthorityMaterial:
        existing = loaded.get(config.name)
        if existing is not None:
            return existing

        issuer: AuthorityMaterial | None = (
            None
            if config.issuer is None
            else self._load_authority(
                authority_by_name[config.issuer],
                authority_by_name,
                loaded,
                output_directory,
            )
        )

        directory: Path = output_directory / "authorities" / config.name
        private_key: rsa.RSAPrivateKey = self.load_private_key(directory / "key.pem")
        certificate: x509.Certificate = self.load_certificate(directory / "cert.pem")

        parent_chain = (
            () if issuer is None else (issuer.certificate, *issuer.parent_chain)
        )
        material = AuthorityMaterial(
            config=config,
            private_key=private_key,
            certificate=certificate,
            parent_chain=parent_chain,
        )
        loaded[config.name] = material
        return material
