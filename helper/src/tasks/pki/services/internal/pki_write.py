import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import final

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from src.configs.pki_config import (
    CertificateAuthorityConfig,
    CertificateConfig,
    EntityName,
    PkiConfig,
)
from src.tasks.pki.constants import (
    ENCRYPTED_STORE_MODE,
    ENTITY_DIRECTORY_MODE,
    PRIVATE_DIRECTORY_MODE,
    PRIVATE_FILE_MODE,
    PUBLIC_FILE_MODE,
)
from src.tasks.pki.schemas import (
    AuthorityMaterial,
    ManifestCertificate,
    Pkcs12Passwords,
    PkiManifest,
)
from src.tasks.pki.services.internal.pki_helpers import (
    authority_key_usage,
    build_alternative_names,
    build_subject,
    certificate_key_usage,
    config_hash,
    extended_key_usage_oid,
    manifest_entry,
    signing_chain,
)


@final
class PkiWriteService:
    def __init__(self, config: PkiConfig) -> None:
        self._config: PkiConfig = config

    def write(self, output_directory: Path) -> None:
        self._create_directory(output_directory, ENTITY_DIRECTORY_MODE)
        authorities_directory = output_directory / "authorities"
        entities_directory = output_directory / "entities"
        self._create_directory(authorities_directory, PRIVATE_DIRECTORY_MODE)
        self._create_directory(entities_directory, ENTITY_DIRECTORY_MODE)

        generation_time = datetime.now(UTC)
        authority_by_name: dict[EntityName, CertificateAuthorityConfig] = {
            authority.name: authority for authority in self._config.authorities
        }
        generated_authorities: dict[EntityName, AuthorityMaterial] = {}
        manifest_certificates: list[ManifestCertificate] = []

        for authority in self._config.authorities:
            material = self._generate_authority(
                authority,
                authority_by_name,
                generated_authorities,
                authorities_directory,
                generation_time,
            )
            manifest_certificates.append(
                manifest_entry(material.certificate, authority.name, "authority")
            )

        generated_passwords: dict[EntityName, Pkcs12Passwords] = {}
        for certificate_config in self._config.certificates:
            certificate, passwords = self._generate_certificate(
                certificate_config,
                generated_authorities[certificate_config.issuer],
                entities_directory,
                generation_time,
            )
            manifest_certificates.append(
                manifest_entry(certificate, certificate_config.name, "certificate")
            )
            if passwords is not None:
                generated_passwords[certificate_config.name] = passwords

        self._write_pkcs12_passwords(output_directory, generated_passwords)
        manifest = PkiManifest(
            version=1,
            config_sha256=config_hash(self._config),
            certificates=manifest_certificates,
        )
        self._write_file(
            output_directory / "manifest.json",
            manifest.model_dump_json(indent=2).encode(),
            PUBLIC_FILE_MODE,
        )

    def _generate_authority(
        self,
        config: CertificateAuthorityConfig,
        authority_by_name: dict[EntityName, CertificateAuthorityConfig],
        generated: dict[EntityName, AuthorityMaterial],
        authorities_directory: Path,
        generation_time: datetime,
    ) -> AuthorityMaterial:
        existing = generated.get(config.name)
        if existing is not None:
            return existing

        issuer_material = (
            None
            if config.issuer is None
            else self._generate_authority(
                authority_by_name[config.issuer],
                authority_by_name,
                generated,
                authorities_directory,
                generation_time,
            )
        )
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=config.key_bits
        )
        subject = build_subject(config.subject)
        issuer_name: x509.Name = (
            subject if issuer_material is None else issuer_material.certificate.subject
        )
        issuer_key: rsa.RSAPrivateKey = (
            private_key if issuer_material is None else issuer_material.private_key
        )
        not_before: datetime = generation_time - timedelta(
            minutes=self._config.backdate_minutes
        )
        not_after: datetime = generation_time + timedelta(days=config.validity_days)
        certificate: x509.Certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_name)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=config.path_length),
                critical=True,
            )
            .add_extension(authority_key_usage(), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    issuer_key.public_key()
                ),
                critical=False,
            )
            .sign(private_key=issuer_key, algorithm=hashes.SHA256())
        )
        parent_chain = (
            ()
            if issuer_material is None
            else (issuer_material.certificate, *issuer_material.parent_chain)
        )
        material = AuthorityMaterial(
            config=config,
            private_key=private_key,
            certificate=certificate,
            parent_chain=parent_chain,
        )
        generated[config.name] = material

        directory = authorities_directory / config.name
        self._create_directory(directory, PRIVATE_DIRECTORY_MODE)
        self._write_private_key(directory / "key.pem", private_key)
        self._write_certificate(directory / "cert.pem", certificate)
        self._write_certificate_chain(
            directory / "chain.pem", (certificate, *parent_chain)
        )
        return material

    def _generate_certificate(
        self,
        config: CertificateConfig,
        issuer: AuthorityMaterial,
        entities_directory: Path,
        generation_time: datetime,
    ) -> tuple[x509.Certificate, Pkcs12Passwords | None]:
        private_key: rsa.RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537, key_size=config.key_bits
        )
        not_before: datetime = generation_time - timedelta(
            minutes=self._config.backdate_minutes
        )
        not_after: datetime = generation_time + timedelta(days=config.validity_days)
        builder = (
            x509.CertificateBuilder()
            .subject_name(build_subject(config.subject))
            .issuer_name(issuer.certificate.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(certificate_key_usage(), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        extended_key_usage_oid(usage)
                        for usage in config.extended_key_usages
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    issuer.private_key.public_key()
                ),
                critical=False,
            )
        )
        alternative_names: list[x509.GeneralName] = build_alternative_names(
            config.alternative_names
        )
        if alternative_names:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(alternative_names), critical=False
            )
        certificate = builder.sign(
            private_key=issuer.private_key, algorithm=hashes.SHA256()
        )

        directory = entities_directory / config.name
        self._create_directory(directory, ENTITY_DIRECTORY_MODE)
        self._write_private_key(directory / "key.pem", private_key)
        self._write_certificate(directory / "cert.pem", certificate)
        certificate_chain = signing_chain(issuer)
        self._write_certificate_chain(
            directory / "chain.pem", (certificate, *certificate_chain)
        )
        self._write_certificate(directory / "ca.pem", issuer.certificate)

        passwords = None
        if config.pkcs12:
            passwords = self._write_pkcs12_artifacts(
                directory, config.name, private_key, certificate, issuer
            )
        return certificate, passwords

    def _write_pkcs12_artifacts(
        self,
        directory: Path,
        name: str,
        private_key: rsa.RSAPrivateKey,
        certificate: x509.Certificate,
        issuer: AuthorityMaterial,
    ) -> Pkcs12Passwords:
        passwords = Pkcs12Passwords(
            keystore=secrets.token_urlsafe(32).encode(),
            truststore=secrets.token_urlsafe(32).encode(),
        )
        certificate_chain = signing_chain(issuer)
        keystore = pkcs12.serialize_key_and_certificates(
            name=name.encode(),
            key=private_key,
            cert=certificate,
            cas=[
                pkcs12.PKCS12Certificate(cert=ca, friendly_name=b"issuer")
                for ca in certificate_chain
            ],
            encryption_algorithm=serialization.BestAvailableEncryption(
                passwords.keystore
            ),
        )
        truststore = pkcs12.serialize_java_truststore(
            certs=[
                pkcs12.PKCS12Certificate(
                    cert=issuer.certificate,
                    friendly_name=issuer.config.name.encode(),
                )
            ],
            encryption_algorithm=serialization.BestAvailableEncryption(
                passwords.truststore
            ),
        )
        self._write_file(directory / "keystore.p12", keystore, ENCRYPTED_STORE_MODE)
        self._write_file(directory / "truststore.p12", truststore, ENCRYPTED_STORE_MODE)
        return passwords

    def normalize_runtime_permissions(self, output_directory: Path) -> None:
        """Make service-mounted entity directories and encrypted stores readable."""
        self._chmod_existing(output_directory, ENTITY_DIRECTORY_MODE)
        self._chmod_existing(output_directory / "entities", ENTITY_DIRECTORY_MODE)
        for certificate in self._config.certificates:
            directory = output_directory / "entities" / certificate.name
            self._chmod_existing(directory, ENTITY_DIRECTORY_MODE)
            if certificate.pkcs12:
                self._chmod_existing(directory / "keystore.p12", ENCRYPTED_STORE_MODE)
                self._chmod_existing(directory / "truststore.p12", ENCRYPTED_STORE_MODE)

    def _write_pkcs12_passwords(
        self,
        output_directory: Path,
        passwords_by_name: dict[EntityName, Pkcs12Passwords],
    ) -> None:
        lines: list[str] = []
        for name, passwords in sorted(passwords_by_name.items()):
            prefix = name.upper().replace("-", "_")
            lines.extend(
                (
                    f"{prefix}_KEYSTORE_PASSWORD={passwords.keystore.decode()}",
                    f"{prefix}_KEY_PASSWORD={passwords.keystore.decode()}",
                    f"{prefix}_TRUSTSTORE_PASSWORD={passwords.truststore.decode()}",
                )
            )
        self._write_file(
            output_directory / "passwords.env",
            ("\n".join(lines) + "\n").encode(),
            PRIVATE_FILE_MODE,
        )

    @staticmethod
    def _create_directory(path: Path, mode: int) -> None:
        path.mkdir(parents=True, exist_ok=False, mode=mode)
        path.chmod(mode)

    @staticmethod
    def _chmod_existing(path: Path, mode: int) -> None:
        if path.is_symlink():
            raise ValueError(f"Refusing to change permissions on PKI symlink: {path}")
        if path.exists():
            path.chmod(mode)

    @staticmethod
    def _write_private_key(path: Path, private_key: rsa.RSAPrivateKey) -> None:
        PkiWriteService._write_file(
            path,
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            PRIVATE_FILE_MODE,
        )

    @staticmethod
    def _write_certificate(path: Path, certificate: x509.Certificate) -> None:
        PkiWriteService._write_file(
            path,
            certificate.public_bytes(serialization.Encoding.PEM),
            PUBLIC_FILE_MODE,
        )

    @staticmethod
    def _write_certificate_chain(
        path: Path, certificates: tuple[x509.Certificate, ...]
    ) -> None:
        PkiWriteService._write_file(
            path,
            b"".join(
                certificate.public_bytes(serialization.Encoding.PEM)
                for certificate in certificates
            ),
            PUBLIC_FILE_MODE,
        )

    @staticmethod
    def _write_file(path: Path, content: bytes, mode: int) -> None:
        _ = path.write_bytes(content)
        path.chmod(mode)
