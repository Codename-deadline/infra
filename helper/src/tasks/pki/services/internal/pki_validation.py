import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, final

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from src.configs.pki_config import CertificateConfig, EntityName, PkiConfig
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
    signing_chain,
)
from src.tasks.pki.services.internal.pki_load import PkiLoadService


@final
class PkiValidationService:
    def __init__(self, config: PkiConfig, loader: PkiLoadService) -> None:
        self._config: PkiConfig = config
        self._loader: PkiLoadService = loader

    def validate(self, output_directory: Path) -> None:
        """Check the artifact layout, config hash, manifest, CAs, and leaf certs."""

        self._validate_layout(output_directory)

        manifest: PkiManifest = self._loader.load_manifest(output_directory)
        if manifest.config_sha256 != config_hash(self._config):
            message = "PKI configuration changed; existing material was not replaced."
            message += " Rotate the affected certificates explicitly."
            raise ValueError(message)

        authorities: dict[EntityName, AuthorityMaterial] = (
            self._loader.load_authorities(output_directory)
        )
        manifest_by_name: dict[str, ManifestCertificate] = {
            certificate.name: certificate for certificate in manifest.certificates
        }
        expected_names = {authority.name for authority in self._config.authorities}
        expected_names.update(
            certificate.name for certificate in self._config.certificates
        )
        if set(manifest_by_name) != expected_names:
            raise ValueError("PKI manifest does not match configured certificates")

        for authority in authorities.values():
            self._validate_authority(authority, authorities, output_directory)
            self._validate_manifest_entry(
                authority.certificate,
                manifest_by_name[authority.config.name],
                "authority",
            )

        passwords = self._validated_pkcs12_passwords(output_directory)
        for certificate_config in self._config.certificates:
            certificate = self._validate_certificate(
                certificate_config,
                authorities[certificate_config.issuer],
                output_directory,
                passwords.get(certificate_config.name),
            )
            self._validate_manifest_entry(
                certificate,
                manifest_by_name[certificate_config.name],
                "certificate",
            )

    def _validate_layout(self, output_directory: Path) -> None:
        """Check every configured artifact exists, is not a symlink, and has its mode."""

        self._validate_directory(output_directory, ENTITY_DIRECTORY_MODE)
        self._validate_directory(
            output_directory / "authorities", PRIVATE_DIRECTORY_MODE
        )
        self._validate_directory(output_directory / "entities", ENTITY_DIRECTORY_MODE)

        self._validate_file(output_directory / "manifest.json", PUBLIC_FILE_MODE)
        self._validate_file(output_directory / "passwords.env", PRIVATE_FILE_MODE)

        for authority in self._config.authorities:
            directory = output_directory / "authorities" / authority.name
            self._validate_directory(directory, PRIVATE_DIRECTORY_MODE)
            self._validate_file(directory / "key.pem", PRIVATE_FILE_MODE)
            self._validate_file(directory / "cert.pem", PUBLIC_FILE_MODE)
            self._validate_file(directory / "chain.pem", PUBLIC_FILE_MODE)

        for certificate in self._config.certificates:
            directory = output_directory / "entities" / certificate.name
            self._validate_directory(directory, ENTITY_DIRECTORY_MODE)
            self._validate_file(directory / "key.pem", PRIVATE_FILE_MODE)
            self._validate_file(directory / "cert.pem", PUBLIC_FILE_MODE)
            self._validate_file(directory / "chain.pem", PUBLIC_FILE_MODE)
            self._validate_file(directory / "ca.pem", PUBLIC_FILE_MODE)
            if certificate.pkcs12:
                self._validate_file(directory / "keystore.p12", ENCRYPTED_STORE_MODE)
                self._validate_file(directory / "truststore.p12", ENCRYPTED_STORE_MODE)

    def _validate_authority(
        self,
        authority: AuthorityMaterial,
        authorities: dict[EntityName, AuthorityMaterial],
        output_directory: Path,
    ) -> None:
        """
        Check a CA's key, configured fields, extensions, signature, and chain.

        The private key must produce the certificate's public key. The certificate
        must have the configured subject and size, CA constraints and usages, and
        a signature from its configured issuer (or itself for the root).
        """

        config = authority.config
        self._validate_key_pair(
            authority.private_key, authority.certificate, config.name
        )
        self._validate_common_certificate(
            authority.certificate,
            build_subject(config.subject),
            config.key_bits,
            config.name,
        )
        constraints = authority.certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        if not constraints.ca or constraints.path_length != config.path_length:
            raise ValueError(f"Invalid basic constraints for authority {config.name}")
        key_usage = authority.certificate.extensions.get_extension_for_class(
            x509.KeyUsage
        ).value
        if key_usage != authority_key_usage():
            raise ValueError(f"Invalid key usage for authority {config.name}")

        issuer = authority if config.issuer is None else authorities[config.issuer]
        authority.certificate.verify_directly_issued_by(issuer.certificate)
        self._validate_key_identifiers(
            authority.certificate, issuer.certificate, config.name
        )
        directory = output_directory / "authorities" / config.name
        self._validate_chain(
            directory / "chain.pem",
            (authority.certificate, *authority.parent_chain),
        )

    def _validate_certificate(
        self,
        config: CertificateConfig,
        issuer: AuthorityMaterial,
        output_directory: Path,
        passwords: Pkcs12Passwords | None,
    ) -> x509.Certificate:
        """
        Check a leaf's key match, configured fields, issuer, chain, and stores.

        The certificate must be a non-CA certificate with the exact configured
        subject, key size, SANs, and EKUs, and its signature must verify against
        the selected issuer.
        """

        directory = output_directory / "entities" / config.name
        private_key = self._loader.load_private_key(directory / "key.pem")
        certificate = self._loader.load_certificate(directory / "cert.pem")
        self._validate_key_pair(private_key, certificate, config.name)
        self._validate_common_certificate(
            certificate, build_subject(config.subject), config.key_bits, config.name
        )
        certificate.verify_directly_issued_by(issuer.certificate)

        constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        if constraints.ca or constraints.path_length is not None:
            raise ValueError(f"Invalid basic constraints for certificate {config.name}")
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        if key_usage != certificate_key_usage():
            raise ValueError(f"Invalid key usage for certificate {config.name}")
        self._validate_key_identifiers(certificate, issuer.certificate, config.name)

        actual_usages = set(
            certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        )
        expected_usages = {
            extended_key_usage_oid(usage) for usage in config.extended_key_usages
        }
        if actual_usages != expected_usages:
            raise ValueError(
                f"Invalid extended key usages for certificate {config.name}"
            )
        if self._certificate_alternative_names(certificate) != set(
            build_alternative_names(config.alternative_names)
        ):
            raise ValueError(
                f"Invalid subject alternative names for certificate {config.name}"
            )

        certificate_chain = signing_chain(issuer)
        self._validate_chain(directory / "chain.pem", (certificate, *certificate_chain))
        ca_certificate = self._loader.load_certificate(directory / "ca.pem")
        if ca_certificate.fingerprint(
            hashes.SHA256()
        ) != issuer.certificate.fingerprint(hashes.SHA256()):
            raise ValueError(f"Invalid CA certificate for {config.name}")

        if config.pkcs12:
            if passwords is None:
                raise ValueError(f"Missing PKCS#12 passwords for {config.name}")
            self._validate_pkcs12(directory, certificate, issuer, passwords)
        elif passwords is not None:
            raise ValueError(f"Unexpected PKCS#12 passwords for {config.name}")
        return certificate

    def _validate_pkcs12(
        self,
        directory: Path,
        certificate: x509.Certificate,
        issuer: AuthorityMaterial,
        passwords: Pkcs12Passwords,
    ) -> None:
        """
        Decrypt the stores and inspect their certificate entries.

        The keystore must contain a key and the expected leaf certificate. The
        truststore must contain exactly the configured issuer certificate.
        """

        keystore_path = directory / "keystore.p12"
        truststore_path = directory / "truststore.p12"
        keystore = pkcs12.load_pkcs12(keystore_path.read_bytes(), passwords.keystore)
        if keystore.key is None or keystore.cert is None:
            raise ValueError(f"Invalid PKCS#12 keystore: {keystore_path}")
        if keystore.cert.certificate.fingerprint(
            hashes.SHA256()
        ) != certificate.fingerprint(hashes.SHA256()):
            raise ValueError(f"PKCS#12 keystore certificate mismatch: {keystore_path}")

        truststore = pkcs12.load_pkcs12(
            truststore_path.read_bytes(), passwords.truststore
        )
        trusted_fingerprints = {
            item.certificate.fingerprint(hashes.SHA256())
            for item in truststore.additional_certs
        }
        if trusted_fingerprints != {issuer.certificate.fingerprint(hashes.SHA256())}:
            raise ValueError(f"PKCS#12 truststore mismatch: {truststore_path}")

    def _validated_pkcs12_passwords(
        self, output_directory: Path
    ) -> dict[EntityName, Pkcs12Passwords]:
        """
        Require three password entries per store and reject missing or extra keys.

        The key password must equal the keystore password because the generated
        PKCS#12 keystore uses one password for both.
        """

        values = self._loader.load_password_values(output_directory)
        result: dict[EntityName, Pkcs12Passwords] = {}
        expected_keys: set[str] = set()
        for certificate in self._config.certificates:
            if not certificate.pkcs12:
                continue
            prefix = certificate.name.upper().replace("-", "_")
            keystore_key = f"{prefix}_KEYSTORE_PASSWORD"
            key_key = f"{prefix}_KEY_PASSWORD"
            truststore_key = f"{prefix}_TRUSTSTORE_PASSWORD"
            expected_keys.update((keystore_key, key_key, truststore_key))
            try:
                if values[key_key] != values[keystore_key]:
                    message = "PKCS#12 key password must match the keystore password"
                    raise ValueError(f"{message} for {certificate.name}")
                result[certificate.name] = Pkcs12Passwords(
                    keystore=values[keystore_key], truststore=values[truststore_key]
                )
            except KeyError as error:
                raise ValueError(
                    f"Missing PKCS#12 password for {certificate.name}"
                ) from error
        if set(values) != expected_keys:
            path = output_directory / "passwords.env"
            raise ValueError(f"Unexpected entries in PKCS#12 password file: {path}")
        return result

    def _validate_common_certificate(
        self,
        certificate: x509.Certificate,
        expected_subject: x509.Name,
        expected_key_bits: int,
        name: str,
    ) -> None:
        """Compare subject and RSA size, then reject future or near-expiry certs."""

        if certificate.subject != expected_subject:
            raise ValueError(f"Certificate subject does not match config: {name}")
        public_key = certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError(f"Certificate does not contain an RSA key: {name}")
        if public_key.key_size != expected_key_bits:
            raise ValueError(f"Certificate key size does not match config: {name}")
        now: datetime = datetime.now(UTC)
        if certificate.not_valid_before_utc > now:
            raise ValueError(f"Certificate is not valid yet: {name}")
        renewal_time: datetime = now + timedelta(days=self._config.renew_before_days)
        if certificate.not_valid_after_utc <= renewal_time:
            raise ValueError(f"Certificate requires renewal: {name}")

    @staticmethod
    def _validate_key_identifiers(
        certificate: x509.Certificate,
        issuer: x509.Certificate,
        name: str,
    ) -> None:
        """Recompute SKI from the leaf key and AKI from the issuer key and compare."""

        subject_key_identifier = certificate.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value
        expected_subject_key_identifier = x509.SubjectKeyIdentifier.from_public_key(
            certificate.public_key()
        )
        if subject_key_identifier != expected_subject_key_identifier:
            raise ValueError(f"Invalid subject key identifier: {name}")

        authority_key_identifier = certificate.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value
        issuer_key_identifier = x509.SubjectKeyIdentifier.from_public_key(
            issuer.public_key()
        )
        if authority_key_identifier.key_identifier != issuer_key_identifier.digest:
            raise ValueError(f"Invalid authority key identifier: {name}")

    @staticmethod
    def _validate_key_pair(
        private_key: rsa.RSAPrivateKey,
        certificate: x509.Certificate,
        name: str,
    ) -> None:
        """Derive both public keys, encode them as DER, and compare their bytes."""

        private_public_key = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        certificate_public_key = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if private_public_key != certificate_public_key:
            raise ValueError(f"Private key does not match certificate: {name}")

    @staticmethod
    def _validate_manifest_entry(
        certificate: x509.Certificate,
        entry: ManifestCertificate,
        expected_kind: Literal["authority", "certificate"],
    ) -> None:
        """Compare manifest kind, SHA-256 fingerprint, and expiry with the cert."""

        if entry.kind != expected_kind:
            raise ValueError(f"Invalid manifest kind for {entry.name}")
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        if entry.fingerprint_sha256 != fingerprint:
            raise ValueError(f"Invalid manifest fingerprint for {entry.name}")
        if entry.expires_at != certificate.not_valid_after_utc:
            raise ValueError(f"Invalid manifest expiry for {entry.name}")

    def _validate_chain(
        self, path: Path, expected: tuple[x509.Certificate, ...]
    ) -> None:
        """Compare the PEM chain's ordered SHA-256 fingerprints with expectations."""

        certificates = self._loader.load_certificate_chain(path)
        actual_fingerprints = [
            certificate.fingerprint(hashes.SHA256()) for certificate in certificates
        ]
        expected_fingerprints = [
            certificate.fingerprint(hashes.SHA256()) for certificate in expected
        ]
        if actual_fingerprints != expected_fingerprints:
            raise ValueError(f"Certificate chain is invalid: {path}")

    @staticmethod
    def _certificate_alternative_names(
        certificate: x509.Certificate,
    ) -> set[x509.GeneralName]:
        """Read all SAN values, returning an empty set when the extension is absent."""

        try:
            extension = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
        except x509.ExtensionNotFound:
            return set()
        return set(extension.value)

    @staticmethod
    def _validate_directory(path: Path, expected_mode: int) -> None:
        """Reject symlinks and non-directories, then require the supplied mode."""

        if path.is_symlink() or not path.is_dir():
            raise ValueError(f"Expected safe PKI directory: {path}")
        if stat.S_IMODE(path.stat().st_mode) != expected_mode:
            raise ValueError(f"Invalid PKI directory permissions: {path}")

    @staticmethod
    def _validate_file(path: Path, expected_mode: int) -> None:
        """Reject symlinks and non-files, then require the supplied permission mode."""

        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Expected safe PKI file: {path}")
        if stat.S_IMODE(path.stat().st_mode) != expected_mode:
            raise ValueError(f"Invalid PKI file permissions: {path}")
