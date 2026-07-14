import stat
import tempfile
import unittest
from pathlib import Path
from typing import cast, final, override

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID
from pydantic import ValidationError
from src.configs.pki_config import (
    CertificateAuthorityConfig,
    CertificateConfig,
    ExtendedKeyUsage,
    PkiConfig,
    SubjectAlternativeNamesConfig,
    SubjectConfig,
)
from src.tasks.pki.services.pki_service import PkiService


def _subject(common_name: str) -> SubjectConfig:
    return SubjectConfig(
        common_name=common_name,
        organization="Deadlines",
        organizational_unit=None,
        country=None,
        state=None,
        locality=None,
    )


def _authority(
    name: str, issuer: str | None, validity_days: int, path_length: int
) -> CertificateAuthorityConfig:
    return CertificateAuthorityConfig(
        name=name,
        issuer=issuer,
        subject=_subject(name),
        key_bits=2048,
        validity_days=validity_days,
        path_length=path_length,
    )


def _certificate(
    name: str,
    issuer: str,
    usages: list[ExtendedKeyUsage],
    dns_names: list[str],
    pkcs12: bool,
) -> CertificateConfig:
    return CertificateConfig(
        name=name,
        issuer=issuer,
        subject=_subject(name),
        alternative_names=SubjectAlternativeNamesConfig(dns=dns_names, ip=[], uri=[]),
        extended_key_usages=usages,
        key_bits=2048,
        validity_days=90,
        pkcs12=pkcs12,
    )


def _config() -> PkiConfig:
    return PkiConfig(
        output_directory=Path("pki"),
        backdate_minutes=5,
        renew_before_days=10,
        authorities=[
            _authority("root", None, 365, 1),
            _authority("kafka-ca", "root", 180, 0),
            _authority("grpc-ca", "root", 180, 0),
        ],
        certificates=[
            _certificate(
                "kafka-broker",
                "kafka-ca",
                [ExtendedKeyUsage.SERVER_AUTH, ExtendedKeyUsage.CLIENT_AUTH],
                ["kafka", "localhost"],
                True,
            ),
            _certificate(
                "api-grpc",
                "grpc-ca",
                [ExtendedKeyUsage.SERVER_AUTH],
                ["api"],
                False,
            ),
        ],
    )


@final
class PkiConfigTest(unittest.TestCase):
    def test_rejects_unknown_issuer(self) -> None:
        with self.assertRaisesRegex(ValidationError, "Unknown issuer"):
            _ = PkiConfig(
                output_directory=Path("pki"),
                backdate_minutes=5,
                renew_before_days=10,
                authorities=[_authority("root", None, 365, 1)],
                certificates=[
                    _certificate(
                        "api-grpc",
                        "missing-ca",
                        [ExtendedKeyUsage.SERVER_AUTH],
                        ["api"],
                        False,
                    )
                ],
            )

    def test_rejects_authority_cycle(self) -> None:
        with self.assertRaisesRegex(ValidationError, "cycle"):
            _ = PkiConfig(
                output_directory=Path("pki"),
                backdate_minutes=5,
                renew_before_days=10,
                authorities=[
                    _authority("root", None, 365, 2),
                    _authority("first-ca", "second-ca", 180, 0),
                    _authority("second-ca", "first-ca", 180, 0),
                ],
                certificates=[
                    _certificate(
                        "api-grpc",
                        "root",
                        [ExtendedKeyUsage.SERVER_AUTH],
                        ["api"],
                        False,
                    )
                ],
            )

    def test_rejects_unsafe_output_directory(self) -> None:
        config = _config()
        with self.assertRaisesRegex(ValidationError, "safe relative path"):
            _ = PkiConfig(
                output_directory=Path("../pki"),
                backdate_minutes=config.backdate_minutes,
                renew_before_days=config.renew_before_days,
                authorities=config.authorities,
                certificates=config.certificates,
            )

    def test_rejects_renewal_window_longer_than_certificate_validity(self) -> None:
        config = _config()
        with self.assertRaisesRegex(ValidationError, "renew_before_days"):
            _ = PkiConfig(
                output_directory=config.output_directory,
                backdate_minutes=config.backdate_minutes,
                renew_before_days=90,
                authorities=config.authorities,
                certificates=config.certificates,
            )


@final
class PkiServiceTest(unittest.TestCase):
    _temporary_directory = cast(tempfile.TemporaryDirectory[str], object())
    _generated_directory = cast(Path, object())
    _service = cast(PkiService, object())

    @override
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self._generated_directory = Path(self._temporary_directory.name)
        self._service = PkiService(_config(), self._generated_directory)

    @override
    def tearDown(self) -> None:
        self._temporary_directory.cleanup()

    def test_generates_and_preserves_valid_material(self) -> None:
        self.assertEqual(self._service.initialize(), "generated")
        certificate_path = (
            self._service.output_directory / "entities" / "kafka-broker" / "cert.pem"
        )
        fingerprint = x509.load_pem_x509_certificate(
            certificate_path.read_bytes()
        ).fingerprint(hashes.SHA256())

        self.assertEqual(self._service.initialize(), "validated")
        preserved_fingerprint = x509.load_pem_x509_certificate(
            certificate_path.read_bytes()
        ).fingerprint(hashes.SHA256())

        self.assertEqual(preserved_fingerprint, fingerprint)

    def test_generates_expected_sans_usages_and_protocol_chains(self) -> None:
        _ = self._service.initialize()
        output = self._service.output_directory
        kafka_certificate = x509.load_pem_x509_certificate(
            (output / "entities" / "kafka-broker" / "cert.pem").read_bytes()
        )
        grpc_certificate = x509.load_pem_x509_certificate(
            (output / "entities" / "api-grpc" / "cert.pem").read_bytes()
        )
        kafka_ca = x509.load_pem_x509_certificate(
            (output / "authorities" / "kafka-ca" / "cert.pem").read_bytes()
        )
        grpc_ca = x509.load_pem_x509_certificate(
            (output / "authorities" / "grpc-ca" / "cert.pem").read_bytes()
        )

        dns_names = kafka_certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        usages = set(
            kafka_certificate.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
        )

        self.assertEqual(set(dns_names), {"kafka", "localhost"})
        self.assertEqual(
            usages,
            {ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH},
        )
        kafka_certificate.verify_directly_issued_by(kafka_ca)
        grpc_certificate.verify_directly_issued_by(grpc_ca)
        with self.assertRaises(ValueError):
            grpc_certificate.verify_directly_issued_by(kafka_ca)

    def test_generates_pkcs12_and_secure_private_files(self) -> None:
        _ = self._service.initialize()
        output = self._service.output_directory
        entity_directory = output / "entities" / "kafka-broker"

        self.assertTrue((entity_directory / "keystore.p12").is_file())
        self.assertTrue((entity_directory / "truststore.p12").is_file())
        self.assertEqual(
            stat.S_IMODE((entity_directory / "key.pem").stat().st_mode), 0o600
        )
        self.assertEqual(stat.S_IMODE((output / "passwords.env").stat().st_mode), 0o600)
        passwords = (output / "passwords.env").read_text(encoding="utf-8")
        self.assertIn("KAFKA_BROKER_KEY_PASSWORD=", passwords)
        self._service.validate()

    def test_rejects_configuration_drift_without_replacing_material(self) -> None:
        _ = self._service.initialize()
        changed_config = _config().model_copy(update={"renew_before_days": 11})
        changed_service = PkiService(changed_config, self._generated_directory)

        with self.assertRaisesRegex(ValueError, "configuration changed"):
            _ = changed_service.initialize()


if __name__ == "__main__":
    _ = unittest.main()
