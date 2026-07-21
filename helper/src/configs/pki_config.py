from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Annotated, ClassVar, Literal, Self

from pydantic import (
    AnyUrl,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

EntityName = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9-]*$", min_length=1, max_length=63),
]
KeyBits = Literal[2048, 3072, 4096]


class StrictConfigModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")


class ExtendedKeyUsage(StrEnum):
    SERVER_AUTH = "server_auth"
    CLIENT_AUTH = "client_auth"


class SubjectConfig(StrictConfigModel):
    common_name: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    organization: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    organizational_unit: (
        Annotated[str, StringConstraints(min_length=1, max_length=64)] | None
    )
    country: Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$")] | None
    state: Annotated[str, StringConstraints(min_length=1, max_length=128)] | None
    locality: Annotated[str, StringConstraints(min_length=1, max_length=128)] | None


class SubjectAlternativeNamesConfig(StrictConfigModel):
    dns: list[Annotated[str, StringConstraints(min_length=1, max_length=253)]]
    ip: list[IPv4Address | IPv6Address]
    uri: list[AnyUrl]

    @field_validator("dns")
    @classmethod
    def validate_dns_names(cls, names: list[str]) -> list[str]:
        for name in names:
            candidate = name[2:] if name.startswith("*.") else name
            labels = candidate.removesuffix(".").split(".")
            if any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not label.replace("-", "").isalnum()
                or not label.isascii()
                for label in labels
            ):
                raise ValueError(f"Invalid DNS name: {name}")
        return names


class CertificateAuthorityConfig(StrictConfigModel):
    name: EntityName
    issuer: EntityName | None
    subject: SubjectConfig
    key_bits: KeyBits
    validity_days: Annotated[int, Field(gt=0)]
    path_length: Annotated[int, Field(ge=0)]


class CertificateConfig(StrictConfigModel):
    name: EntityName
    issuer: EntityName
    subject: SubjectConfig
    alternative_names: SubjectAlternativeNamesConfig
    extended_key_usages: Annotated[list[ExtendedKeyUsage], Field(min_length=1)]
    key_bits: KeyBits
    validity_days: Annotated[int, Field(gt=0)]
    pkcs12: bool

    @field_validator("extended_key_usages")
    @classmethod
    def validate_unique_extended_key_usages(
        cls, usages: list[ExtendedKeyUsage]
    ) -> list[ExtendedKeyUsage]:
        if len(usages) != len(set(usages)):
            raise ValueError("Extended key usages must be unique")
        return usages


class PkiConfig(StrictConfigModel):
    output_directory: Path
    backdate_minutes: Annotated[int, Field(ge=0)]
    renew_before_days: Annotated[int, Field(ge=0)]
    authorities: Annotated[list[CertificateAuthorityConfig], Field(min_length=1)]
    certificates: Annotated[list[CertificateConfig], Field(min_length=1)]

    @field_validator("output_directory")
    @classmethod
    def validate_output_directory(cls, path: Path) -> Path:
        if (
            path.is_absolute()
            or len(path.parts) != 1
            or ".." in path.parts
            or path == Path(".")
        ):
            raise ValueError("PKI output_directory must be a safe relative path")
        return path

    @model_validator(mode="after")
    def validate_hierarchy(self) -> Self:
        authority_by_name: dict[EntityName, CertificateAuthorityConfig] = {
            authority.name: authority for authority in self.authorities
        }
        if len(authority_by_name) != len(self.authorities):
            raise ValueError("Certificate authority names must be unique")

        certificate_names: list[EntityName] = [
            certificate.name for certificate in self.certificates
        ]
        if len(set(certificate_names)) != len(certificate_names):
            raise ValueError("Certificate names must be unique")
        duplicate_names: set[EntityName] = set(authority_by_name).intersection(
            certificate_names
        )
        if duplicate_names:
            names = ", ".join(sorted(duplicate_names))
            raise ValueError(
                f"Authority and certificate names must be distinct: {names}"
            )

        roots: list[CertificateAuthorityConfig] = [
            authority for authority in self.authorities if authority.issuer is None
        ]
        if not roots:
            raise ValueError(
                "PKI configuration must contain at least one root authority"
            )
        shortest_validity = min(
            authority.validity_days for authority in self.authorities
        )
        shortest_validity = min(
            shortest_validity,
            min(certificate.validity_days for certificate in self.certificates),
        )
        if self.renew_before_days >= shortest_validity:
            raise ValueError(
                "renew_before_days must be shorter than every certificate validity"
            )

        for authority in self.authorities:
            if (
                authority.issuer is not None
                and authority.issuer not in authority_by_name
            ):
                raise ValueError(
                    f"Unknown issuer {authority.issuer} for authority {authority.name}"
                )
        for certificate in self.certificates:
            if certificate.issuer not in authority_by_name:
                message = (
                    f"Unknown issuer {certificate.issuer} for certificate"
                    f" {certificate.name}"
                )
                raise ValueError(message)

        for authority in self.authorities:
            self._validate_authority_chain(authority, authority_by_name)
        for certificate in self.certificates:
            issuer = authority_by_name[certificate.issuer]
            if certificate.validity_days > issuer.validity_days:
                message = (
                    f"Certificate {certificate.name} cannot outlive issuer"
                    f" {issuer.name}"
                )
                raise ValueError(message)
        return self

    @staticmethod
    def _validate_authority_chain(
        authority: CertificateAuthorityConfig,
        authority_by_name: dict[str, CertificateAuthorityConfig],
    ) -> None:
        visited: set[str] = set()
        current: CertificateAuthorityConfig = authority
        depth: int = 0

        while current.issuer is not None:
            if current.name in visited:
                raise ValueError(
                    f"Certificate authority cycle detected at {current.name}"
                )
            visited.add(current.name)
            issuer = authority_by_name[current.issuer]
            if issuer.name in visited:
                raise ValueError(
                    f"Certificate authority cycle detected at {issuer.name}"
                )
            if current.validity_days > issuer.validity_days:
                raise ValueError(
                    f"Authority {current.name} cannot outlive issuer {issuer.name}"
                )
            depth += 1
            if issuer.path_length < depth - 1:
                message = (
                    f"Authority {issuer.name} path_length is too small for"
                    f" {authority.name}"
                )
                raise ValueError(message)
            current = issuer
