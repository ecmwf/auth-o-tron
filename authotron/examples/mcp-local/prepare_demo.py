"""Generate disposable local-demo material outside the source repository."""

import argparse
import ipaddress
import json
import os
import secrets
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from demo_settings import (
    CALLBACK,
    CLIENT_ID,
    RESOURCE,
    ROLE,
    SCOPE,
    make_settings,
    validate_remote_issuer,
)

REPOSITORY = Path(__file__).resolve().parents[3]


def outside_repository(path: Path) -> Path:
    """Resolve aliases before checking containment (e.g. /tmp/demo is valid,
    repository/examples/runtime is invalid).
    """
    resolved = path.expanduser().resolve()
    if resolved == REPOSITORY or REPOSITORY in resolved.parents:
        raise ValueError("runtime directory must be outside the repository")
    if resolved in REPOSITORY.parents:
        raise ValueError("runtime directory cannot contain the repository")
    return resolved


def write_private(path: Path, contents: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(contents)


def write_json(path: Path, value: dict) -> None:
    write_private(path, (json.dumps(value, indent=2) + "\n").encode())


def private_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def generate_tls(runtime: Path) -> None:
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Authotron local demo CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    write_private(runtime / "tls-ca.pem", ca.public_bytes(serialization.Encoding.PEM))
    write_private(runtime / "tls-cert.pem", leaf.public_bytes(serialization.Encoding.PEM))
    write_private(runtime / "tls-key.pem", private_pem(key))
    # The CA signing key is discarded; this demo never installs trust or issues more leaves.


def prepare(runtime_dir: Path, issuer: str | None = None) -> Path:
    """Local mode (issuer None) writes a full Authotron runtime; remote mode writes only
    the resource server's TLS material and settings.json pointing at the remote issuer.
    """
    settings = make_settings(issuer)
    # Check the unresolved spelling too: an existing symlink must never be overridden.
    original = runtime_dir.expanduser()
    runtime = outside_repository(original)
    if original.exists() or original.is_symlink() or runtime.exists():
        raise FileExistsError("runtime directory already exists; choose a new path")
    runtime.mkdir(mode=0o700)
    try:
        runtime.chmod(0o700)
        if issuer is not None:
            generate_tls(runtime)
            write_json(runtime / "settings.json", settings)
            return runtime
        issuer = settings["issuer"]
        signing = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        write_private(runtime / "oauth-private.pem", private_pem(signing))
        generate_tls(runtime)
        password = secrets.token_urlsafe(24)
        config = {
            "version": "2.0.0",
            "store": {"enabled": False},
            "services": [],
            "providers": [
                {
                    "type": "plain",
                    "name": "basic",
                    "realm": "local",
                    "users": [{"username": "alice", "password": password, "roles": [ROLE]}],
                }
            ],
            "augmenters": [],
            "server": {"host": "127.0.0.1", "port": 8000},
            "metrics": {"enabled": False},
            "include_legacy_headers": False,
            "jwt": {"iss": "mcp-local-legacy", "exp": 300, "secret": secrets.token_urlsafe(32)},
            "logging": {"level": "warn", "format": "console"},
            "auth": {"timeout_in_ms": 5000},
            "ui": {
                "enabled": True,
                "basic": {"provider_name": "basic"},
                "browser_session": {
                    "public_origin": issuer.rstrip("/"),
                    "backend": {"type": "memory"},
                },
            },
            "oauth": {
                "enabled": True,
                "issuer": issuer,
                "signing": {
                    "active_kid": "mcp-local",
                    "keys": [
                        {"kid": "mcp-local", "private_key_file": str(runtime / "oauth-private.pem")}
                    ],
                },
                "clients": [
                    {
                        "client_id": CLIENT_ID,
                        "display_name": "Local MCP demo",
                        "application_type": "native",
                        "redirect_uris": [CALLBACK],
                        "resources": [{"resource": RESOURCE, "scopes": [SCOPE]}],
                    }
                ],
                "resources": [
                    {
                        "resource": RESOURCE,
                        "allowed_realms": ["local"],
                        "scopes": [{"name": SCOPE, "required_roles": [ROLE]}],
                    }
                ],
            },
        }
        write_json(runtime / "authotron.json", config)
        write_json(runtime / "credentials.json", {"username": "alice", "password": password})
        write_json(runtime / "settings.json", settings)
    except BaseException:
        shutil.rmtree(runtime)
        raise
    return runtime


def issuer_argument(value: str) -> str:
    """Report make_settings' issuer rule as a usage error (exit 2) instead of a runtime failure."""
    try:
        return validate_remote_issuer(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument(
        "--issuer",
        type=issuer_argument,
        help="remote HTTPS issuer origin with trailing slash, e.g. https://issuer.example.org/",
    )
    args = parser.parse_args()
    try:
        runtime = prepare(args.runtime_dir, args.issuer)
    except (OSError, ValueError):
        parser.exit(
            1,
            "Preparation failed: use a new path outside the repository with an existing writable parent.\n",
        )
    print(f"Prepared private demo runtime: {runtime}")


if __name__ == "__main__":
    main()
