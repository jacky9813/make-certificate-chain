import click.testing
from cryptography import x509
from cryptography.x509 import extensions as x509_extensions

from make_certificate_chain.cli import cli


def test_cli_output_only(example_com_cert: bytes):
    runner = click.testing.CliRunner()
    with runner.isolated_filesystem():
        with open("server.cert.pem", mode="wb") as cert_fd:
            cert_fd.write(example_com_cert)

        result = runner.invoke(
            cli,
            ["output-only", "-o", f"{__name__}.chain.pem", "server.cert.pem"]
        )

        assert result.exit_code == 0
        with open(f"{__name__}.chain.pem", mode="rb") as chain_fd:
            certs = x509.load_pem_x509_certificates(chain_fd.read())
        assert len(certs) > 1
        sans = [
            san.value
            for san in certs[0].extensions.get_extension_for_class(
                x509_extensions.SubjectAlternativeName
            ).value
        ]
        assert "example.com" in sans


def test_cli_output_only_with_stdin(example_com_cert: bytes):
    runner = click.testing.CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            cli,
            ["output-only", "-o", f"{__name__}.chain.pem"],
            input=example_com_cert
        )
        assert result.exit_code == 0
        with open(f"{__name__}.chain.pem", mode="rb") as chain_fd:
            certs = x509.load_pem_x509_certificates(chain_fd.read())
        assert len(certs) > 1
        sans = [
            san.value
            for san in certs[0].extensions.get_extension_for_class(
                x509_extensions.SubjectAlternativeName
            ).value
        ]
        assert "example.com" in sans
