import itertools
import sys
import typing
import logging

import click
from cryptography.hazmat.primitives.serialization import Encoding

from .cli import cli
from . import common
from .. import utils
from .. import solver

logger = logging.getLogger(__name__)


@cli.command()
@click.argument(
    "certificate_in",
    type=click.File(mode="rb"),
    nargs=-1
)
@click.option(
    "--capath",
    help="The path where CA certificates store at. "
    "Can be a directory containing multiple X.509 files or a single X.509 "
    "file. Default store path depends on the operating system or OpenSSL "
    "configuration."
)
@click.option(
    "--skip-revoke-check",
    help="Skip certificate revoke check via OCSP or CRL",
    is_flag=True,
    default=False
)
def verify_chain(
    certificate_in: typing.Tuple[typing.BinaryIO, ...],
    capath: typing.Optional[str],
    skip_revoke_check: bool
):
    """
        Output certificate chain to stdout.

        Leave certificate_in blank for reading from stdin.
    """
    if skip_revoke_check:
        logger.warning("Will not check certificate revocation")

    if not certificate_in:
        certificate_in = [sys.stdin.buffer]

    cert_chain = [
        (cert, False)
        for cert in itertools.chain(*[
            utils.read_x509_certificates(cert_fd.read())
            for cert_fd in certificate_in
        ])
    ]
    if not cert_chain:
        logger.critical("No certificate found in file.")
        sys.exit(1)

    logger.info("Read %d certificates", len(cert_chain))

    ca_certs = utils.get_system_ca(capath or None)

    if cert_chain[-1][0].subject != cert_chain[-1][0].issuer:
        # add root ca to the end
        ca_name = cert_chain[-1][0].issuer.rfc4514_string()
        root_ca_cert = ca_certs.get(ca_name)
        if root_ca_cert:
            ca_cert = root_ca_cert[0]
            logger.info(
                'Using Root CA certificate "%s"',
                ca_cert.subject.rfc4514_string()
            )
            cert_chain.append((ca_cert, True))
        else:
            logger.warning('CA certificate for "%s" not found', ca_name)
    else:
        logger.warning("Root CA should not be provided in certificate chain.")

    for (subject, _), (issuer, from_system) in zip(cert_chain[:-1], cert_chain[1:]):
        logger.info("=" * common.PADDING_LENGTH)
        logger.info("Verifying:")
        logger.info("Not Before:     %s", utils.format_datetime(
            subject.not_valid_before_utc))
        logger.info("Not After:      %s", utils.format_datetime(
            subject.not_valid_after_utc))
        logger.info("Cert Subject:   %s", subject.subject.rfc4514_string())
        logger.info("Cert Issuer:    %s", subject.issuer.rfc4514_string())
        logger.info("CA Subject:     %s", issuer.subject.rfc4514_string())
        logger.info("CA Issuer:      %s", issuer.issuer.rfc4514_string())
        logger.info("CA Cert Source: %s", "System" if from_system else "Chain")
        solver.verify_certificate(
            subject, issuer, skip_revoke_check=skip_revoke_check
        )
        logger.info("")
        logger.info("Verify: OK")
        logger.info("=" * common.PADDING_LENGTH)
