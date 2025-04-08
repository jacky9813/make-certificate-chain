import logging
import sys
import typing

import click
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from .cli import cli
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
    "--cert-type",
    default="x509",
    type=click.Choice([
        fmt
        for fmt in utils.CERTIFICATE_FORMATS.keys()
    ], case_sensitive=True),
    help="The format of the certificate file.",
    show_default=True
)
def get_issuer(
    certificate_in: typing.Tuple[typing.BinaryIO, ...],
    cert_type: str
):
    """
    Get the issuer certificate.
    """
    logger.info("Reading a %s formatted certificate", cert_type)
    if not certificate_in:
        logger.info("Reading certificate from stdin. Waiting for EOF...")
        certificate_in = (sys.stdin.buffer, )
    certs: typing.List[x509.Certificate] = utils.CERTIFICATE_FORMATS[
        cert_type](certificate_in[0].read())
    if not certs:
        logger.critical("No certificate found in file")
        ctx = click.get_current_context()
        if ctx:
            ctx.exit(1)
        sys.exit(1)

    if certs[0].issuer == certs[0].subject:
        logger.critical("Cannot get issuer for self-signed certificate.")
        ctx = click.get_current_context()
        if ctx:
            ctx.exit(1)
        sys.exit(1)

    issuer = solver.get_issuer_certificate(certs[0]).get(
        certs[0].issuer.rfc4514_string(), [])
    for issuer_cert in issuer:
        solver.verify_certificate(
            certs[0],
            issuer_cert,
            skip_ocsp_verification=True
        )
        print(issuer_cert.public_bytes(Encoding.PEM).decode().strip())
        break
