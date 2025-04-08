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
    "--cert-type",
    default="x509",
    type=click.Choice([
        fmt
        for fmt in utils.CERTIFICATE_FORMATS.keys()
    ], case_sensitive=True),
    help="The format of the certificate file.",
    show_default=True
)
@click.option(
    "--capath",
    help="The path where CA certificates store at. "
    "Can be a directory containing multiple X.509 files or a single X.509 "
    "file. Default store path depends on the operating system or OpenSSL "
    "configuration."
)
@click.option(
    "-o", "--output",
    help="The filename for the certificate chain.",
    type=click.File(mode="w"),
    default="-",
    show_default=True
)
@click.option(
    "--skip-ocsp",
    help="Skip certificate revoke check via OCSP",
    is_flag=True,
    default=False
)
def output_only(
    certificate_in: typing.Tuple[typing.BinaryIO, ...],
    cert_type: str,
    capath: typing.Optional[str],
    output: typing.TextIO,
    skip_ocsp: bool
):
    """
        Output certificate chain to stdout.

        Leave certificate_in blank for reading from stdin.
    """
    if not certificate_in:
        certificate_in = (sys.stdin.buffer, )
    logger.info("Reading a %s formatted certificate.", cert_type)
    certs = utils.CERTIFICATE_FORMATS[cert_type](certificate_in[0].read())
    if not certs:
        logger.critical("No certificate found in file.")
        sys.exit(1)

    ca_certs = utils.get_system_ca(capath or None)

    for cert in solver.solve_cert_chain(
        certs[0],
        ca_certs,
        skip_ocsp_verification=skip_ocsp
    ):
        logger.info("=" * common.PADDING_LENGTH)
        for line in common.output_info(cert).splitlines():
            logger.info(line)
        logger.info("=" * common.PADDING_LENGTH)
        print(
            cert.public_bytes(Encoding.PEM).decode().strip(),
            file=output
        )

