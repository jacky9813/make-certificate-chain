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
    type=click.Choice([fmt for fmt in utils.CERTIFICATE_FORMATS.keys()], case_sensitive=True),
    help="The format of the certificate file. (Default: x509)"
)
def output_only(certificate_in: typing.Tuple[typing.BinaryIO, ...], cert_type: str):
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
    for cert in solver.solve_cert_chain(certs[0]):
        logger.info("=" * common.PADDING_LENGTH)
        for line in common.output_info(cert).splitlines():
            logger.info(line)
        logger.info("=" * common.PADDING_LENGTH)
        print(cert.public_bytes(Encoding.PEM).decode().strip())
