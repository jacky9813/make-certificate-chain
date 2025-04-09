import itertools
import logging
import os
import sys
import typing

import click
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from .cli import cli
from .. import utils

logger = logging.getLogger(__name__)

INDISTINGUISHABLE_RDN = [
    NameOID.BUSINESS_CATEGORY,
    NameOID.COUNTRY_NAME,
    NameOID.DOMAIN_COMPONENT,
    NameOID.GIVEN_NAME,
    NameOID.LOCALITY_NAME,
    NameOID.STATE_OR_PROVINCE_NAME,
    NameOID.STREET_ADDRESS,
]
FILTERED_RDN = [
    NameOID.SERIAL_NUMBER,
    NameOID.GENERATION_QUALIFIER,
    NameOID.X500_UNIQUE_IDENTIFIER,
    NameOID.EMAIL_ADDRESS,
]
RDN_PRIORITY = [
    NameOID.COMMON_NAME,
    NameOID.ORGANIZATIONAL_UNIT_NAME,
    NameOID.ORGANIZATION_NAME,
]


def get_best_rdn(dn: x509.Name) -> typing.Iterable[x509.NameAttribute]:
    labels = [
        attribute
        for rdn in dn.rdns
        for attribute in rdn._attributes
        if attribute.oid not in FILTERED_RDN
    ]
    if labels[0].oid in INDISTINGUISHABLE_RDN:
        return [l for l in labels[::-1] if l.oid not in INDISTINGUISHABLE_RDN]
    if labels[-1].oid in INDISTINGUISHABLE_RDN:
        return [l for l in labels if l.oid not in INDISTINGUISHABLE_RDN]
    try:
        left_priority = RDN_PRIORITY.index(labels[0].oid)
    except ValueError:
        left_priority = len(RDN_PRIORITY)
    try:
        right_priority = RDN_PRIORITY.index(labels[-1].oid)
    except ValueError:
        right_priority = len(RDN_PRIORITY)
    # Smaller number is higher priority
    return labels[::-1] if right_priority < left_priority else labels


@cli.command()
@click.argument(
    "output_dir",
    type=click.Path(
        exists=False,
        file_okay=False,
        dir_okay=True,
        writable=True,
        readable=True,
        allow_dash=False
    )
)
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
def split_certs(
    output_dir: typing.Union[os.PathLike, str],
    certificate_in: typing.Tuple[typing.BinaryIO, ...],
    cert_type: str
):
    """
    Split a file that contains multiple certificates into multiple files.
    Each file will be named after its
    """
    os.makedirs(output_dir, exist_ok=True)
    if not certificate_in:
        certificate_in = (sys.stdin.buffer, )
    certs: typing.Iterable[x509.Certificate] = itertools.chain(*[
        utils.CERTIFICATE_FORMATS[cert_type](cert_fd.read())
        for cert_fd in certificate_in
    ])

    for cert in certs:
        labels = get_best_rdn(cert.subject)
        for label in labels:
            filename = f'{label.value}.pem'.replace("/", "_")
            output_path = os.path.join(output_dir, filename)
            if not os.path.exists(output_path):
                break
        loop_count = 0
        while os.path.exists(output_path):
            logger.warning("%s already exists", output_path)
            output_path = os.path.join(
                output_dir,
                "{}{}.pem".format(
                    labels[0].value,
                    f'.{loop_count}' if loop_count else ""
                )
            )
            loop_count += 1
        with open(output_path, mode="wb") as cert_fd:
            cert_fd.write(cert.public_bytes(Encoding.PEM))
