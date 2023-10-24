import typing
import logging
import getpass
import sys

import click
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
import boto3

from .cli import cli
from . import common
from .. import utils
from .. import solver



logger = logging.getLogger(__name__)

@cli.command()
@click.argument(
    "certificate_in",
    type=click.File(mode="rb")
)
@click.argument(
    "key_in",
    type=click.File(mode="rb"),
    nargs=-1
)
@click.option(
    "--target-arn",
    help="Reimport certificate to selected ACM certificate resource."
)
@click.option(
    "--cert-type",
    default="x509",
    type=click.Choice([
        fmt for fmt in utils.CERTIFICATE_FORMATS.keys()
    ], case_sensitive=True),
    help="The format of the certificate file. (Default: x509)"
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Do not perform change to Google Cloud."
)
@click.option(
    "--profile",
    help="AWS CLI profile to be used."
)
@click.option(
    "--region",
    help="The region where certificate to be created at. "
    "Defaults to what profile specified."
)
def aws(
    certificate_in: typing.BinaryIO,
    key_in: typing.Tuple[typing.BinaryIO, ...],
    target_arn: typing.Optional[str],
    cert_type: str,
    dry_run: bool,
    profile: typing.Optional[str],
    region: typing.Optional[str]
):
    """
        Upload certificate chain to AWS Certificate Manager (ACM).

        Certificate ARN will be shown in stdout after import/reimport.
    """
    
    cert_raw = certificate_in.read()
    key_raw = None
    if key_in and key_in[0] != sys.stdin.buffer:
        key_raw = key_in[0].read()

    cert_pem, chain_pem, key_pem = common.build_pem_chain_and_key(
        cert_type, cert_raw, key_raw
    )

    if dry_run:
        print("\n".join([
            line if "-----" in line else "*" * len(line)
            for line in key_pem.splitlines()
        ]))
        print(chain_pem)
        return

    session = boto3.Session(**({"profile_name": profile} if profile else {}))
    acm_client = session.client("acm", **({"region_name": region} if region else {}))

    response = acm_client.import_certificate(
        Certificate=cert_pem.encode(),
        PrivateKey=key_pem.encode(),
        CertificateChain=chain_pem.encode(),
        **({"CertificateArn": target_arn} if target_arn else {})
    )

    logger.info(
        "Certificate imported into %s",
        response.get("CertificateArn", "UNKNOWN")
    )

    print(response.get("CertificateArn", ""))
