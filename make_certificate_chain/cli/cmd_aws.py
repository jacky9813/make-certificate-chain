import typing
import logging
import sys

import click
import boto3

from .cli import cli
from . import common
from .. import utils


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
    help="The format of the certificate file.",
    show_default=True
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Do not perform change to AWS.",
    show_default=True
)
@click.option(
    "--profile",
    help="AWS CLI profile to be used."
)
@click.option(
    "--region",
    help="The region where certificate to be created at. Defaults to what "
    "has specified in the profile."
)
@click.option(
    "--capath",
    help="The path where CA certificates store at. "
    "Can be a directory containing multiple X.509 files or a single X.509 "
    "file. Default store path depends on the operating system or OpenSSL "
    "configuration."
)
@click.option(
    "--skip-ocsp",
    help="Skip certificate revoke check via OCSP",
    is_flag=True,
    default=False
)
def aws(
    certificate_in: typing.BinaryIO,
    key_in: typing.Tuple[typing.BinaryIO, ...],
    target_arn: typing.Optional[str],
    cert_type: str,
    dry_run: bool,
    profile: typing.Optional[str],
    region: typing.Optional[str],
    capath: typing.Optional[str],
    skip_ocsp: bool
):
    """
    Upload certificate chain to AWS Certificate Manager (ACM).

    Certificate ARN will be shown in stdout after import/reimport.

    For PKCS #12 or PFX files with private key bundled, KEY_IN is not required.
    """

    cert_raw = certificate_in.read()
    key_raw = None
    if key_in and key_in[0] != sys.stdin.buffer:
        key_raw = key_in[0].read()

    cert_pem, chain_pem, key_pem = common.build_pem_chain_and_key(
        cert_type, cert_raw, key_raw,
        ca_path=capath or None,
        skip_ocsp_verification=skip_ocsp
    )

    if dry_run:
        print("\n".join([
            line if "-----" in line else "*" * len(line)
            for line in key_pem.splitlines()
        ]))
        print(chain_pem)
        return

    session = boto3.Session(**({"profile_name": profile} if profile else {}))
    acm_client = session.client(
        "acm",
        **({"region_name": region} if region else {})
    )

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
