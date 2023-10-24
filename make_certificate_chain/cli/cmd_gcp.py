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
from google.cloud import compute_v1

from .cli import cli
from . import common
from .. import utils
from .. import solver


logger = logging.getLogger(__name__)

@cli.command()
@click.argument("name")
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
    "--project",
    help="Google Cloud project id. Program uses current project in gcloud by default."
)
@click.option(
    "--description",
    help="The description for the certificate."
)
@click.option(
    "--region",
    help="The region where certificate to be created at. Defaults to global.",
    default="global"
)
def gcp(
    name: str,
    certificate_in: typing.BinaryIO,
    key_in: typing.Tuple[typing.BinaryIO, ...],
    cert_type: str,
    dry_run: bool,
    project: typing.Optional[str],
    description: str,
    region: str
):
    """
        Upload certificate chain to Google Cloud.

        Resource self-link will be shown in stdout after import.
    """
    cert_raw = certificate_in.read()
    key_raw = None
    if key_in and key_in[0] != sys.stdin.buffer:
        key_raw = key_in[0].read()

    _, chain_pem, key_pem = common.build_pem_chain_and_key(
        cert_type, cert_raw, key_raw
    )

    if dry_run:
        logger.warning(
            "Program running in dry run mode. "
            "Outputting masked key and certificate chain into stdout."
        )
        print("\n".join([
            line if "-----" in line else "*" * len(line)
            for line in key_pem.splitlines()
        ]))
        print(chain_pem)
        return
    
    ssl_cert = compute_v1.SslCertificate(
        certificate=chain_pem,
        private_key=key_pem,
        name=name,
        description=description or ""
    )
    additional_args = {"project": project} if project else {}
    if region == "global":
        ssl_cert_client = compute_v1.SslCertificatesClient()
        operation_client = compute_v1.GlobalOperationsClient()
    else:
        additional_args["region"] = region
        ssl_cert_client = compute_v1.RegionSslCertificatesClient()
        operation_client = compute_v1.RegionOperationsClient()
        
    logger.info(
        "Creating GCP SSL Certificate %s for project %s in %s",
        name, project, region
    )
    insert_operation = ssl_cert_client.insert_unary(
        ssl_certificate_resource=ssl_cert,
        **additional_args
    )
    operation_client.wait(
        operation=insert_operation.name,
        **additional_args
    )
    ssl_cert_object: compute_v1.SslCertificate = ssl_cert_client.get(
        ssl_certificate=name,
        **additional_args
    )

    logger.info("%s created", ssl_cert_object.self_link)
    print(ssl_cert_object.self_link)
