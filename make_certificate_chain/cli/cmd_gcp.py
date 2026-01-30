import typing
import logging
import sys
import time
import uuid

import click
from google.cloud import compute_v1
from google.cloud import certificate_manager_v1
import google.auth

from .cli import cli
from . import common
from .. import utils


logger = logging.getLogger(__name__)


def _compute_upload_global(
    project: str, ssl_cert: compute_v1.SslCertificate,
    request_id: uuid.UUID
) -> compute_v1.SslCertificate:
    ssl_cert_client = compute_v1.SslCertificatesClient()
    operation_client = compute_v1.GlobalOperationsClient()
    request = compute_v1.InsertSslCertificateRequest(
        project=project, ssl_certificate_resource=ssl_cert,
        request_id=str(request_id)
    )
    insert_operation = ssl_cert_client.insert_unary(request)
    wait_request = compute_v1.WaitGlobalOperationRequest(
        project=project, operation=insert_operation.name
    )
    operation_client.wait(wait_request)
    get_cert_request = compute_v1.GetSslCertificateRequest(
        project=project, ssl_certificate=ssl_cert.name
    )
    ssl_cert_object = ssl_cert_client.get(get_cert_request)
    return ssl_cert_object


def _compute_upload_regional(
    project: str, region: str, ssl_cert: compute_v1.SslCertificate,
    request_id: uuid.UUID
) -> compute_v1.SslCertificate:
    ssl_cert_client = compute_v1.RegionSslCertificatesClient()
    operation_client = compute_v1.RegionOperationsClient()
    request = compute_v1.InsertRegionSslCertificateRequest(
        project=project, region=region, ssl_certificate_resource=ssl_cert,
        request_id=str(request_id),
    )
    insert_operation = ssl_cert_client.insert_unary(request)
    wait_request = compute_v1.WaitRegionOperationRequest(
        project=project, region=region, operation=insert_operation.name
    )
    operation_client.wait(wait_request)
    get_cert_request = compute_v1.GetRegionSslCertificateRequest(
        project=project, region=region, ssl_certificate=ssl_cert.name
    )
    ssl_cert_object = ssl_cert_client.get(get_cert_request)
    return ssl_cert_object


def _compute_upload(
    project: str, region: str, name: str,
    chain_pem: str, key_pem: str,
    description: str = ""
) -> None:
    request_id = uuid.uuid4()
    is_global = region == "global"
    ssl_cert = compute_v1.SslCertificate(
        name=name, certificate=chain_pem, private_key=key_pem,
        description=description
    )
    expected_link = "/".join([
        "https://www.googleapis.com/compute/v1"
        "projects", project,
        *(["global"] if is_global else ["regions", region]),
        "sslCertificates", name
    ])

    logger.info(
        "Creating Compute Engine SSL Certificate %s", expected_link
    )
    if is_global:
        ssl_cert_object = _compute_upload_global(
            project, ssl_cert, request_id)
    else:
        ssl_cert_object = _compute_upload_regional(
            project, region, ssl_cert, request_id)
    logger.info(
        "Compute Engine SSL Certificate %s created", ssl_cert_object.self_link
    )


def _certmgr_upload(
    project: str, region: str, name: str,
    chain_pem: str, key_pem: str,
    description: str = "", scope: str = "DEFAULT"
) -> certificate_manager_v1.Certificate:
    if region != "global" and scope != "DEFAULT":
        logger.warning("Regional certificates cannot specify scope. Ignored.")
    ssl_cert = certificate_manager_v1.Certificate(
        name=name,
        description=description,
        self_managed=certificate_manager_v1.Certificate.SelfManagedCertificate(
            pem_certificate = chain_pem,
            pem_private_key=key_pem),
        **(
            {"scope": getattr(certificate_manager_v1.Certificate.Scope, scope)}
            if region == "global" else {}),
    )
    parent = "/".join(["projects", project, "locations", region])
    resource = "/".join([parent, "certificates", name])
    insert_request = certificate_manager_v1.CreateCertificateRequest(
        parent=parent, certificate_id=name, certificate=ssl_cert
    )
    logger.info(
        "Creating certificate https://certificatemanager.googleapis.com/v1/%s",
        resource
    )
    client = certificate_manager_v1.CertificateManagerClient()
    operation = client.create_certificate(insert_request)
    while not operation.done():
        time.sleep(1.0)
    get_request = certificate_manager_v1.GetCertificateRequest(name=resource)
    ssl_cert = client.get_certificate(get_request)
    logger.info("Certificate created: %s", ssl_cert.name)
    return ssl_cert


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
    help="The format of the certificate file.",
    show_default=True
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Do not perform change to Google Cloud.",
    show_default=True
)
@click.option(
    "--project",
    help="Google Cloud project id. Program uses default project in "
    "application default credentials by default. Change the default project "
    "with \"gcloud auth application-default set-quota-project\"."
)
@click.option(
    "--description",
    help="The description for the certificate."
)
@click.option(
    "--region",
    help="The region where certificate to be created at.",
    default="global",
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
    "--skip-revoke-check",
    help="Skip certificate revoke check via OCSP or CRL",
    is_flag=True,
    default=False
)
@click.option(
    "--api",
    help="The API to be uploaded to. Default: compute",
    type=click.Choice(["compute", "certificatemanager"]),
    default="compute"
)
@click.option(
    "--scope",
    help="(Certificate Manager only) The scope for the global certificate. "
         "Default: DEFAULT",
    type=click.Choice(["DEFAULT", "EDGE_CACHE", "ALL_REGIONS"]),
    default="DEFAULT"
)
def gcp(
    name: str,
    certificate_in: typing.BinaryIO,
    key_in: typing.Tuple[typing.BinaryIO, ...],
    cert_type: str,
    dry_run: bool,
    project: typing.Optional[str],
    description: str,
    region: str,
    capath: typing.Optional[str],
    skip_revoke_check: bool,
    api: typing.Literal["compute", "certificatemanager"],
    scope: typing.Literal["DEFAULT", "EDGE_CACHE", "ALL_REGIONS"]
):
    """
    Upload certificate chain to Google Cloud.

    Resource self-link will be shown in stdout after import.

    For PKCS #12 or PFX files with private key bundled, KEY_IN is not required.
    """
    cert_raw = certificate_in.read()
    key_raw = None
    if key_in and key_in[0] != sys.stdin.buffer:
        key_raw = key_in[0].read()

    _, chain_pem, key_pem = common.build_pem_chain_and_key(
        cert_type, cert_raw, key_raw,
        ca_path=capath or None,
        skip_revoke_check=skip_revoke_check
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

    if project is None:
        _, project = google.auth.default()

    if api == "compute":
        _compute_upload(
            project=project, region=region, name=name,  # type: ignore
            chain_pem=chain_pem, key_pem=key_pem,
            description=description
        )
    elif api == "certificatemanager":
        _certmgr_upload(
            project=project, region=region, name=name,  # type: ignore
            chain_pem=chain_pem, key_pem=key_pem, description=description,
            scope=scope
        )

