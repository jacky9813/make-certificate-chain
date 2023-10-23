#!/usr/bin/env python3
import argparse
import argcomplete
import datetime
import sys
import warnings
import typing

import cryptography.x509

from .solver import solve_cert_chain
from . import VERSION
from . import utils


def main():
    warnings.simplefilter("always")
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=VERSION
    )
    parser.add_argument(
        "--expire-warning",
        type=float,
        default=15,
        help="Output warning if the certificate is about to expire."
        " (Unit: day, Default: 15)"
    )
    parser.add_argument(
        "--include-root-ca",
        action="store_true",
        help="Output Root CA's certificate as well."
    )
    parser.add_argument(
        "--in-type",
        choices=[cert_format for cert_format in utils.SUPPORTED_FORMATS.keys()],
        default="x509",
        help="The file type for the input file. (Default: x509)"
    )
    parser.add_argument(
        "server_cert",
        nargs="?",
        type=argparse.FileType(mode="rb"),
        default=sys.stdin.buffer,
        help="The certificate file. Can be X.509 in DER or PEM encoding. "
        "Leave blank if using stdin."
    )

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    # Reading certificate
    server_cert_src = args.server_cert.read()
    if args.server_cert != sys.stdin.buffer:
        args.server_cert.close()
    
    server_cert = utils.SUPPORTED_FORMATS[args.in_type](server_cert_src)[0]

    if args.expire_warning < 0:
        warnings.warn("Received a negative value in --expire-warning.")

    chain = solve_cert_chain(
        server_cert,
        None,
        datetime.timedelta(days=args.expire_warning),
        args.include_root_ca
    )

    outputed_certs = []

    print("=" * 10, file=sys.stderr)
    for cert in chain:
        if cert in outputed_certs:
            continue
        print("Subject:   ", cert.subject.rfc4514_string(), file=sys.stderr)
        print("Issuer:    ", cert.issuer.rfc4514_string(), file=sys.stderr)
        print("Not Before:", cert.not_valid_before.strftime("%Y-%m-%dT%H:%M:%SZ"), file=sys.stderr)
        print("Not After: ", cert.not_valid_after.strftime("%Y-%m-%dT%H:%M:%SZ"), file=sys.stderr)
        print("=" * 10, file=sys.stderr)
        print(
            cert.public_bytes(
                encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM
            ).decode().strip()
        )
        outputed_certs.append(cert)

if __name__ == "__main__":
    main()