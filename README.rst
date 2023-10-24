======================
Make Certificate Chain
======================

.. image:: https://github.com/jacky9813/make-certificate-chain/actions/workflows/test.yml/badge.svg

This program helps system administrators to configure a Web Service that
provides full SSL/TLS chain when handshaking.

With server provides all the certificates needed, it is possible to gain
a little performance benefit for client verifying the server certificate.

.. note:: 
    This program leverages on the existence of CAIssuers field 
    (OID: ``1.3.6.1.5.5.7.48.2``).


Certificate Validation
======================

User shouldn't seen SSL handshake error due to invalid certificate. This program also validates
all certificates in chain. These are the items being checked across all certificates in chain:

- Signature
- Issuer name and subject name in issuer's certficate.
- Dates (Not Before, Not After)


Supported Certificate Formats / Encodings
=========================================

- X.509 in PEM or DER encoding (``--cert-type=x509``)
- PKCS#7 certificates bundle in PEM or DER encoding (``--cert-type=pkcs7``)
- PKCS#12 certificates and key bundle in DER encoding (``--cert-type=pkcs12``)

.. important::
    For PKCS#12 bundle, when importing certificate into cloud services, this program will only
    use bundled private key.

    If the bundle doesn't contain the key, the program will fail.

.. important::
    For containers capable of bundling multiple certificates (X.509 in PEM, PKCS#7, PKCS#12),
    only the first certificate will be parsed by this program.


Supported Importing Destinations
================================

.. _Global/Regional SSL Certificates: https://cloud.google.com/load-balancing/docs/ssl-certificates/self-managed-certs
.. _AWS Certificate Manager: https://docs.aws.amazon.com/acm/latest/userguide/import-certificate-api-cli.html

- Google Cloud - `Global/Regional SSL Certificates`_
- AWS - `AWS Certificate Manager`_ (ACM)


System Requirements
===================

.. _Google Cloud CLI: https://cloud.google.com/sdk/docs/install
.. _AWS CLI: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

- Python 3.8 or later
- `Google Cloud CLI`_ for import certificate to Google Cloud
- `AWS CLI`_ for import certificate to AWS Certificate Manager (ACM)


Install & Upgrade
=================

.. code-block:: shell

    pip install -U git+https://github.com/jacky9813/make-certificate-chain


Usage
=====

.. note::

    Unlike OpenSSL, this program detects the format automatically, so you
    don't have to put ``-inform`` equivalent parameter.

Example 1: Simple usage
-----------------------

.. code-block:: shell

    mkcertchain output-only example.cert.pem > example.chain.pem


Example 2: Piped from stdout
----------------------------

.. code-block:: shell

    echo "" | openssl s_client -connect www.example.com:443 | mkcertchain output-only > example.com.chain.pem

Example 3: Create SSL Certificate in Google Cloud
-------------------------------------------------

.. code-block:: shell

    # Log into Google Cloud and update Application Default Credentials
    gcloud auth login --update-adc
    # The following command will ask password for private key, even it's unencrypted.
    # In such case, input nothing but enter when prompted for password.
    mkcertchain gcp --project my-project my-certificate server.cert.pem server.key.pem

Example 4: Create SSL Certificate in AWS with PKCS#12 bundle
------------------------------------------------------------

.. code-block:: shell

    # The following command will ask password for unpack PKCS#12 bundle, even it's unencrypted.
    # In such case, input nothing but enter when prompted for password.
    mkcertchain aws --cert-type=pkcs12 --profile=aws-cli-profile --region=ap-northeast-1 server.pfx

Example 5: Via Python module
----------------------------

.. code-block:: shell

    python3 -m make_certificate_chain --help

