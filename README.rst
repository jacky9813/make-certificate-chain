=======================
Certificate Chain Maker
=======================

.. image:: https://github.com/jacky9813/make-certificate-chain/actions/workflows/test.yml/badge.svg

This program helps system administrators to configure a Web Service that
provides full SSL/TLS chain when handshaking.

With server provides all the certificates needed, it is possible to gain
a little performance benefit for client verifying the server certificate.

.. note:: 
    This program leverages on the existence of CAIssuers field 
    (OID: ``1.3.6.1.5.5.7.48.2``).


System Requirements
===================

- Python 3.7+


Supported Certificate Formats / Encodings
=========================================

- X.509 in PEM or DER encoding
- PKCS#7 certificates bundle in PEM or DER encoding
- PKCS#12 certificates and key bundle in DER encoding


Install
=======

.. code-block:: shell

    pip install git+https://github.com/jacky9813/make-certificate-chain


Usage
=====

.. note::

    Unlike OpenSSL, this program detects the format automatically, so you
    don't have to put ``-inform`` equivalent parameter.

Example 1: Simple usage
-----------------------

.. code-block:: shell

    mkcertchain example.cert.pem > example.chain.pem


Example 2: Piped from stdout
----------------------------

.. code-block:: shell

    echo "" | openssl s_client -connect www.example.com:443 | mkcertchain > example.com.chain.pem

Example 3: Export with Root CA's certificate
--------------------------------------------

.. code-block:: shell

    mkcertchain --include-root-ca example.cert.pem

Example 4: Using PKCS#7 certificates file
-----------------------------------------

.. code-block:: shell

    mkcertchain --in-type=pkcs7 example.p7b.der

Example 5: Python module
------------------------

.. code-block:: shell

    python3 -m make_certificate_chain --help

