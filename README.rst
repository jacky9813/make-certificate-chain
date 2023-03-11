=======================
Certificate Chain Maker
=======================

.. _rkoopmans/python-certificate-chain-resolver: https://github.com/rkoopmans/python-certificate-chain-resolver

.. note::
    Wait, there're better options like `rkoopmans/python-certificate-chain-resolver`_.

    This project is not planned to be uploaded to PyPi unless there's a great reason for me to publish.
    

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

- X.509 in PEM encoding
- X.509 in DER encoding


Install
=======

.. code-block:: shell

    pip install https://github.com/jacky9813/make-certificate-chain


Usage
=====

Example 1: Simple usage
-----------------------

.. code-block:: shell

    mkcertchain example.cert.pem > example.chain.pem


Example 2: Piped from stdout
----------------------------

.. code-block:: shell

    echo "" | openssl s_client -connect www.example.com:443 | openssl x509 | mkcertchain > example.com.chain.pem

Example 3: Export with Root CA's certificate
--------------------------------------------

.. code-block:: shell

    mkcertchain --include-root-ca example.cert.pem

