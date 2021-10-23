#!/usr/bin/env python3

import ssl
import socket
from pprint import pprint
from datetime import datetime
import OpenSSL


import binascii
import copy
import datetime
import ipaddress
import os
import typing


import pytz

from cryptography import utils, x509
from cryptography.x509 import extensions
from cryptography.x509.extensions import PolicyInformation
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ObjectIdentifier
from cryptography.hazmat.backends import default_backend

from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
    NameOID,
    SignatureAlgorithmOID,
    SubjectInformationAccessOID,
)

# Connect to host, get X.509 in PEM format
def get_certificate(host, port=443, timeout=10):
    cert_pem = ssl.get_server_certificate((host, port))
    return cert_pem

import inspect

def test_OIDs(cert_x509):
    try:
        val = cert_x509.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
        print(val)

    except x509.ExtensionNotFound:
        return False

    for policy_val in val:
        print()
        print(policy_val)
        print(policy_val.policy_identifier)

        output = 'OID %s: ' % policy_val.policy_identifier.dotted_string
        print(output)

        if policy_val.policy_qualifiers is not None:
            for p in policy_val.policy_qualifiers:
                print(p)




#        print(policy.policy_identifier)

#        pi = PolicyInformation(policy, None)
#        print(pi)
#
#        # pass the serialized value to the constructor and see if it's still the same
#        pi2 = PolicyInformation(pi.serialize())
#        print(pi2)




def analyse2(cert_pem):
    # Parse PEM into X.509 object
    cert_x509 = x509.load_pem_x509_certificate(bytes(cert_pem, 'utf-8'))
    print(cert_x509.serial_number)

    test_OIDs(cert_x509)


def main(host, port=443):
    cert_pem = get_certificate(host, port)



    analyse2(cert_pem)


# Main
if __name__ == "__main__":
    main('cloud.koeroo.net', 443)
