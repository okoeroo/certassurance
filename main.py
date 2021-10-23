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


OID_DV = "2.23.140.1.2.1"
OID_OV = "2.23.140.1.2.2"

"""
Wikipedia:

EV HTTPS certificates contain a subject with X.509 OIDs for jurisdictionOfIncorporationCountryName (OID: 1.3.6.1.4.1.311.60.2.1.3),[12] jurisdictionOfIncorporationStateOrProvinceName (OID: 1.3.6.1.4.1.311.60.2.1.2) (optional),[13]jurisdictionLocalityName (OID: 1.3.6.1.4.1.311.60.2.1.1) (optional),[14] businessCategory (OID: 2.5.4.15)[15] and serialNumber (OID: 2.5.4.5),[16] with the serialNumber pointing to the ID at the relevant secretary of state (US) or government business registrar (outside US)[citation needed], as well as a CA-specific policy identifier so that EV-aware software, such as a web browser, can recognize them.[17] This identifier[18][failed verification] is what defines EV certificate and is the difference with OV certificate.
"""


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
    import ssl
    port = 443
    conn = ssl.create_connection((host, port))
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    sock = context.wrap_socket(conn, server_hostname=host)
    cert_pem = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))

    # cert_pem = ssl.get_server_certificate((host, port))
    return cert_pem

def identify_cert(cert_x509):
    print("Subject:", cert_x509.subject.rfc4514_string())
    print("Serial number:", cert_x509.serial_number)


# Get the Policy OIDs from the certificate and see if it contains the OIDs for DN, OV or EV
def test_OIDs(cert_x509):
    try:
        val = cert_x509.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
        # print(val)

    except x509.ExtensionNotFound:
        return None

    # Display
    for policy_val in val:
        output = 'OID %s: ' % policy_val.policy_identifier.dotted_string

        if policy_val.policy_qualifiers is not None:
            p_qualifiers = [p_q for p_q in policy_val.policy_qualifiers]
        else:
            p_qualifiers = None

        print(output, p_qualifiers)

    # Test
    for policy_val in val:
        if OID_DV == policy_val.policy_identifier.dotted_string:
            print ("Domain Validated OID found!")
            return OID_DV
        if OID_OV == policy_val.policy_identifier.dotted_string:
            print ("Organisation Validated OID found!")
            return OID_OV

    return None



def analyse(cert_pem):
    # Parse PEM into X.509 object
    cert_x509 = x509.load_pem_x509_certificate(bytes(cert_pem, 'utf-8'))

    identify_cert(cert_x509)
    test_OIDs(cert_x509)


def main(host, port=443):
    cert_pem = get_certificate(host, port)

    analyse(cert_pem)


# Main
if __name__ == "__main__":
    with open("tests.txt") as fp:
        lines = fp.readlines()
        for line in lines:
            print(" --- {} ---".format(line.strip()))
            main(line.strip(), 443)

