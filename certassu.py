#!/usr/bin/env python3

from bottle import route, run, template

import binascii
import os
import sys
import argparse

import ssl
import socket
from pprint import pprint
import OpenSSL

import io
import csv
import json

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


class bcolors:
    HEADER = '\033[95m'
    COLOR_OV = '\033[94m'
    COLOR_IV = '\033[93m'
    COLOR_DV = '\033[96m'
    COLOR_EV = '\033[92m'
    COLOR_QWAC = '\033[0;37;45m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m'


IDENTIFIED_TYPE_DV      = 1
IDENTIFIED_TYPE_OV      = 2
IDENTIFIED_TYPE_EV      = 3
IDENTIFIED_TYPE_QWAC    = 4
IDENTIFIED_TYPE_PSD2    = 5
IDENTIFIED_TYPE_IV      = 6


# Source:
# https://cabforum.org/object-registry/
OID_CAB_FORUM_DV        = "2.23.140.1.2.1"
OID_CAB_FORUM_OV        = "2.23.140.1.2.2"
OID_CAB_FORUM_IV        = "2.23.140.1.2.3" # individual-validated
OID_CAB_FORUM_EV        = "2.23.140.1.1"
OID_QWAC_WEB    = "0.4.0.194112.1.4"
OID_PSD2_WEB    = "0.4.0.19495.3.1"

OID_ETSI_EV     = "0.4.0.2042.1.4"


"""
Wikipedia:

EV HTTPS certificates contain a subject with X.509 OIDs for jurisdictionOfIncorporationCountryName (OID: 1.3.6.1.4.1.311.60.2.1.3),[12] jurisdictionOfIncorporationStateOrProvinceName (OID: 1.3.6.1.4.1.311.60.2.1.2) (optional),[13]jurisdictionLocalityName (OID: 1.3.6.1.4.1.311.60.2.1.1) (optional),[14] businessCategory (OID: 2.5.4.15)[15] and serialNumber (OID: 2.5.4.5),[16] with the serialNumber pointing to the ID at the relevant secretary of state (US) or government business registrar (outside US)[citation needed], as well as a CA-specific policy identifier so that EV-aware software, such as a web browser, can recognize them.[17] This identifier[18][failed verification] is what defines EV certificate and is the difference with OV certificate.
"""

class PolicyOID():
    def __init__(self, path):
        with open(path, "r") as f:
            self.stream = io.StringIO(f.read())

        self.reader = csv.DictReader(self.stream)

    def lookup(self, oid):

        # Rewind stream
        self.rewind()

        # OrderedDict([
        # ('oid', '0.4.0.1456.1.1'), ('owner', 'ETSI'),
        # ('customer', ''), ('short_name', 'etsi-qcp'), ('long_name', 'ETSI
        # Qualified Certificate Policy'), ('description', 'ETSI Qualified
        # Certificate Policy (QCP)'), ('tls_dv', ''), ('tls_ov', ''),
        # ('tls_ev', ''), ('tls_iv', ''), ('codesigning_ov', ''),
        # ('codesigning_ev', '')])

        for row in self.reader:
            for key, value in row.items():
                if value == oid:
                    print(key, value)
                    return row
        else:
            return None

    def rewind(self):
        self.stream.seek(0, 0)

    def headers(self):
        # Rewind stream
        self.rewind()

        for row in self.reader:
            print(row)
            return

    def show(self):
        # Rewind stream
        self.rewind()

        for row in self.reader:
            print(row)



# Connect to host, get X.509 in PEM format
def get_certificate(host, port=443, timeout=5):

    try:
        conn = ssl.create_connection((host, port), timeout=timeout)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(capath='/etc/ssl/certs/',
                                      cafile='/etc/ssl/certs/ca-certificates.crt')

        sock = context.wrap_socket(conn, server_hostname=host)
        cert_der = sock.getpeercert(True)
        cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)

        # Note: Not matching hostname on purpose

    except:
        return None

    # cert_pem = ssl.get_server_certificate((host, port))
    return cert_pem


def info_cert(cert_x509):
    print("Subject:", cert_x509.subject.rfc4514_string())
    print("Subject:", cert_x509.issuer.rfc4514_string())
    print("Serial number:", cert_x509.serial_number)


# Get the Policy OIDs from the certificate and see if it contains the OIDs for DN, OV or EV
def test_OIDs(cert_x509):
    # poid.show()

    try:
        val = cert_x509.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value

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
        found_oid = poid.lookup(policy_val.policy_identifier.dotted_string)
        if found_oid is None:
            print (f"{bcolors.FAIL}No OID found for DV, OV, EV{bcolors.ENDC}")
            sys.exit(1)
            return None

        print(found_oid)

        # OrderedDict([
        # ('oid', '0.4.0.1456.1.1'), ('owner', 'ETSI'),
        # ('customer', ''), ('short_name', 'etsi-qcp'), ('long_name', 'ETSI
        # Qualified Certificate Policy'), ('description', 'ETSI Qualified
        # Certificate Policy (QCP)'), ('tls_dv', ''), ('tls_ov', ''),
        # ('tls_ev', ''), ('tls_iv', ''), ('codesigning_ov', ''),
        # ('codesigning_ev', '')])


        if found_oid['tls_dv'] == 'TRUE':
            print (f"{bcolors.COLOR_DV}Domain Validated OID found{bcolors.ENDC}")
            return IDENTIFIED_TYPE_DV
        elif found_oid['tls_iv'] == 'TRUE':
            print (f"{bcolors.COLOR_IV}Individual Validated OID found{bcolors.ENDC}")
            return IDENTIFIED_TYPE_IV
        elif found_oid['tls_ov'] == 'TRUE':
            print (f"{bcolors.COLOR_OV}Organisation Validated OID found{bcolors.ENDC}")
            return IDENTIFIED_TYPE_OV
        elif found_oid['tls_ev'] == 'TRUE':
            print (f"{bcolors.COLOR_EV}Extended Validated OID found{bcolors.ENDC}")
            return IDENTIFIED_TYPE_EV
        elif found_oid['short_name'] == 'etsi-qcp-w':
            print (f"{bcolors.COLOR_QWAC}QWAC Web Validated OID found{bcolors.ENDC}")
            return IDENTIFIED_TYPE_QWAC

        elif OID_PSD2_WEB == policy_val.policy_identifier.dotted_string:
            print (f"{bcolors.COLOR_QWAC}PSD2 Web Validated OID found{bcolors.ENDC}")
            return IDENTIFIED_TYPE_PSD2


        if OID_CAB_FORUM_DV == policy_val.policy_identifier.dotted_string:
            print (f"{bcolors.COLOR_DV}Domain Validated OID found{bcolors.ENDC}")
            return IDENTIFIED_TYPE_DV
        elif OID_CAB_FORUM_OV == policy_val.policy_identifier.dotted_string:
            print (f"{bcolors.COLOR_OV}Organisation Validated OID found{bcolors.ENDC}")
            return IDENTIFIED_TYPE_OV
        elif OID_CAB_FORUM_IV == policy_val.policy_identifier.dotted_string:
            print (f"{bcolors.COLOR_IV}Individual Validated OID found{bcolors.ENDC}")
            return IDENTIFIED_TYPE_IV
        elif OID_CAB_FORUM_EV == policy_val.policy_identifier.dotted_string:
            print (f"{bcolors.COLOR_EV}Extended Validated OID found{bcolors.ENDC}")
            return IDENTIFIED_TYPE_EV
        elif OID_QWAC_WEB == policy_val.policy_identifier.dotted_string:
            print (f"{bcolors.COLOR_QWAC}QWAC Web Validated OID found{bcolors.ENDC}")
            return IDENTIFIED_TYPE_QWAC
        elif OID_PSD2_WEB == policy_val.policy_identifier.dotted_string:
            print (f"{bcolors.COLOR_QWAC}PSD2 Web Validated OID found{bcolors.ENDC}")
            return IDENTIFIED_TYPE_PSD2

        # QUOVADIS ROOT CA2
        # CERTIFICATE POLICY/CERTIFICATION PRACTICE STATEMENT
        # OID: 1.3.6.1.4.1.8024.0.2 Effective Date: May 27, 2014 Version: 1.15
        elif "1.3.6.1.4.1.8024.0.2.100.1.1" == policy_val.policy_identifier.dotted_string:
            print (f"{bcolors.COLOR_OV}Organisation Validated OID found - QUOVADIS ROOT CA{bcolors.ENDC}")
            return IDENTIFIED_TYPE_OV

    else:
        print (f"{bcolors.FAIL}No OID found for DV, OV, EV{bcolors.ENDC}")
        sys.exit(1)
        return None



def analyse(cert_pem):
    # Parse PEM into X.509 object
    cert_x509 = x509.load_pem_x509_certificate(bytes(cert_pem, 'utf-8'))

    info_cert(cert_x509)

    rc_analysis = test_OIDs(cert_x509)
    if rc_analysis is not None:
        return rc_analysis


def start_probe(host, port=443, timeout=5):
    cert_pem = get_certificate(host, port, timeout)
    if cert_pem is None:
        print(f"{bcolors.FAIL}Connection failed, no certificate to analyse{bcolors.ENDC}")
        return

    # Analyse the PEM formatted certificate from the peer
    return analyse(cert_pem)


def argparsing(exec_file):
    parser = argparse.ArgumentParser(exec_file)
    parser.add_argument("--oid",
                        dest='oid',
                        help="CSV file containing OIDs and specification.",
                        default=None,
                        type=str)
    parser.add_argument("-i",
                        dest='input',
                        help="Input file.",
                        default=None,
                        type=str)
    parser.add_argument("--fqdn",
                        dest='fqdn',
                        help="Target FQDN.",
                        default=None,
                        type=str)
    parser.add_argument("-lp",
                        dest='listening_port',
                        help="Listening port number.",
                        default=None,
                        type=int)
    parser.add_argument("-dp",
                        dest='destination_port',
                        help="Destination port number.",
                        default=443,
                        type=int)
    parser.add_argument("-t",
                        dest='timeout',
                        help="timeout in seconds.",
                        default=10,
                        type=int)

    args = parser.parse_args()
    return args


def assurance_to_str(code):
    if code == IDENTIFIED_TYPE_DV:
        return 'DV'
    elif code == IDENTIFIED_TYPE_OV:
        return 'OV'
    elif code == IDENTIFIED_TYPE_IV:
        return 'IV'
    elif code == IDENTIFIED_TYPE_EV:
        return 'EV'
    elif code == IDENTIFIED_TYPE_QWAC:
        return 'QWAC'
    elif code == IDENTIFIED_TYPE_PSD2:
        return 'PSD2'


def assurance_to_OID(code):
    if code == IDENTIFIED_TYPE_DV:
        return OID_CAB_FORUM_DV
    elif code == IDENTIFIED_TYPE_OV:
        return OID_CAB_FORUM_OV
    elif code == IDENTIFIED_TYPE_EV:
        return OID_CAB_FORUM_EV
    elif code == IDENTIFIED_TYPE_QWAC:
        return OID_QWAC_WEB
    elif code == IDENTIFIED_TYPE_PSD2:
        return OID_PSD2_WEB


@route('/certassurance/<fqdn>')
def serv_certassurance_with_param(fqdn):
    rc = start_probe(fqdn, 443)

    j = {}
    if rc is None:
        j['fqdn'] = fqdn
    else:
        j['fqdn'] = fqdn
        j['assurance'] = assurance_to_str(rc)

    from bottle import response
    response.content_type = 'application/json'
    return json.dumps(j)




### Main
if __name__ == "__main__":
    args = argparsing(os.path.basename(__file__))

    # Load OIDs
    if args.oid is None:
        print("Can't continue without OIDs")

    # Load OIDs to memory - global var
    poid = PolicyOID(args.oid)
    # poid.headers()

    # Launch a micro HTTP service
    if args.listening_port is not None:
        # Loop here endlessly
        run(host='0.0.0.0', port=args.listening_port)
        sys.exit(0)

    # Just one host by its FQDN
    if args.fqdn is not None:
        start_probe(args.fqdn, args.destination_port, args.timeout)
        sys.exit(0)

    # Process a list
    if args.input is None:
        print("No input file, use -i <file>")
        sys.exit(1)

    with open(args.input) as fp:
        lines = fp.readlines()
        for line in lines:
            print(f"{bcolors.HEADER}--- {line.strip()} ---{bcolors.ENDC}")
            start_probe(line.strip(), args.destination_port, args.timeout)


