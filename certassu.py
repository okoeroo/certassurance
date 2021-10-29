#!/usr/bin/env python3

from bottle import route, run, template

import signal
import sqlite3

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


def handler(signum, frame):
    msg = "Ctrl-c was pressed."
    print(msg, flush=True)
    print("")
    exit(signum)


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


class Database():
    def __init__(self, path):
        self.con = sqlite3.connect(path)
        self.cur = self.con.cursor()

        self.cur.execute('''CREATE TABLE IF NOT EXISTS cache
                            (fqdn text, type text, status text)''')

        self.cur.execute('''CREATE UNIQUE INDEX IF NOT EXISTS idx_cache_fqdn ON cache (fqdn)''')

    def lookup(self, fqdn):
        sql = " ".join(["SELECT fqdn, type, status",
                          "FROM cache",
                         "WHERE fqdn = ?"])
        self.cur.execute(sql, (fqdn,))

        row = self.cur.fetchone()
        if row is None:
            return None

        j = row[2]
        return json.loads(j)

    def add(self, fqdn, certtype, obj_oid_rc):
        try:
            sql = '''INSERT INTO cache(fqdn, type, status) VALUES (?, ?, ?)'''
            self.cur.execute(sql, (fqdn, certtype, json.dumps(obj_oid_rc)))
            self.con.commit()
        except:
            pass


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
    print("Issuer:", cert_x509.issuer.rfc4514_string())
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
            continue

        # OrderedDict([
        # ('oid', '0.4.0.1456.1.1'), ('owner', 'ETSI'),
        # ('customer', ''), ('short_name', 'etsi-qcp'), ('long_name', 'ETSI
        # Qualified Certificate Policy'), ('description', 'ETSI Qualified
        # Certificate Policy (QCP)'), ('tls_dv', ''), ('tls_ov', ''),
        # ('tls_ev', ''), ('tls_iv', ''), ('codesigning_ov', ''),
        # ('codesigning_ev', '')])


        if found_oid['tls_dv'] == 'TRUE':
            print (f"{bcolors.COLOR_DV}Domain Validated OID found{bcolors.ENDC}")
            found_oid['type'] = 'DV'
        elif found_oid['tls_iv'] == 'TRUE':
            print (f"{bcolors.COLOR_IV}Individual Validated OID found{bcolors.ENDC}")
            found_oid['type'] = 'IV'
        elif found_oid['tls_ov'] == 'TRUE':
            print (f"{bcolors.COLOR_OV}Organisation Validated OID found{bcolors.ENDC}")
            found_oid['type'] = 'OV'
        elif found_oid['tls_ev'] == 'TRUE':
            print (f"{bcolors.COLOR_EV}Extended Validated OID found{bcolors.ENDC}")
            found_oid['type'] = 'EV'

        elif found_oid['short_name'] == 'etsi-qcp-w':
            print (f"{bcolors.COLOR_QWAC}QWAC Web Validated OID found{bcolors.ENDC}")
            found_oid['type'] = 'QWAC'


        # PSD special
        elif OID_PSD2_WEB == policy_val.policy_identifier.dotted_string:
            print (f"{bcolors.COLOR_QWAC}PSD2 Web Validated OID found{bcolors.ENDC}")
            found_oid['type'] = 'PSD2'

        else:
            # Loop
            continue

        # Return that OID row
        return found_oid

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
    parser.add_argument("--dbfile",
                        dest='db_file',
                        help="Sqlite database file path.",
                        default='cache.db',
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
    found_oid = start_probe(fqdn, 443)
    if found_oid is None:
        db.add(fqdn, "NONE", "error")
    else:
        db.add(fqdn, found_oid['type'], found_oid)

    j = {}
    if found_oid is None:
        j['fqdn'] = fqdn
        j['error'] = "nothing found"
    else:
        j['fqdn'] = fqdn
        j['assurance'] = found_oid

    from bottle import response
    response.content_type = 'application/json'
    return json.dumps(j)



### Main
if __name__ == "__main__":
    # Add signal handler
    signal.signal(signal.SIGINT, handler)

    # Arguments parsing
    args = argparsing(os.path.basename(__file__))

    # Lock and loading the database
    db = Database(args.db_file)

    # Load OIDs
    if args.oid is None:
        print("Can't continue without OIDs")

    # Load OIDs to memory - global var
    poid = PolicyOID(args.oid)

    # Launch a micro HTTP service
    if args.listening_port is not None:
        # Loop here endlessly
        run(host='0.0.0.0', port=args.listening_port)
        sys.exit(0)

    # Just one host by its FQDN
    if args.fqdn is not None:
        # Lookup in cache, if enabled
        found_oid = db.lookup(args.fqdn)
        if found_oid is None:
            # Probe host
            found_oid = start_probe(args.fqdn, args.destination_port, args.timeout)
            if found_oid is None:
                db.add(args.fqdn, "NONE", "error")
            else:
                db.add(args.fqdn, found_oid['type'], found_oid)
        else:
            print(found_oid)

        sys.exit(0)

    # Process a list
    if args.input is None:
        print("No input file, use -i <file>")
        sys.exit(1)

    with open(args.input) as fp:
        lines = fp.readlines()
        for line in lines:
            fqdn = line.strip()
            print(f"{bcolors.HEADER}--- {line.strip()} ---{bcolors.ENDC}")
            found_oid = db.lookup(fqdn)
            if found_oid:
                print("Found in cache.")
                print(found_oid)
            else:
                found_oid = start_probe(fqdn, args.destination_port, args.timeout)
                if found_oid is None:
                    db.add(fqdn, "NONE", "error")
                else:
                    db.add(fqdn, found_oid['type'], found_oid)


