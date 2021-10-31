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
import pprint
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
OID_QWAC_WEB    = "0.4.0.194112.1.4"
OID_PSD2_WEB    = "0.4.0.19495.3.1"


def handler(signum, frame):
    msg = "Ctrl-c was pressed."
    print(msg, flush=True)
    print("")
    sys.exit(signum)



class Database():
    def setup_cache(self):
        self.cur.execute('''CREATE TABLE IF NOT EXISTS cache
                            (fqdn text, type text, status text)''')

        self.cur.execute('''CREATE UNIQUE INDEX IF NOT EXISTS
                            idx_cache_fqdn ON cache (fqdn)''')

    def setup_certificate_policies(self):
        self.cur.execute('''CREATE TABLE IF NOT EXISTS certificate_policies
                            (oid text, owner text, customer text, short_name text, 
                            long_name text, description text, tls_dv text, 
                            tls_ov text, tls_ev text, tls_iv text, codesigning_ov text, 
                            codesigning_ev text, tls_qwac text, tls_psd2 text)''')

        self.cur.execute('''CREATE UNIQUE INDEX IF NOT EXISTS 
                            idx_certificate_policies_oid ON certificate_policies (oid)''')


    def __init__(self, db_path=None, cert_policy_oid_csv_path=None):
        if db_path:
            self.db_path = db_path
        else:
            self.db_path = ":memory:"


        self.con = sqlite3.connect(self.db_path)
        self.cur = self.con.cursor()

        # DB setup
        self.setup_cache()
        self.setup_certificate_policies()


        with open(cert_policy_oid_csv_path, "r") as f:
            self.stream = io.StringIO(f.read())

        reader = csv.DictReader(self.stream)

        # OrderedDict([
        # ('oid', '0.4.0.1456.1.1'), ('owner', 'ETSI'),
        # ('customer', ''), ('short_name', 'etsi-qcp'), ('long_name', 'ETSI
        # Qualified Certificate Policy'), ('description', 'ETSI Qualified
        # Certificate Policy (QCP)'), ('tls_dv', ''), ('tls_ov', ''),
        # ('tls_ev', ''), ('tls_iv', ''), ('codesigning_ov', ''),
        # ('codesigning_ev', '')])

        for row in reader:
            # QWAC Web detected
            if row['oid'] == OID_QWAC_WEB:
                self.add_policy_oid(row['oid'], row['owner'], row['customer'], row['short_name'],
                                    row['long_name'], row['description'], row['tls_dv'], row['tls_ov'], row['tls_ev'], row['tls_iv'],
                                    row['codesigning_ov'], row['codesigning_ev'], "TRUE", "FALSE")
            # PSD2 detected
            elif row['oid'] == OID_PSD2_WEB:
                self.add_policy_oid(row['oid'], row['owner'], row['customer'], row['short_name'],
                                    row['long_name'], row['description'], row['tls_dv'], row['tls_ov'], row['tls_ev'], row['tls_iv'],
                                    row['codesigning_ov'], row['codesigning_ev'], "FALSE", "TRUE")
            # CORRECTION on OID
            elif row['oid'] == OID_PSD2_WEB:
                self.add_policy_oid(row['oid'], row['owner'], row['customer'], row['short_name'],
                                    row['long_name'], row['description'], row['tls_dv'], row['tls_ov'], row['tls_ev'], row['tls_iv'],
                                    row['codesigning_ov'], row['codesigning_ev'], "FALSE", "TRUE")
            # Reasonably normal policies
            else:
                self.add_policy_oid(row['oid'], row['owner'], row['customer'], row['short_name'],
                                    row['long_name'], row['description'], row['tls_dv'], row['tls_ov'], row['tls_ev'], row['tls_iv'],
                                    row['codesigning_ov'], row['codesigning_ev'], "FALSE", "FALSE")
        else:
            return None

    def add_policy_oid(self, oid, owner, customer, short_name,
                             long_name, description, tls_dv, tls_ov, tls_ev, tls_iv,
                             codesigning_ov, codesigning_ev, tls_qwac, tls_psd2):
        try:
            sql = " ".join(["INSERT INTO certificate_policies",
                            "(oid, owner, customer, short_name,",
                            "long_name, description, tls_dv, tls_ov, tls_ev, tls_iv,",
                            "codesigning_ov, codesigning_ev, tls_qwac, tls_psd2)",
                            "VALUES",
                            "(?, ?, ?, ?,",
                            "?, ?, ?, ?, ?, ?,",
                            "?, ?, ?, ?)"
                            ])


            self.cur.execute(sql, (oid, owner, customer, short_name,
                                    long_name, description, tls_dv, tls_ov, tls_ev, tls_iv,
                                    codesigning_ov, codesigning_ev, tls_qwac, tls_psd2))
            self.con.commit()
        except Exception as e:
            print(oid, owner, customer, short_name)
            print(e)
            # pass

    def lookup_policy_oid(self, oid):
        # print(f"looking up: \"{oid}\"")
        sql = " ".join(["SELECT oid, owner, customer, short_name,",
                              " long_name, description, tls_dv, tls_ov, tls_ev, tls_iv,",
                              " codesigning_ov, codesigning_ev, tls_qwac, tls_psd2",
                          "FROM certificate_policies",
                         "WHERE oid = ?"])

        self.cur.execute(sql, (oid,))
        # print(sql, oid)

        row = self.cur.fetchone()
        # print(row)

        if not row:
            print("OID", oid, "not found in db")
            return None

        p = {}
        p['oid'] = row[0]
        p['owner']  = row[1]
        p['customer'] = row[2]
        p['short_name'] = row[3]
        p['long_name'] = row[4]
        p['description'] = row[5]
        p['tls_dv'] = row[6]
        p['tls_ov'] = row[7]
        p['tls_ev'] = row[8]
        p['tls_iv'] = row[9]
        p['codesigning_ov'] = row[10]
        p['codesigning_ev'] = row[11]
        p['tls_qwac'] = row[12]
        p['tls_psd2'] = row[13]

        # pp = pprint.PrettyPrinter(indent=4)
        # pp.pprint(p)

        return p


    def lookup_fqdn(self, fqdn):
        sql = " ".join(["SELECT fqdn, type, status",
                          "FROM cache",
                         "WHERE fqdn = ?"])
        self.cur.execute(sql, (fqdn,))

        row = self.cur.fetchone()
        if row is None:
            return None

        j = row[2]
        return json.loads(j)

    def add_fqdn(self, fqdn, certtype, obj_oid_rc):
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
    try:
        val = cert_x509.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value

    except x509.ExtensionNotFound:
        print("Extension Not Found")
        return None

    # Test
    for policy_val in val:
        pol_val_policy_identifier_dotter_str = str(policy_val.policy_identifier.dotted_string)
        output = 'OID %s: ' % pol_val_policy_identifier_dotter_str

        if policy_val.policy_qualifiers is not None:
            p_qualifiers = [p_q for p_q in policy_val.policy_qualifiers]
        else:
            p_qualifiers = None


        found_oid = db.lookup_policy_oid(pol_val_policy_identifier_dotter_str)
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
    print(f"{bcolors.HEADER}--- {fqdn} ---{bcolors.ENDC}")
    found_oid = start_probe(fqdn, 443)
    if found_oid is None:
        db.add_fqdn(fqdn, "NONE", "error")
    else:
        db.add_fqdn(fqdn, found_oid['type'], found_oid)

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

    # Load OIDs
    if args.oid is None:
        print("Can't continue without OIDs")

    # Lock and loading the database
    db = Database(args.db_file, args.oid)

    # Load OIDs to memory - global var
    # poid = PolicyOID(args.oid)

    # Launch a micro HTTP service
    if args.listening_port is not None:
        # Loop here endlessly
        run(host='0.0.0.0', port=args.listening_port)
        sys.exit(0)

    # Just one host by its FQDN
    if args.fqdn is not None:
        print(f"{bcolors.HEADER}--- {args.fqdn} ---{bcolors.ENDC}")

        # Lookup in cache, if enabled
        found_oid = db.lookup_fqdn(args.fqdn)
        if found_oid is None:
            # Probe host
            found_oid = start_probe(args.fqdn, args.destination_port, args.timeout)
            if found_oid is None:
                db.add_fqdn(args.fqdn, "NONE", "error")
            else:
                db.add_fqdn(args.fqdn, found_oid['type'], found_oid)
        else:
            print(json.dumps(found_oid))

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
            found_oid = db.lookup_fqdn(fqdn)
            if found_oid:
                print("Found in cache.")
                print(json.dumps(found_oid))
            else:
                found_oid = start_probe(fqdn, args.destination_port, args.timeout)
                if found_oid is None:
                    db.add_fqdn(fqdn, "NONE", "error")
                else:
                    db.add_fqdn(fqdn, found_oid['type'], found_oid)


