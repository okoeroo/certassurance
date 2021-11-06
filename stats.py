#!/usr/bin/env python3

import matplotlib
import matplotlib.pyplot as plt
import pandas as pd

from collections import Counter
import numpy as np

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
    def __init__(self, db_path=None):
        if db_path:
            self.db_path = db_path
        else:
            self.db_path = ":memory:"


        self.con = sqlite3.connect(self.db_path)
        self.cur = self.con.cursor()


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
            # print(oid, owner, customer, short_name)
            # print(e)
            pass

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

    def lookup_fqdn_long(self, fqdn):
        sql = " ".join(["SELECT fqdn, type, status",
                          "FROM cache",
                         "WHERE fqdn = ?"])
        self.cur.execute(sql, (fqdn,))

        row = self.cur.fetchone()
        if row is None:
            return None

        j = {}
        j['fqdn']   = row[0]
        j['type']   = row[1]
        j['status'] = row[2]

        return j


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


def argparsing(exec_file):
    parser = argparse.ArgumentParser(exec_file)
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
    parser.add_argument("--bar-file",
                        dest="barfiles",
                        help="Input files.",
                        action='append',
                        type=str)
    parser.add_argument("--bar-name",
                        dest="barnames",
                        help="Bar name.",
                        action='append',
                        type=str)
    parser.add_argument("--bar-xlim-low",
                        dest="xlimlow",
                        help="Bar x-axis limit - low end.",
                        default=None,
                        type=int)
    parser.add_argument("--bar-xlim-high",
                        dest="xlimhigh",
                        help="Bar x-axis limit - high end.",
                        default=None,
                        type=int)
    parser.add_argument("--bar-ylim-low",
                        dest="ylimlow",
                        help="Bar y-axis limit - low end.",
                        default=None,
                        type=int)
    parser.add_argument("--bar-ylim-high",
                        dest="ylimhigh",
                        help="Bar y-axis limit - high end.",
                        default=None,
                        type=int)
    parser.add_argument("--title",
                        dest='title',
                        help="Title of plot.",
                        default=None,
                        type=str)
    parser.add_argument("--plot",
                        dest='plot_file',
                        help="Output file of the plot (in PNG format).",
                        default='plot.png',
                        type=str)
    parser.add_argument("--fqdn",
                        dest='fqdn',
                        help="Target FQDN.",
                        default=None,
                        type=str)

    args = parser.parse_args()
    return args


def plot(args, bars_data):
    cnt_data = {}

    for key, cache in bars_data.items():

        d = { 'DV': 0, 'IV': 0, 'OV': 0, 'EV': 0, 'QWAC': 0, 'PSD2': 0 }

        for i in cache:
            if i['type'] == 'DV':
                d['DV'] += 1
            if i['type'] == 'IV':
                d['IV'] += 1
            if i['type'] == 'OV':
                d['OV'] += 1
            if i['type'] == 'EV':
                d['EV'] += 1
            if i['type'] == 'QWAC':
                d['QWAC'] += 1
            if i['type'] == 'PSD2':
                d['PSD2'] += 1

        cnt_data[key] = list([d['DV'], d['IV'], d['OV'], d['EV'], d['QWAC'], d['PSD2']])

    names = list(['DV', 'IV', 'OV', 'EV', 'QWAC', 'PSD2'])

    labels = ['DV', 'IV', 'OV', 'EV', 'QWAC', 'PSD2']


    # creating dataframe
    df = pd.DataFrame(cnt_data, index=labels)

    #matplotlib.style.use('fivethirtyeight') 
    ax = df.plot(kind="bar")
    for container in ax.containers:
        ax.bar_label(container, rotation=90, padding=3)


    plt.xticks(rotation=90, horizontalalignment="center")
    plt.title("Distribution of certificate types")
    plt.xlabel("Certificate types")
    plt.ylabel("Detected")

    # HACK
    if args.ylimhigh is not None:
        if args.ylimlow is not None:
            plt.ylim([args.ylimlow, args.ylimhigh])
        else:
            plt.ylim([0, args.ylimhigh])

    # HACK
    if args.xlimhigh is not None:
        if args.xlimlow is not None:
            plt.xlim([args.xlimlow, args.xlimhigh])
        else:
            plt.xlim([0, args.xlimhigh])

    plt.savefig(args.plot_file)



def stats_from_file(args):
    bars = dict(zip(args.barnames, args.barfiles))

    bars_data = {}

    for key, filename in bars.items():
        cache = []

        with open(filename) as fp:
            lines = fp.readlines()
            for line in lines:
                fqdn = line.strip()

                found_fqdn = db.lookup_fqdn_long(fqdn)
                if found_fqdn:
                    cache.append(found_fqdn)

        bars_data[key] = cache

    plot(args, bars_data)

#    pp = pprint.PrettyPrinter(indent=4)
#    pp.pprint(cache)


### Main
if __name__ == "__main__":
    # Add signal handler
    signal.signal(signal.SIGINT, handler)

    # Arguments parsing
    args = argparsing(os.path.basename(__file__))


    # Lock and loading the database
    db = Database(args.db_file)

    # Just one host by its FQDN
    if args.fqdn is not None:
        print(f"{bcolors.HEADER}--- {args.fqdn} ---{bcolors.ENDC}")

        # Lookup in cache, if enabled
        found_oid = db.lookup_fqdn(args.fqdn)
        if not found_oid:
            print("Not found in DB")
        else:
            print(json.dumps(found_oid))

        sys.exit(0)

    # Process a list
    if not args.input and not args.barfiles:
        print("No input file, use -i <file> or --bar-file")
        sys.exit(1)

    else:
        stats_from_file(args)
        sys.exit(0)

