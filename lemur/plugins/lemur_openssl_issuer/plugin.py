from flask import current_app

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

import os
import subprocess

from lemur.plugins.bases import IssuerPlugin
from lemur.plugins import lemur_openssl_issuer
from lemur.common.utils import validate_conf

from lemur.certificates.service import create_csr

def initialize_CA(basedir, serial_number):
    for sub_dir in ["certs", "crl", "newcerts", "private"]:
        path = os.path.join(basedir, sub_dir)
        os.makedirs(path, 0o700)

    with open(os.path.join(basedir, "serial"), "w") as f:
        f.write(str(serial_number))
    with open(os.path.join(basedir, "crlnumber"), "w") as f:
        f.write(str(serial_number))
    with open(os.path.join(basedir, "index.txt.attr"), "w") as f:
        f.write("unique_subject = no\n")
    open(os.path.join(basedir, "index.txt"), "w").close()

def generate_private_key(basedir, key_size):
    subprocess.check_call(["/usr/bin/openssl", "genrsa",
                           "-out", "private/ca.key.pem",
                           "{}".format(key_size)], cwd=basedir)
    subprocess.check_call(["chmod", "400", "private/ca.key.pem"], cwd=basedir)

def sign_root_CA(basedir, days, subj):
    subprocess.check_call(["/usr/bin/openssl", "req", "-batch",
                           "-key", "private/ca.key.pem",
                           "-new", "-x509", "-sha256",
                           "-days", "{}".format(days),
                           "-subj", subj,
                           "-out", "certs/ca.cert.pem"], cwd=basedir)

def update_crl(basedir):
    # TODO
    pass

SUBJECT = "/C={country}/ST={state}/L={location}/O={organization}/OU={organizational_unit}/emailAddress={owner}/CN={common_name}"
class OpensslIssuerPlugin(IssuerPlugin):
    title = 'Openssl issuer'
    slug = 'opensslIssuer'
    description = 'Use openssl as backend for the certificate cration.'
    version = lemur_openssl_issuer.VERSION

    author = 'Romain Fontaine'
    author_url = 'https://perdu.com'


    def __init__(self, *args, **kwargs):
        required_vars = [
            'OPENSSL_DIR',
        ]

        validate_conf(current_app, required_vars)

        super(OpensslIssuerPlugin, self).__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        # requests.get('a third party')
        pass

    def revoke_certificate(self, certificate, comments):
        # requests.put('a third party')
        pass

    def create_authority(self, options):
        print("options: ", options)
        print("path: ", current_app.config.get("OPENSSL_DIR"))
        basedir = os.path.join(current_app.config.get("OPENSSL_DIR"), options["name"])

        initialize_CA(basedir, options["first_serial"])

        key_size = int(options["key_type"].lstrip("RSA"))
        generate_private_key(basedir, key_size)

        subj = SUBJECT.format(**options)
        days = options["validity_end"] - options["validity_start"]
        days = days.days
        sign_root_CA(basedir, days, subj)

        update_crl(basedir)

        with open(os.path.join(basedir, "certs/ca.cert.pem")) as f:
            root_cert = f.read()

        role = dict(username="", password="", name='openssl')
        return root_cert, "", [role]
