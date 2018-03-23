from flask import current_app

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

import os
import subprocess
import tempfile

from lemur.plugins.bases import IssuerPlugin
from lemur.plugins import lemur_openssl_issuer
from lemur.common.utils import validate_conf, parse_certificate

from lemur.certificates.service import create_csr

openssl_cnf = """
[ ca ]
default_ca      = CA_default            # The default ca section

[ CA_default ]
dir            = ./              # top dir
database       = $dir/index.txt        # index file.
new_certs_dir  = $dir/newcerts         # new certs dir

certificate    = $dir/certs/ca.cert.pem       # The CA cert
serial         = $dir/serial           # serial no file
private_key    = $dir/private/ca.key.pem# CA private key
RANDFILE       = $dir/private/.rand    # random number file

default_days   = 365                   # how long to certify for
default_crl_days= 30                   # how long before next CRL
default_md     = md5                   # md to use

policy         = policy_any            # default policy
email_in_dn    = no                    # Don't add the email into cert DN

name_opt       = ca_default            # Subject name display option
cert_opt       = ca_default            # Certificate display option
copy_extensions = none                 # Don't copy extensions from request

[ policy_any ]
countryName            = supplied
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional
"""


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
    author_url = 'https://github.com/etnarek'

    def __init__(self, *args, **kwargs):
        required_vars = [
            'OPENSSL_DIR',
        ]

        validate_conf(current_app, required_vars)

        super(OpensslIssuerPlugin, self).__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        print("csr: ", csr)
        print("options: ", issuer_options)
        ca_name = issuer_options["authority"].name
        basedir = os.path.join(current_app.config.get("OPENSSL_DIR"), ca_name)

        f = tempfile.NamedTemporaryFile("w", delete=False)
        f.write(csr)
        f.close()
        subprocess.check_call(["/usr/bin/openssl", "ca",
                               "-batch",
                               "-config", "openssl.cnf",
                               "-in", f.name,
                               "-out", f.name + ".crt"], cwd=basedir)
        with open(f.name + ".crt") as crt:
            cert = crt.read()

        parsed_cert = parse_certificate(cert)

        return cert, issuer_options["authority"].authority_certificate.body, parsed_cert.serial_number

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