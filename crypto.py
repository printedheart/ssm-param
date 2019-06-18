#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os
import re
import subprocess
import uuid
try:
    import OpenSSL as PyOpenSSL
    PyOpenSSL_AVAILABLE = True
except ImportError:
    PyOpenSSL_AVAILABLE = False


def generate_private_key(size='2048'):
    """
    Generates and returns a new private key
    """

    if size not in ['1024', '2048', '4096']:
        raise Exception(f'Invalid private key size {size}')

    if PyOpenSSL_AVAILABLE:
        private_key = PyOpenSSL.crypto.PKey()
        private_key.generate_key(PyOpenSSL.crypto.TYPE_RSA, int(size))

        return PyOpenSSL.crypto.dump_privatekey(
            PyOpenSSL.crypto.FILETYPE_PEM,
            private_key
        ).strip().decode('utf-8')
    else:
        process = subprocess.run(['openssl', 'genrsa', size],
                                 stdout=subprocess.PIPE)

        return process.stdout.strip().decode('utf-8')


def generate_certificate_request(domains, private_key, tmp_directory='/tmp'):
    """
    Generates a Certificate Signing Request for the given domains
    using the specified private key
    """

    if PyOpenSSL_AVAILABLE:
        key = PyOpenSSL.crypto.load_privatekey(PyOpenSSL.crypto.FILETYPE_PEM,
                                               private_key.encode('utf-8'))

        csr = PyOpenSSL.crypto.X509Req()

        if len(domains) == 0:
            raise Exception('At least one domain required')

        csr.get_subject().CN = domains[0]

        if len(domains) > 1:
            csr.add_extensions([
                PyOpenSSL.crypto.X509Extension(
                    'subjectAltName'.encode('utf-8'),
                    False,
                    ', '.join(
                        [f'DNS:{d}' for d in domains]
                    ).encode('utf-8')
                )
            ])

        csr.set_pubkey(key)
        csr.sign(key, 'sha256')

        certificate_request = PyOpenSSL.crypto.dump_certificate_request(
            PyOpenSSL.crypto.FILETYPE_PEM, csr).strip().decode('utf-8')
    else:
        temporary_certificate_request_path = f'{tmp_directory}/{uuid.uuid4()}'
        temporary_private_key_path = f'{tmp_directory}/{uuid.uuid4()}'
        temporary_openssl_config_path = f'{tmp_directory}/{uuid.uuid4()}'

        params = ['openssl', 'req', '-new', '-sha256',
                  '-key', temporary_private_key_path,
                  '-out', temporary_certificate_request_path,
                  '-config', temporary_openssl_config_path]

        if len(domains) == 1:
            config = """[req]
    distinguished_name = req_distinguished_name
    prompt             = no
    [req_distinguished_name]
    commonName = {domain}""".format(domain=domains[0])
        elif len(domains) > 1:
            config = """[req]
    distinguished_name = req_distinguished_name
    req_extensions = v3_req
    prompt             = no
    [req_distinguished_name]
    commonName = {first_domain}
    [ v3_req ]
    subjectAltName = {alt_names}""".format(
                    first_domain=domains[0],
                    alt_names=','.join([f'DNS:{name}' for name in domains]))
        else:
            raise Exception('At least one domain required')

        with open(temporary_openssl_config_path, 'w') as f:
            f.write(config)

        with open(temporary_private_key_path, 'w') as f:
            f.write(private_key)

        subprocess.run(params, stdout=subprocess.PIPE)

        os.remove(temporary_private_key_path)
        os.remove(temporary_openssl_config_path)

        with open(temporary_certificate_request_path) as f:
            certificate_request = f.read().strip()

        os.remove(temporary_certificate_request_path)

    return certificate_request


def parse_private_key(private_key):
    """
    Parse a private key and return the values of modulus and publicExponent
    """

    if PyOpenSSL_AVAILABLE:
        key = PyOpenSSL.crypto.load_privatekey(PyOpenSSL.crypto.FILETYPE_PEM,
                                               private_key.encode('utf-8'))
        out = PyOpenSSL.crypto.dump_privatekey(PyOpenSSL.crypto.FILETYPE_TEXT,
                                               key)
    else:
        process = subprocess.Popen(['openssl', 'rsa', '-in', '/dev/stdin',
                                    '-noout', '-text'], stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE)
        out, _ = process.communicate(f'{private_key}\n'.encode('utf-8'))

    modulus, exponent = re.search(
        r'modulus:\n\s+00:([a-f\d\:\s]+?)\npublicExponent: ([\d]+)',
        out.decode('utf-8'), re.MULTILINE | re.DOTALL
    ).groups()

    exponent = '{0:x}'.format(int(exponent))
    exponent = f'0{exponent}' if len(exponent) % 2 else exponent

    return modulus, exponent


def sign(private_key, data, tmp_directory='/tmp'):
    """
    Signs the provided the data with the private key. The private key is temporarily written to a temporary directory which can
    be specified (default is /tmp) for the duration of the call to openssl dgst.
    """

    if PyOpenSSL_AVAILABLE:
        key = PyOpenSSL.crypto.load_privatekey(PyOpenSSL.crypto.FILETYPE_PEM, private_key)
        return PyOpenSSL.crypto.sign(key, data, 'sha256')
    else:
        temp_id = uuid.uuid4()

        with open(f'{tmp_directory}/{temp_id}', 'w') as f:
            f.write(private_key)

        process = subprocess.Popen(['openssl', 'dgst', '-sha256', '-sign',
                                    f'{tmp_directory}/{temp_id}'],
                                   stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE)

        out, _ = process.communicate(f'{data}'.encode('utf-8'))

        os.remove(f'{tmp_directory}/{temp_id}')

        return out


def der_encode_csr(certificate_request):
    """
    DER-encodes the provided Certificate Signing Request
    """

    if PyOpenSSL_AVAILABLE:
        csr = PyOpenSSL.crypto.load_certificate_request(
            PyOpenSSL.crypto.FILETYPE_PEM,
            certificate_request
        )

        return PyOpenSSL.crypto.dump_certificate_request(
            PyOpenSSL.crypto.FILETYPE_ASN1,
            csr
        )
    else:
        process = subprocess.Popen(['openssl', 'req', '-in', '/dev/stdin',
                                    '-outform', 'DER'],
                                   stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE)

        out, _ = process.communicate(f'{certificate_request}'.encode('utf-8'))

        return out
