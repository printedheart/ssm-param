#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os
import subprocess
import boto3


ssm = boto3.client('ssm')

LETSENCRYPT_ACCOUNT_KEY_PARAMSTORE_NAME = os.getenv(
        'LETSENCRYPT_ACCOUNT_KEY_PARAMSTORE_NAME',
        default='letsencrypt-account-key')
KMS_KEY_ID = os.getenv('KMS_KEY_ID')


def retrieve_account_key():
    """
    Returns the RSA private key from Parameter Store if it exists, None if not.
    """

    try:
        key = ssm.get_parameter(Name=LETSENCRYPT_ACCOUNT_KEY_PARAMSTORE_NAME,
                                WithDecryption=True)

        return key['Parameter']['Value']
    except Exception as ex:
        try:
            if ex.__dict__['response']['Error']['Code'] == 'ParameterNotFound':
                return None
        except KeyError:
            raise ex


def generate_account_key():
    """
    Generates a new 4096 bit RSA account key and stores it in Parameter Store.
    """

    process = subprocess.run(['openssl', 'genrsa', '4096'],
                             stdout=subprocess.PIPE)
    key = process.stdout.strip().decode('utf-8')

    ssm.put_parameter(
        Name=LETSENCRYPT_ACCOUNT_KEY_PARAMSTORE_NAME,
        Description='Let\'s Encrypt Account Key',
        Value=key,
        Type='SecureString',
        KeyId=KMS_KEY_ID
    )

    return key


def lambda_function(event=None, context=None):
    account_key = retrieve_account_key()

    if account_key is None:
        account_key = generate_account_key()
