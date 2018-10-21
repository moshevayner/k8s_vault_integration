#!/usr/bin/env python

""" Perform initial vault login using k8s SA token in order to generate a client token """

__author__ = 'Moshe Shitrit'
__creation_date__ = '9/12/18'

import os
import json
import requests
import logging
import sys
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

print """
 ___ ___                __  __        _______         __                       _______                                    __                
|   |   |.---.-..--.--.|  ||  |_     |_     _|.-----.|  |--..-----..-----.    |     __|.-----..-----..-----..----..---.-.|  |_ .-----..----.
|   |   ||  _  ||  |  ||  ||   _|      |   |  |  _  ||    < |  -__||     |    |    |  ||  -__||     ||  -__||   _||  _  ||   _||  _  ||   _|
 \_____/ |___._||_____||__||____|      |___|  |_____||__|__||_____||__|__|    |_______||_____||__|__||_____||__|  |___._||____||_____||__|  
                                                                                                                                            

"""

root = logging.getLogger()
root.setLevel(logging.DEBUG)

VERSION = '1.0'
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
root.addHandler(ch)

expected_vars = ['VAULT_ADDR', 'VAULT_ROLE', 'VAULT_K8S_MOUNT_PATH']
root.info(msg='Image version={}'.format(VERSION))
root.info(msg='Verifying all expected variables exist: {}'.format(expected_vars))
for v in expected_vars:
    if not os.getenv(v):
        root.critical(msg="{} environment variable is NOT SET!".format(v))
        exit(77)
    else:
        root.debug(msg='{} environment variable is set with value {}'.format(v, os.getenv(v)))
TOKEN_PATH = os.getenv('TOKEN_PATH', '/var/secrets')
TOKEN_FILE = '{}/vault_access_token'.format(TOKEN_PATH)

# ================== END GLOBAL ================== #


def retry_session(retries, session=None, backoff_factor=0.3, status_forcelist=(500, 502, 503, 504)):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        method_whitelist=['HEAD', 'TRACE', 'GET', 'PUT', 'OPTIONS', 'DELETE', 'POST'],
        raise_on_status=False
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def get_vault_token():
    """
    Initiate the Vault login flow using provided environment variables
    :return: void
    """
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token') as sa_token:
        data = {
            "jwt": sa_token.readline().rstrip(),
            "role": os.getenv("VAULT_ROLE")
        }
    root.debug(msg="Payload: {}".format(data))
    url = "{0}/v1/auth/{1}/login".format(os.getenv('VAULT_ADDR'), os.getenv('VAULT_K8S_MOUNT_PATH'))
    root.debug(msg="URL: {}".format(url))
    session = retry_session(retries=5)
    response = session.post(url=url, data=json.dumps(data), headers={})
    if response.status_code != 200:
        root.critical(msg="Vault login failed with error {0} ({1}, {2})".format(response.status_code,
                                                                                response.reason,
                                                                                response.text.rstrip()))
    else:
        root.info(msg="Vault login succeeded. Access token will be written to {}".format(TOKEN_FILE))
        with open(TOKEN_FILE, 'w') as tf:
            tf.write(json.loads(response.text)['auth']['client_token'])


def main():
    get_vault_token()


if __name__ == '__main__':
    main()
