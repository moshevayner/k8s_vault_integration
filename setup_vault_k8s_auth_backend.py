#!/usr/bin/env python

"""
Automatically create and configure an auth backend in Vault of type 'kubernetes'.
This enables the k8s-vault integration in an automated manner
"""

__author__ = 'Moshe Shitrit'
__creation_date__ = '5/2/18'

import requests
import json
from argparse import ArgumentParser

parser = ArgumentParser(description=__doc__)
parser.add_argument('--k8s_cluster_name', help='K8s Cluster name')
parser.add_argument('--k8s_namespace', help='Namespace in k8s in which the vault integration is needed. '
                                            'This will also be the name of the Vault role created for this integration')
parser.add_argument('--k8s_service_account', help='Name of the service account in K8s which will '
                                                  'be used for the integration. Defaults to vault-auth',
                    default='vault-auth')
parser.add_argument('--k8s_sa_jwt', help='K8s serviceAccount token in JWT format')
parser.add_argument('--k8s_api_url', help='URL To access K8S API')
parser.add_argument('--k8s_ca', help='K8S CA Cert')
parser.add_argument('--x_vault_token', help='Admin token to configure auth backend in Vault')
parser.add_argument('--vault_url', help='URL to Vault API, i.e.: http://vault:8200/v1/')
parser.add_argument('--vault_role_ttl',
                    help='TTL for tokens issued using provided role (in seconds)',
                    default='1800000')
parser.add_argument('--vault_policies', help='Comma-delimited list of policies in Vault to assign to this role, '
                                             'i.e: dev,prod (NO SPACES)')
parser.add_argument('--del_role', help='Remove the integration setup from Vault side ONLY for PROVIDED Namespace '
                                       '(The auth backend will remain enabled, only role will be deleted)',
                    action='store_true')
parser.add_argument('--remove', help='Remove the integration setup from Vault side for the entire K8s cluster',
                    action='store_true')
args = parser.parse_args()

# ================== END GLOBAL ================== #


def send_post(url, data, headers, return_output=False):
    """
    gets the below specified params, generated a POST request to provided url and either prints or returns the output

    :param url: URL to send the POST request to
    :param data: data (payload)
    :param headers: request headers to pass
    :param return_output: If True, the function will return the request output rather than print it
    :return: void
    """
    req = requests.post(url=url, data=json.dumps(data), headers=headers)
    if return_output:
        return req
    if str(req.status_code).startswith('2'):
        print 'SUCCESS! {0} {1} {2}'.format(req.status_code, req.reason, req.content)
    else:
        print 'FAIL! {0} {1} {2}'.format(req.status_code, req.reason, req.content)
        exit(77)


def send_delete(url, data={}, headers={}, return_output=False):
    """
    gets the below specified params, generated a DELETE request to provided url and either prints or returns the output

    :param url: URL to send the DELETE request to
    :param data: data (payload)
    :param headers: request headers to pass
    :param return_output: If True, the function will return the request output rather than print it
    :return: void
    """
    req = requests.delete(url=url, data=json.dumps(data), headers=headers)
    if return_output:
        return req
    if str(req.status_code).startswith('2'):
        print 'SUCCESS! {0} {1} {2}'.format(req.status_code, req.reason, req.content)
    else:
        print 'FAIL! {0} {1} {2}'.format(req.status_code, req.reason, req.content)
        exit(77)


def enable_auth_backend():
    """
    generates all the parameters for enabling auth backend API call, then calls send_post method with needed params
    :return: void
    """
    headers = {"X-Vault-Token": args.x_vault_token}
    data = {"type": "kubernetes"}
    url = "{0}/sys/auth/{1}".format(args.vault_url, args.k8s_cluster_name)
    print 'Enabling auth backend of type kubernetes for {0}'.format(args.k8s_cluster_name)
    req = send_post(url=url, data=data, headers=headers, return_output=True)
    if str(req.status_code).startswith('2'):
        print 'SUCCESS! {0} {1} {2}'.format(req.status_code, req.reason, req.content)
    else:
        if 'path is already in use' in req.content:
            print 'NOTE: Auth backend already enabled, which means the cluster is already setup on Vault.'
            print 'NOTE: Moving forward to Role creation, which is namespace-based'
        else:
            print 'FAIL! {0} {1} {2}'.format(req.status_code, req.reason, req.content)
            exit(77)


def remove_auth_backend():
    """
    generates all the parameters for removing the auth backend from provided k8s cluster,
    then calls the send_delete method with needed params to generate the API call to Vault
    :return: void
    """

    headers = {"X-Vault-Token": args.x_vault_token}
    url = "{0}/sys/auth/{1}".format(args.vault_url, args.k8s_cluster_name)
    print 'Disabling auth backend for cluster {0}'.format(args.k8s_cluster_name)
    send_delete(url=url, headers=headers)


def config_auth_backend():
    """
    generates all the parameters for configuring the newly created auth backend,
    then calls the send_post method with needed params to generate the API call to Vault
    :return: void
    """

    headers = {"X-Vault-Token": args.x_vault_token}
    data = {
        "kubernetes_host": args.k8s_api_url,
        "kubernetes_ca_cert": args.k8s_ca,
        "token_reviewer_jwt": args.k8s_sa_jwt
    }
    url = "{0}/auth/{1}/config".format(args.vault_url, args.k8s_cluster_name)
    print 'Configuring auth backend with k8s cluster information (api, host & jwt)'
    send_post(url=url, data=data, headers=headers)


def create_role():
    """
    generates all parameters needed to create a dedicated role in Vault for the newly created auth backend.
    then call the send_post method to generate the API call to Vault.
    :return:
    """
    headers = {"X-Vault-Token": args.x_vault_token}
    data = {
            "bound_service_account_names": args.k8s_service_account,
            "bound_service_account_namespaces": args.k8s_namespace,
            "policies": args.vault_policies.split(','),
            "ttl": args.vault_role_ttl
            }
    url = "{0}/auth/{1}/role/{2}".format(args.vault_url, args.k8s_cluster_name, args.k8s_namespace)
    print 'Creating role {0} for {1} with policies {2} and ttl {3}'.format(args.k8s_namespace,
                                                                           args.k8s_cluster_name,
                                                                           args.vault_policies,
                                                                           args.vault_role_ttl)
    send_post(url=url, data=data, headers=headers)


def remove_role():
    """
    generates all parameters needed to delete the dedicated role in Vault for the existing auth backend.
    then call the send_delete method to generate the API call to Vault.
    :return:
    """
    headers = {"X-Vault-Token": args.x_vault_token}
    url = "{0}/auth/{1}/role/{2}".format(args.vault_url, args.k8s_cluster_name, args.k8s_namespace)
    print 'Removing role {0} for {1}'.format(args.k8s_namespace, args.k8s_cluster_name)
    send_delete(url=url, headers=headers)


def test_login():
    """
    Generate a test login request to confirm that the integration is working
    :return: void
    """
    headers = {}
    data = {"role": args.k8s_namespace, "jwt": args.k8s_sa_jwt}
    url = "{0}/auth/{1}/login".format(args.vault_url, args.k8s_cluster_name)
    print "Testing login to confirm that the integration is working"
    req = send_post(url=url, data=data, headers=headers, return_output=True)
    if str(req.status_code).startswith('2'):
        print 'SUCCESS! Login request returned {0} {1}'.format(req.status_code, req.reason)
    else:
        print 'FAIL! {0} {1} {2}'.format(req.status_code, req.reason, req.content)
        exit(77)


def main():
    if args.del_role:
        remove_role()
    elif args.remove:
        remove_auth_backend()
    else:
        enable_auth_backend()
        config_auth_backend()
        create_role()
        test_login()


if __name__ == '__main__':
    main()
