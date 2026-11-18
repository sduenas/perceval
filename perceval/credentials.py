# -*- coding: utf-8 -*-
#
# Copyright (C) GrimoireLab Contributors
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import re


CREDENTIAL_FIELDS = ['user', 'password', 'api_token', 'email',
                     'access_token', 'user_id']
"""Fields Perceval looks up in a secret of a credential manager."""

SECRETS_MANAGERS = ['bitwarden', 'hashicorp']
"""Credential managers supported by Perceval."""

LIST_SEPARATORS = re.compile(r'[,\n]')


def build_credential_manager(manager_type, bw_client_id=None,
                             bw_client_secret=None, bw_master_password=None,
                             vault_url=None, vault_token=None,
                             vault_certificate=None):
    """Build a credential manager.

    Create a credential manager instance of the given type to
    retrieve credentials. Each type of manager requires its own
    set of parameters to access the service. Bitwarden requires
    `bw_client_id`, `bw_client_secret` and `bw_master_password`;
    HashiCorp Vault (or any Vault compatible service, like OpenBao)
    requires `vault_url` and `vault_token`.

    :param manager_type: type of the manager; one of `SECRETS_MANAGERS`
    :param bw_client_id: Bitwarden API client ID
    :param bw_client_secret: Bitwarden API client secret
    :param bw_master_password: Bitwarden master password
    :param vault_url: URL of the Vault server
    :param vault_token: token to authenticate in the Vault server
    :param vault_certificate: path to the CA certificate to verify
        the TLS connection with the Vault server

    :returns: a credential manager instance

    :raises ValueError: when the type of manager is not supported
        or any of its required parameters is missing
    """
    if manager_type == 'bitwarden':
        if not all([bw_client_id, bw_client_secret, bw_master_password]):
            raise ValueError(
                'Bitwarden requires client id, client secret, and master password'
            )

        from grimoirelab_toolkit.credential_manager.bw_manager import BitwardenManager
        return BitwardenManager(bw_client_id, bw_client_secret, bw_master_password)
    elif manager_type == 'hashicorp':
        if not all([vault_url, vault_token]):
            raise ValueError('HashiCorp Vault requires url and token')

        from grimoirelab_toolkit.credential_manager.hc_manager import HashicorpManager
        return HashicorpManager(vault_url, vault_token, vault_certificate)

    raise ValueError(f"Unsupported secrets manager: '{manager_type}'")


def resolve_backend_credentials(backend_class, manager, secret_name):
    """Retrieve the credentials of a backend from a credential manager.

    Read the secret `secret_name` from the credential manager and
    extract the credential fields that Perceval knows about (see
    `CREDENTIAL_FIELDS`). The values are adapted to the type
    of parameter each backend expects (see `normalize_credentials`).

    :param backend_class: backend class that will use the credentials
    :param manager: credential manager instance
    :param secret_name: name of the secret in the credential manager

    :returns: a dict with the credentials found in the secret

    :raises ValueError: when `secret_name` is empty or the secret
        contains several values for a field that the backend
        only accepts as a single value
    """
    credentials = manager.resolve_credentials(
        secret_name=secret_name,
        field_names=CREDENTIAL_FIELDS,
    )
    return normalize_credentials(backend_class, credentials)


def normalize_credentials(backend_class, credentials):
    """Adapt the values of the credentials to a backend.

    Fields listed in the backend's `CREDENTIAL_LIST_FIELDS` (e.g.
    the pool of API tokens of GitHub) are converted into lists.
    Values for these fields can be lists or strings with the
    elements separated by commas or new lines.

    Any other field must have a single value. A list with only
    one element is converted to that element.

    :param backend_class: backend class that will use the credentials
    :param credentials: dict with the credentials

    :returns: a new dict with the normalized credentials

    :raises ValueError: when a field that only accepts a single value
        has several values
    """
    list_fields = getattr(backend_class, 'CREDENTIAL_LIST_FIELDS', ())
    normalized = {}

    for name, value in credentials.items():
        if name in list_fields:
            values = value if isinstance(value, list) else LIST_SEPARATORS.split(value)
            normalized[name] = [v.strip() for v in values if v and v.strip()]
        elif isinstance(value, list):
            if len(value) != 1:
                msg = (
                    f"'{name}' must have a single value; "
                    f"{backend_class.__name__} does not support multiple values"
                )
                raise ValueError(msg)
            normalized[name] = value[0]
        else:
            normalized[name] = value

    return normalized
