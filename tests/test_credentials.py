#!/usr/bin/env python3
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

import sys
import types
import unittest
import unittest.mock

from perceval.backend import Backend
from perceval.backends.core.github import GitHub
from perceval.backends.core.githubql import GitHubQL
from perceval.backends.core.gitlab import GitLab
from perceval.credentials import (CREDENTIAL_FIELDS,
                                  build_credential_manager,
                                  normalize_credentials,
                                  resolve_backend_credentials)


class SingleValueBackend(Backend):
    """Backend that accepts single values for its credentials"""


class ListValueBackend(Backend):
    """Backend that accepts a pool of API tokens"""

    CREDENTIAL_LIST_FIELDS = ('api_token',)


class TestBuildCredentialManager(unittest.TestCase):
    """Unit tests for build_credential_manager"""

    @unittest.mock.patch('grimoirelab_toolkit.credential_manager.bw_manager.BitwardenManager')
    def test_bitwarden(self, mock_bw):
        """Test whether a Bitwarden manager is built"""

        manager = build_credential_manager('bitwarden',
                                           bw_client_id='cid',
                                           bw_client_secret='csecret',
                                           bw_master_password='mpass',
                                           vault_url='http://vault')

        self.assertEqual(manager, mock_bw.return_value)
        mock_bw.assert_called_once_with('cid', 'csecret', 'mpass')

    def test_hashicorp(self):
        """Test whether a HashiCorp Vault manager is built"""

        # hvac is an optional dependency, so the module is replaced
        hc_module = types.ModuleType('grimoirelab_toolkit.credential_manager.hc_manager')
        hc_module.HashicorpManager = unittest.mock.MagicMock()

        with unittest.mock.patch.dict(sys.modules,
                                      {hc_module.__name__: hc_module}):
            manager = build_credential_manager('hashicorp',
                                               vault_url='http://vault',
                                               vault_token='token',
                                               vault_certificate='/ca.crt')

        self.assertEqual(manager, hc_module.HashicorpManager.return_value)
        hc_module.HashicorpManager.assert_called_once_with('http://vault', 'token', '/ca.crt')

    def test_bitwarden_missing_parameters(self):
        """Test whether it fails when Bitwarden parameters are missing"""

        with self.assertRaisesRegex(ValueError, 'Bitwarden requires'):
            build_credential_manager('bitwarden',
                                     bw_client_id='cid',
                                     bw_client_secret='csecret')

    def test_hashicorp_missing_parameters(self):
        """Test whether it fails when HashiCorp Vault parameters are missing"""

        with self.assertRaisesRegex(ValueError, 'HashiCorp Vault requires'):
            build_credential_manager('hashicorp', vault_url='http://vault')

    def test_unsupported_manager(self):
        """Test whether it fails with an unknown type of manager"""

        with self.assertRaisesRegex(ValueError, "Unsupported secrets manager: 'keepass'"):
            build_credential_manager('keepass')


class TestNormalizeCredentials(unittest.TestCase):
    """Unit tests for normalize_credentials"""

    def test_single_values(self):
        """Test whether single values are not modified"""

        credentials = {
            'user': 'alice',
            'password': 'pass,with\ncommas',
            'api_token': 'tok1'
        }

        result = normalize_credentials(SingleValueBackend, credentials)
        self.assertDictEqual(result, credentials)

    def test_single_value_from_list(self):
        """Test whether a list with one element is converted to that element"""

        result = normalize_credentials(SingleValueBackend, {'api_token': ['tok1']})
        self.assertDictEqual(result, {'api_token': 'tok1'})

    def test_multiple_values_for_single_value_field(self):
        """Test whether it fails when a single value field has several values"""

        with self.assertRaisesRegex(ValueError, "'api_token' must have a single value"):
            normalize_credentials(SingleValueBackend, {'api_token': ['tok1', 'tok2']})

    def test_list_from_string(self):
        """Test whether a string is converted to a list"""

        credentials = {
            'user': 'alice',
            'api_token': ' tok1,tok2\ntok3,\n'
        }

        result = normalize_credentials(ListValueBackend, credentials)
        self.assertDictEqual(result, {
            'user': 'alice',
            'api_token': ['tok1', 'tok2', 'tok3']
        })

    def test_list_from_list(self):
        """Test whether a list is kept as a list"""

        result = normalize_credentials(ListValueBackend, {'api_token': ['tok1', ' tok2 ', '']})
        self.assertDictEqual(result, {'api_token': ['tok1', 'tok2']})

    def test_input_not_modified(self):
        """Test whether the given credentials are not modified"""

        credentials = {'api_token': 'tok1,tok2'}

        normalize_credentials(ListValueBackend, credentials)
        self.assertDictEqual(credentials, {'api_token': 'tok1,tok2'})

    def test_backends_list_fields(self):
        """Test the credential fields that real backends accept as lists"""

        self.assertEqual(Backend.CREDENTIAL_LIST_FIELDS, ())
        self.assertEqual(GitHub.CREDENTIAL_LIST_FIELDS, ('api_token',))
        self.assertEqual(GitHubQL.CREDENTIAL_LIST_FIELDS, ('api_token',))
        self.assertEqual(GitLab.CREDENTIAL_LIST_FIELDS, ())

        result = normalize_credentials(GitLab, {'api_token': 'tok1'})
        self.assertDictEqual(result, {'api_token': 'tok1'})

        result = normalize_credentials(GitHub, {'api_token': 'tok1'})
        self.assertDictEqual(result, {'api_token': ['tok1']})


class TestResolveBackendCredentials(unittest.TestCase):
    """Unit tests for resolve_backend_credentials"""

    def test_resolve(self):
        """Test whether credentials are retrieved and normalized"""

        mock_manager = unittest.mock.MagicMock()
        mock_manager.resolve_credentials.return_value = {
            'user': 'alice',
            'api_token': 'tok1,tok2'
        }

        result = resolve_backend_credentials(ListValueBackend, mock_manager, 'my-item')

        self.assertDictEqual(result, {
            'user': 'alice',
            'api_token': ['tok1', 'tok2']
        })
        mock_manager.resolve_credentials.assert_called_once_with(
            secret_name='my-item',
            field_names=CREDENTIAL_FIELDS
        )


if __name__ == "__main__":
    unittest.main(warnings='ignore')
