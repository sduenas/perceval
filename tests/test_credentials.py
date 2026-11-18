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

import unittest

from perceval.backend import Backend
from perceval.backends.core.github import GitHub
from perceval.backends.core.githubql import GitHubQL
from perceval.backends.core.gitlab import GitLab
from perceval.credentials import normalize_credentials


class SingleValueBackend(Backend):
    """Backend that accepts single values for its credentials"""


class ListValueBackend(Backend):
    """Backend that accepts a pool of API tokens"""

    CREDENTIAL_LIST_FIELDS = ('api_token',)


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


if __name__ == "__main__":
    unittest.main(warnings='ignore')
