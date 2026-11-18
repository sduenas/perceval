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

LIST_SEPARATORS = re.compile(r'[,\n]')


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
