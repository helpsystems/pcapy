# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Hewlett Packard Enterprise Development LP.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.


"""
Tests to check valid package version.
"""

from packaging import version

from pcapyplus import __version__


def test_version():
    """
    Check that version is PEP 440 compliant.

        https://www.python.org/dev/peps/pep-0440/

    This is basically the basic test to bootstrap a pytest testing suite.
    """
    assert version.parse(__version__) >= version.parse('0.1.0')
