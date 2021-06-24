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
pcapyplus module entry point.
"""

from ._pcapyplus import (
    open_live,
    open_offline,
    findalldevs,
    compile,
    create,
)

__author__ = 'Hewlett Packard Enterprise Development LP'
__email__ = 'sdk_tools_frameworks@groups.ext.hpe.com'
__version__ = '0.1.0'


def lookupdev():
    """
    Compatibility function, as the original libpcap function was deprecated.

    Notes from libpcap:

        We're deprecating pcap_lookupdev() for various reasons (not
        thread-safe, can behave weirdly with WinPcap).
        Callers should use pcap_findalldevs() and use the first device.
    """
    return findalldevs()[0]


__all__ = [
    'open_live',
    'open_offline',
    'lookupdev',
    'findalldevs',
    'compile',
    'create',
]
