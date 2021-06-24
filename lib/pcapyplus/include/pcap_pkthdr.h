/*
 * Copyright (C) 2014-2021 CORE Security Technologies
 * Copyright (C) 2021 Hewlett Packard Enterprise Development LP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

#ifndef __pcap_pkthdr__
#define __pcap_pkthdr__

#include <pcap.h>

PyObject*
new_pcap_pkthdr(const struct pcap_pkthdr* hdr);
int
pkthdr_to_native(PyObject *pyhdr, struct pcap_pkthdr *hdr);

extern PyTypeObject Pkthdr_type;

#endif // __pcap_pkthdr__
