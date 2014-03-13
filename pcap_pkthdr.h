/*
 * Copyright (c) 2014 CORE Security Technologies
 *
 * This software is provided under under a slightly modified version
 * of the Apache Software License. See the accompanying LICENSE file
 * for more information.
 *
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
