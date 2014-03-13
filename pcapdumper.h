/*
 * Copyright (c) 2014 CORE Security Technologies
 *
 * This software is provided under under a slightly modified version
 * of the Apache Software License. See the accompanying LICENSE file
 * for more information.
 *
 */

#ifndef __pcapdumper__
#define __pcapdumper__


PyObject*
new_pcapdumper(pcap_dumper_t *dumper);

extern PyTypeObject Pdumpertype;

#endif // __pcapdumper__
