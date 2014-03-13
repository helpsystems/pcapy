/*
 * Copyright (c) 2014 CORE Security Technologies
 *
 * This software is provided under under a slightly modified version
 * of the Apache Software License. See the accompanying LICENSE file
 * for more information.
 *
 */

#ifndef __PCAPY_H__


extern "C" {
#ifdef WIN32
__declspec(dllexport)
#endif
void initpcapy(void);
}

// exception object
extern PyObject* PcapError;

#endif // __PCAPY_H__
