/*
 * Copyright (c) 2014 CORE Security Technologies
 *
 * This software is provided under under a slightly modified version
 * of the Apache Software License. See the accompanying LICENSE file
 * for more information.
 *
 */

#ifndef __PCAPY_H__

#ifndef Py_TYPE  // python3 compatible
    #define Py_TYPE(ob) (((PyObject*)(ob))->ob_type)
#endif

extern "C" {
#ifdef WIN32
__declspec(dllexport)
#endif

#if PY_MAJOR_VERSION >= 3
PyObject * PyInit_pcapy(void);
#else
void initpcapy(void);
#endif
}

// exception object
extern PyObject* PcapError;

#endif // __PCAPY_H__
