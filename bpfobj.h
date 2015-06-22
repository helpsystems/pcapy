/*
 * Copyright (c) 2014 CORE Security Technologies
 *
 * This software is provided under under a slightly modified version
 * of the Apache Software License. See the accompanying LICENSE file
 * for more information.
 *
 */

#ifndef __bpfobj__
#define __bpfobj__

PyObject*
new_bpfobject(const struct bpf_program &bpf);

extern PyObject* BPFError;

extern PyTypeObject BPFProgramType;

extern PyTypeObject Pcaptype;

#endif // __bpfobj__
