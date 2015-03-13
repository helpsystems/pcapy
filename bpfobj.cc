/*
 * Copyright (c) 2014 CORE Security Technologies
 *
 * This software is provided under under a slightly modified version
 * of the Apache Software License. See the accompanying LICENSE file
 * for more information.
 *
 */

#include <pcap.h>
#include <Python.h>

#include "bpfobj.h"
#include "pcapy.h"


// internal bpfobject
typedef struct {
	PyObject_HEAD
	struct bpf_program bpf;
} bpfobject;


// BPFProgramType

static void
bpfprog_dealloc(register bpfobject* bpf)
{
#ifndef WIN32 // XXX: is this missing from winpcap 2.3?
  pcap_freecode(&bpf->bpf);
#endif
  PyObject_Del(bpf);
}


// BPFProgram methods
static PyObject* p_filter(register bpfobject* bpf, PyObject* args);


static PyMethodDef bpf_methods[] = {
  {"filter", (PyCFunction) p_filter, METH_VARARGS, "filter(packet) applies the filter to the packet, returns 0 if there's no match"},
  {NULL, NULL}	/* sentinel */
};

static PyObject*
bpfprog_getattr(bpfobject* pp, char* name)
{
#if PY_MAJOR_VERSION >= 3
  PyObject *nameobj = PyUnicode_FromString(name);
  return PyObject_GenericGetAttr((PyObject *)pp, nameobj);
#else
  return Py_FindMethod(bpf_methods, (PyObject*)pp, name);
#endif
}


PyTypeObject BPFProgramtype = {
#if PY_MAJOR_VERSION >= 3
	PyVarObject_HEAD_INIT(&PyType_Type, 0)
	"Bpf",                          /* tp_name */
    sizeof(bpfobject),              /* tp_basicsize */
    0,                              /* tp_itemsize */
    (destructor)bpfprog_dealloc,    /* tp_dealloc */
    0,                              /* tp_print */
    (getattrfunc)bpfprog_getattr,   /* tp_getattr */
    0,                              /* tp_setattr */
    0,                              /* tp_reserved */
    0,                              /* tp_repr */
    0,                              /* tp_as_number */
    0,                              /* tp_as_sequence */
    0,                              /* tp_as_mapping */
    0,                              /* tp_hash  */
    0,                              /* tp_call */
    0,                              /* tp_str */
    0,                              /* tp_getattro */
    0,                              /* tp_setattro */
    0,                              /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,             /* tp_flags */
    "",                             /* tp_doc */
#else
  PyObject_HEAD_INIT(NULL)
  0,
  "Bpf", // 先看其他pcap库的api如何
  sizeof(bpfobject),
  0,
  /* methods */
  (destructor)bpfprog_dealloc,      /* tp_dealloc*/
  0,                                /* tp_print*/
  (getattrfunc)bpfprog_getattr,     /* tp_getattr*/
  0,                                /* tp_setattr*/
  0,                                /* tp_compare*/
  0,                                /* tp_repr*/
  0,                                /* tp_as_number*/
  0,                                /* tp_as_sequence*/
  0,                                /* tp_as_mapping*/
#endif
};


PyObject*
new_bpfobject(const struct bpf_program &bpfprog)
{
  bpfobject *bpf;
  bpf = PyObject_New(bpfobject, &BPFProgramtype);
  if (bpf == NULL)
    return NULL;

  bpf->bpf = bpfprog;
  return (PyObject*)bpf;
}


static PyObject*
p_filter(register bpfobject* bpf, PyObject* args)
{
  int status;
  u_char* packet;
  unsigned int len;

  if (Py_TYPE(bpf) != &BPFProgramtype)
    {
      PyErr_SetString(PcapError, "Not a bpfprogram object");
	return NULL;
    }

  if (!PyArg_ParseTuple(args,"s#:filter",&packet, &len))
    return NULL;

  status = bpf_filter(bpf->bpf.bf_insns,
		      packet,
		      len, len);

  return Py_BuildValue("i", status);
}
