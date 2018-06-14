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

PyObject* BPFError;


// BPFProgram methods
static PyObject* p_filter(register bpfobject* bpf, PyObject* args);
static PyObject* p_get_bpf(register bpfobject* bpf, PyObject* args);
static PyObject* p_new_bpfobject(PyTypeObject *type, PyObject* args, PyObject *kwags);


static PyMethodDef bpf_methods[] = {
  {"filter", (PyCFunction) p_filter, METH_VARARGS, "filter(packet) applies the filter to the packet, returns 0 if there's no match"},
  {"get_bpf", (PyCFunction) p_get_bpf, METH_NOARGS, "return packet-matching code as decimal numbers"},
  {NULL, NULL}	/* sentinel */
};

static PyObject*
bpfprog_getattr(bpfobject* pp, char* name)
{
#if PY_MAJOR_VERSION >= 3
  PyObject *nameobj = PyUnicode_FromString(name);
  PyObject *attr = PyObject_GenericGetAttr((PyObject *)pp, nameobj);
  Py_DECREF(nameobj);
  return attr;
#else
  return Py_FindMethod(bpf_methods, (PyObject*)pp, name);
#endif
}


PyTypeObject BPFProgramType = {
#if PY_MAJOR_VERSION >= 3
	PyVarObject_HEAD_INIT(&PyType_Type, 0)
  "BPFProgram",                 /* tp_name */
  sizeof(bpfobject),            /* tp_basicsize */
  0,                            /* tp_itemsize */
  (destructor)bpfprog_dealloc,  /* tp_dealloc */
  0,                            /* tp_print */
  (getattrfunc)bpfprog_getattr, /* tp_getattr */
  0,                            /* tp_setattr */
  0,                            /* tp_reserved */
  0,                            /* tp_repr */
  0,                            /* tp_as_number */
  0,                            /* tp_as_sequence */
  0,                            /* tp_as_mapping */
  0,                            /* tp_hash */
  0,                            /* tp_call */
  0,                            /* tp_str */
  0,                            /* tp_getattro */
  0,                            /* tp_setattro */
  0,                            /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT,           /* tp_flags */
  "BPF Program Wrapper",        /* tp_doc */
  0,                            /* tp_traverse */
  0,                            /* tp_clear */
  0,                            /* tp_richcompare */
  0,                            /* tp_weaklistoffset */
  0,                            /* tp_iter */
  0,                            /* tp_iternext */
  bpf_methods,                  /* tp_methods */
  0,                            /* tp_members */
  0,                            /* tp_getset */
  0,                            /* tp_base */
  0,                            /* tp_dict */
  0,                            /* tp_descr_get */
  0,                            /* tp_descr_set */
  0,                            /* tp_dictoffset */
  0,                            /* tp_init */
  0,                            /* tp_alloc */
  p_new_bpfobject               /* tp_new */
#else
  PyObject_HEAD_INIT(NULL)
  0,
  "BPFProgram",
  sizeof(bpfobject),
  0,
  /* methods */
  (destructor)bpfprog_dealloc,      /* tp_dealloc*/
  0,                                /* tp_print*/
  (getattrfunc)bpfprog_getattr,     /* tp_getattr*/
  0,                                /* tp_setattr*/
  0,                                /*tp_compare*/
  0,                                /*tp_repr*/
  0,                                /*tp_as_number*/
  0,                                /*tp_as_sequence*/
  0,                                /*tp_as_mapping*/
  0,                                /*tp_hash */
  0,                                /*tp_call*/
  0,                                /*tp_str*/
  0,                                /*tp_getattro*/
  0,                                /*tp_setattro*/
  0,                                /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, 
                                    /*tp_flags*/
  "BPF Program Wrapper",            /* tp_doc */
  0,                                /* tp_traverse */
  0,                                /* tp_clear */
  0,                                /* tp_richcompare */
  0,                                /* tp_weaklistoffset */
  0,                                /* tp_iter */
  0,                                /* tp_iternext */
  bpf_methods,                      /* tp_methods */
  0,                                /* tp_members */
  0,                                /* tp_getset */
  0,                                /* tp_base */
  0,                                /* tp_dict */
  0,                                /* tp_descr_get */
  0,                                /* tp_descr_set */
  0,                                /* tp_dictoffset */
  0,                                /* tp_init */
  0,                                /* tp_alloc */
  p_new_bpfobject                   /* tp_new */
#endif
};


PyObject*
new_bpfobject(const struct bpf_program &bpfprog)
{
  if (PyType_Ready(&BPFProgramType) < 0)
    return NULL;

  bpfobject *bpf;
  bpf = PyObject_New(bpfobject, &BPFProgramType);
  if (bpf == NULL)
  { 
    PyErr_SetString(BPFError, "Failed to create object");
    return NULL;
  }

  bpf->bpf = bpfprog;
  return (PyObject*)bpf;
}


static PyObject*
p_new_bpfobject(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  char *filter_string;
  int linktype = 1;  // DLT_EN10MB
  if (!PyArg_ParseTuple(args, "s|i", &filter_string, &linktype)){
    return NULL;
  }

  struct bpf_program bpfprog;

  if (pcap_compile_nopcap((1<<16), linktype, &bpfprog, filter_string, 0, 0)){
    PyErr_SetString(BPFError, "Couldn't compile BPF program");
    return NULL;
  }

  return new_bpfobject(bpfprog);
}


static PyObject*
p_filter(register bpfobject* bpf, PyObject* args)
{
  int status;
  u_char* packet;
  unsigned int len;

  if (Py_TYPE(bpf) != &BPFProgramType)
    {
      PyErr_SetString(BPFError, "Not a bpfprogram object");
	    return NULL;
    }

#if PY_MAJOR_VERSION >= 3
  if (!PyArg_ParseTuple(args,"y#:filter",&packet, &len)){
    return NULL;
  }
#else
  if (!PyArg_ParseTuple(args,"s#:filter",&packet, &len)){
    return NULL;
  }
#endif

  status = bpf_filter(bpf->bpf.bf_insns,
		      packet,
		      len, len);

  return Py_BuildValue("i", status);
}

static PyObject*
p_get_bpf(register bpfobject* bpf, PyObject* args)
{
  struct bpf_insn *insn;
  int i;
  int n = bpf->bpf.bf_len;
  PyObject* list;
  PyObject* instruction;

  insn = bpf->bpf.bf_insns;

  if (Py_TYPE(bpf) != &BPFProgramType)
    {
      PyErr_SetString(BPFError, "Not a bpfprogram object");
      return NULL;
    }

  list = PyList_New(n);
  if (!list) {
      return NULL;
  }

  for (i = 0; i < n; ++insn, ++i) {
      instruction = Py_BuildValue("IIII", insn->code, insn->jt, insn->jf, insn->k);
      if (!instruction) {
          Py_DECREF(list);
          return NULL;
      }
      PyList_SET_ITEM(list, i, instruction);
  }

  return list;
}
