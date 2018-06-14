/*
 * Copyright (c) 2014 CORE Security Technologies
 *
 * This software is provided under under a slightly modified version
 * of the Apache Software License. See the accompanying LICENSE file
 * for more information.
 *
 */

#include <Python.h>
#include <pcap.h>

#include "pcapdumper.h"
#include "pcap_pkthdr.h"
#include "pcapy.h"

// internal pcapdumper
typedef struct {
	PyObject_HEAD
	pcap_dumper_t *dumper;
} pcapdumper;

static bool validate_pcapdumper(register const pcapdumper* pp);

// Pdumpertype

static void
pcap_dealloc(register pcapdumper* pp)
{
  if ( pp->dumper )
    pcap_dump_close(pp->dumper);

  pp->dumper = NULL;

  PyObject_Del(pp);
}


// pcap methods
static PyObject* p_close(register pcapdumper* pp, PyObject* args);
static PyObject* p_dump(register pcapdumper* pp, PyObject* args);


static PyMethodDef p_methods[] = {
  {"close", (PyCFunction) p_close, METH_VARARGS, "loops packet dispatching"},
  {"dump", (PyCFunction) p_dump, METH_VARARGS, "dump a packet to the file"},
  {NULL, NULL}	/* sentinel */
};

static PyObject*
pcap_getattr(pcapdumper* pp, char* name)
{
#if PY_MAJOR_VERSION >= 3
  PyObject *nameobj = PyUnicode_FromString(name);
  PyObject *attr = PyObject_GenericGetAttr((PyObject *)pp, nameobj);
  Py_DECREF(nameobj);
  return attr;
#else
  return Py_FindMethod(p_methods, (PyObject*)pp, name);
#endif
}


PyTypeObject Pdumpertype = {
#if PY_MAJOR_VERSION >= 3
	PyVarObject_HEAD_INIT(&PyType_Type, 0)
  "Dumper",                  /* tp_name */
  sizeof(pcapdumper),        /* tp_basicsize */
  0,                         /* tp_itemsize */
  (destructor)pcap_dealloc,  /* tp_dealloc */
  0,                         /* tp_print */
  (getattrfunc)pcap_getattr, /* tp_getattr */
  0,                         /* tp_setattr */
  0,                         /* tp_reserved */
  0,                         /* tp_repr */
  0,                         /* tp_as_number */
  0,                         /* tp_as_sequence */
  0,                         /* tp_as_mapping */
  0,                         /* tp_hash */
  0,                         /* tp_call */
  0,                         /* tp_str */
  0,                         /* tp_getattro */
  0,                         /* tp_setattro */
  0,                         /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT,        /* tp_flags */
  NULL,                      /* tp_doc */
  0,                         /* tp_traverse */
  0,                         /* tp_clear */
  0,                         /* tp_richcompare */
  0,                         /* tp_weaklistoffset */
  0,                         /* tp_iter */
  0,                         /* tp_iternext */
  p_methods,                 /* tp_methods */
  0,                         /* tp_members */
  0,                         /* tp_getset */
  0,                         /* tp_base */
  0,                         /* tp_dict */
  0,                         /* tp_descr_get */
  0,                         /* tp_descr_set */
  0,                         /* tp_dictoffset */
  0,                         /* tp_init */
  0,                         /* tp_alloc */
  0,                         /* tp_new */
#else
  PyObject_HEAD_INIT(NULL)
  0,
  "Dumper",
  sizeof(pcapdumper),
  0,
  /* methods */
  (destructor)pcap_dealloc,  /* tp_dealloc */
  0,                         /* tp_print */
  (getattrfunc)pcap_getattr, /* tp_getattr */
  0,                         /* tp_setattr */
  0,                         /* tp_compare */
  0,                         /* tp_repr */
  0,                         /* tp_as_number */
  0,                         /* tp_as_sequence */
  0,                         /* tp_as_mapping */
#endif
};

PyObject*
new_pcapdumper(pcap_dumper_t *dumper)
{
  if (PyType_Ready(&Pdumpertype) < 0)
    return NULL;

  pcapdumper *pp;

  pp = PyObject_New(pcapdumper, &Pdumpertype);
  if (pp == NULL)
    return NULL;

  pp->dumper = dumper;

  return (PyObject*)pp;
}

static PyObject*
p_dump(register pcapdumper* pp, PyObject* args)
{
	PyObject *pyhdr;
	u_char *data;
	int       len;

	if(validate_pcapdumper(pp) == false){
        return NULL;  
    }

#if PY_MAJOR_VERSION >= 3
	if (!PyArg_ParseTuple(args,"Oy#",&pyhdr,&data,&len)){
		return NULL;
    }
#else
    if (!PyArg_ParseTuple(args,"Os#",&pyhdr,&data,&len)){
        return NULL;
    }
#endif

	struct pcap_pkthdr hdr;
	if (-1 == pkthdr_to_native(pyhdr, &hdr))
		return NULL;

    if (pp->dumper == NULL){
        PyErr_SetString(PcapError, "Dumper is already closed.");
        return NULL;
    }

	pcap_dump((u_char *)pp->dumper, &hdr, data);

	Py_INCREF(Py_None);
	return Py_None;
}

// PdumperClose

static PyObject*
p_close(register pcapdumper* pp, PyObject* args)
{
    if(validate_pcapdumper(pp) == false){
        return NULL;  
    }

    if ( pp->dumper )
        pcap_dump_close(pp->dumper);

    pp->dumper = NULL;

    Py_INCREF(Py_None);
    return Py_None;
}

static bool
validate_pcapdumper(register const pcapdumper* pp){
    if (pp == NULL || Py_TYPE(pp) != &Pdumpertype) {
        PyErr_SetString(PcapError, "Not a pcapdumper object");
        return false;
    }
    return true;
}
