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
//static PyObject* p_close(register pcapdumper* pp, PyObject* args);
static PyObject* p_dump(register pcapdumper* pp, PyObject* args);


static PyMethodDef p_methods[] = {
//  {"close", (PyCFunction) p_close, METH_VARARGS, "loops packet dispatching"},
  {"dump", (PyCFunction) p_dump, METH_VARARGS, "dump a packet to the file"},
  {NULL, NULL}	/* sentinel */
};

static PyObject*
pcap_getattr(pcapdumper* pp, char* name)
{
  return Py_FindMethod(p_methods, (PyObject*)pp, name);
}


PyTypeObject Pdumpertype = {
  PyObject_HEAD_INIT(NULL)
  0,
  "Dumper",
  sizeof(pcapdumper),
  0,

  /* methods */
  (destructor)pcap_dealloc,  /*tp_dealloc*/
  0,			  /*tp_print*/
  (getattrfunc)pcap_getattr, /*tp_getattr*/
  0,			  /*tp_setattr*/
  0,			  /*tp_compare*/
  0,			  /*tp_repr*/
  0,			  /*tp_as_number*/
  0,			  /*tp_as_sequence*/
  0,			  /*tp_as_mapping*/
};


PyObject*
new_pcapdumper(pcap_dumper_t *dumper)
{
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

	if (pp->ob_type != &Pdumpertype) {
		PyErr_SetString(PcapError, "Not a pcapdumper object");
		return NULL;
	}

	if (!PyArg_ParseTuple(args,"Os#",&pyhdr,&data,&len))
		return NULL;

	struct pcap_pkthdr hdr;
	if (-1 == pkthdr_to_native(pyhdr, &hdr))
		return NULL;

	pcap_dump((u_char *)pp->dumper, &hdr, data);

	Py_INCREF(Py_None);
	return Py_None;
}
