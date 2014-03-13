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

#include "pcapy.h"
#include "pcap_pkthdr.h"

#ifdef WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif


// internal pcapobject
typedef struct {
	PyObject_HEAD
	struct timeval ts;
	bpf_u_int32 caplen;
	bpf_u_int32 len;
} pkthdr;


// Pkthdr_Type

static void
pcap_dealloc(register pkthdr* pp)
{
  PyObject_Del(pp);
}


// pcap methods
static PyObject* p_getts(register pkthdr* pp, PyObject* args);
static PyObject* p_getcaplen(register pkthdr* pp, PyObject* args);
static PyObject* p_getlen(register pkthdr* pp, PyObject* args);


static PyMethodDef p_methods[] = {
  {"getts", (PyCFunction) p_getts, METH_VARARGS, "get timestamp tuple (seconds, microseconds) since the Epoch"},
  {"getcaplen", (PyCFunction) p_getcaplen, METH_VARARGS, "returns the length of portion present"},
  {"getlen", (PyCFunction) p_getlen, METH_VARARGS, "returns the length of the packet (off wire)"},
  {NULL, NULL}	/* sentinel */
};

static PyObject*
pcap_getattr(pkthdr* pp, char* name)
{
  return Py_FindMethod(p_methods, (PyObject*)pp, name);
}


PyTypeObject Pkthdr_type = {
  PyObject_HEAD_INIT(NULL)
  0,
  "Pkthdr",
  sizeof(pkthdr),
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
new_pcap_pkthdr(const struct pcap_pkthdr* hdr)
{
  pkthdr *pp;

  pp = PyObject_New(pkthdr, &Pkthdr_type);
  if (pp == NULL)
    return NULL;

  pp->ts = hdr->ts;
  pp->caplen = hdr->caplen;
  pp->len = hdr->len;

  return (PyObject*)pp;
}

static PyObject*
p_getts(register pkthdr* pp, PyObject* args)
{
  if (pp->ob_type != &Pkthdr_type) {
	  PyErr_SetString(PcapError, "Not a pkthdr object");
	  return NULL;
  }

  return Py_BuildValue("(ll)", pp->ts.tv_sec, pp->ts.tv_usec);
}

static PyObject*
p_getcaplen(register pkthdr* pp, PyObject* args)
{
  if (pp->ob_type != &Pkthdr_type) {
	  PyErr_SetString(PcapError, "Not a pkthdr object");
	  return NULL;
  }

  return Py_BuildValue("l", pp->caplen);
}

static PyObject*
p_getlen(register pkthdr* pp, PyObject* args)
{
  if (pp->ob_type != &Pkthdr_type) {
	  PyErr_SetString(PcapError, "Not a pkthdr object");
	  return NULL;
  }

  return Py_BuildValue("l", pp->len);
}

int
pkthdr_to_native(PyObject *pyhdr, struct pcap_pkthdr *hdr)
{
  if (pyhdr->ob_type != &Pkthdr_type) {
	  PyErr_SetString(PcapError, "Not a pkthdr object");
	  return -1;
  }

  pkthdr *pp = (pkthdr *) pyhdr;

  hdr->ts = pp->ts;
  hdr->caplen = pp->caplen;
  hdr->len = pp->len;

  return 0;
}
