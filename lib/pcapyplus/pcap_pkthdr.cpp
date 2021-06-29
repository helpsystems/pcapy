/*
 * Copyright (C) 2014-2021 CORE Security Technologies
 * Copyright (C) 2021 Hewlett Packard Enterprise Development LP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

#include <Python.h>
#include <pcap.h>

#include "pcapy.h"
#include "pcap_pkthdr.h"

#include <netinet/in.h>


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
  PyObject *nameobj = PyUnicode_FromString(name);
  PyObject *attr = PyObject_GenericGetAttr((PyObject *)pp, nameobj);
  Py_DECREF(nameobj);
  return attr;
}


PyTypeObject Pkthdr_type = {
  PyVarObject_HEAD_INIT(&PyType_Type, 0)
  "Pkthdr",                  /* tp_name */
  sizeof(pkthdr),            /* tp_basicsize */
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
};


PyObject*
new_pcap_pkthdr(const struct pcap_pkthdr* hdr)
{
  if (PyType_Ready(&Pkthdr_type) < 0)
    return NULL;

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
  if (Py_TYPE(pp) != &Pkthdr_type) {
	  PyErr_SetString(PcapError, "Not a pkthdr object");
	  return NULL;
  }

  return Py_BuildValue("(ll)", pp->ts.tv_sec, pp->ts.tv_usec);
}

static PyObject*
p_getcaplen(register pkthdr* pp, PyObject* args)
{
  if (Py_TYPE(pp) != &Pkthdr_type) {
	  PyErr_SetString(PcapError, "Not a pkthdr object");
	  return NULL;
  }

  return Py_BuildValue("l", pp->caplen);
}

static PyObject*
p_getlen(register pkthdr* pp, PyObject* args)
{
  if (Py_TYPE(pp) != &Pkthdr_type) {
	  PyErr_SetString(PcapError, "Not a pkthdr object");
	  return NULL;
  }

  return Py_BuildValue("l", pp->len);
}

int
pkthdr_to_native(PyObject *pyhdr, struct pcap_pkthdr *hdr)
{
  if (Py_TYPE(pyhdr) != &Pkthdr_type) {
	  PyErr_SetString(PcapError, "Not a pkthdr object");
	  return -1;
  }

  pkthdr *pp = (pkthdr *) pyhdr;

  hdr->ts = pp->ts;
  hdr->caplen = pp->caplen;
  hdr->len = pp->len;

  return 0;
}
/* vim: set tabstop=2 shiftwidth=2 expandtab: */
