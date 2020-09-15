/*
 * Copyright (c) 2014 CORE Security Technologies
 *
 * This software is provided under under a slightly modified version
 * of the Apache Software License. See the accompanying LICENSE file
 * for more information.
 *
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <pcap.h>

#include "pcapobj.h"
#include "pcapy.h"
#include "pcapdumper.h"
#include "pcap_pkthdr.h"

#ifdef WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif


// internal pcapobject
typedef struct {
	PyObject_HEAD
	pcap_t *pcap;
	bpf_u_int32 net;
	bpf_u_int32 mask;
} pcapobject;


// PcapType

static PyObject*
p_close(register pcapobject* pp, PyObject*)
{
  if ( pp->pcap )
    pcap_close(pp->pcap);

  pp->pcap = NULL;

  Py_RETURN_NONE;
}

static void
pcap_dealloc(register pcapobject* pp)
{
  p_close(pp, NULL);

  PyObject_Del(pp);
}

static PyObject *
err_closed(void)
{
  PyErr_SetString(PyExc_ValueError, "pcap is closed");
  return NULL;
}

// pcap methods
static PyObject* p_getnet(register pcapobject* pp, PyObject* args);
static PyObject* p_getmask(register pcapobject* pp, PyObject* args);
static PyObject* p_setfilter( register pcapobject* pp, PyObject* args );
static PyObject* p_next(register pcapobject* pp, PyObject*);
static PyObject* p_dispatch(register pcapobject* pp, PyObject* args);
static PyObject* p_loop(register pcapobject* pp, PyObject* args);
static PyObject* p_datalink(register pcapobject* pp, PyObject* args);
static PyObject* p_setdirection(register pcapobject* pp, PyObject* args);
static PyObject* p_setnonblock(register pcapobject* pp, PyObject* args);
static PyObject* p_getnonblock(register pcapobject* pp, PyObject* args);
static PyObject* p_dump_open(register pcapobject* pp, PyObject* args);
static PyObject* p_sendpacket(register pcapobject* pp, PyObject* args);
static PyObject* p_stats( register pcapobject* pp, PyObject*);
static PyObject* p__enter__( register pcapobject* pp, PyObject*);
static PyObject* p_getfd(register pcapobject* pp, PyObject* args);
static PyObject* p_set_snaplen(register pcapobject* pp, PyObject* args);
static PyObject* p_set_promisc(register pcapobject* pp, PyObject* args);
static PyObject* p_set_timeout(register pcapobject* pp, PyObject* args);
static PyObject* p_set_buffer_size(register pcapobject* pp, PyObject* args);
static PyObject* p_set_rfmon(register pcapobject* pp, PyObject* args);
static PyObject* p_activate(register pcapobject* pp, PyObject* args);

static PyMethodDef p_methods[] = {
  {"loop", (PyCFunction) p_loop, METH_VARARGS, "loops packet dispatching"},
  {"dispatch", (PyCFunction) p_dispatch, METH_VARARGS, "dispatchs packets"},
  {"next", (PyCFunction) p_next, METH_NOARGS, "returns next packet"},
  {"setfilter", (PyCFunction) p_setfilter, METH_VARARGS, "compiles and sets a BPF capture filter"},
  {"getnet", (PyCFunction) p_getnet, METH_VARARGS, "returns the network address for the device"},
  {"getmask", (PyCFunction) p_getmask, METH_VARARGS, "returns the netmask for the device"},
  {"datalink", (PyCFunction) p_datalink, METH_VARARGS, "returns the link layer type"},
  {"getnonblock", (PyCFunction) p_getnonblock, METH_VARARGS, "returns the current `non-blocking' state"},
  {"setnonblock", (PyCFunction) p_setnonblock, METH_VARARGS, "puts into `non-blocking' mode, or take it out, depending on the argument"},
  {"setdirection", (PyCFunction) p_setdirection, METH_VARARGS, "set the direction for which packets will be captured"},
  {"dump_open", (PyCFunction) p_dump_open, METH_VARARGS, "creates a dumper object"},
  {"sendpacket", (PyCFunction) p_sendpacket, METH_VARARGS, "sends a packet through the interface"},
  {"stats", (PyCFunction) p_stats, METH_NOARGS, "returns capture statistics"},
  {"close", (PyCFunction) p_close, METH_NOARGS, "close the capture"},
  {"set_snaplen", (PyCFunction)p_set_snaplen, METH_VARARGS, "set the snapshot length for a not-yet-activated capture handle"},
  {"set_promisc", (PyCFunction)p_set_promisc, METH_VARARGS, "set promiscuous mode for a not-yet-activated capture handle"},
  {"set_timeout", (PyCFunction)p_set_timeout, METH_VARARGS, "set the read timeout for a not-yet-activated capture handle"},
  {"set_buffer_size", (PyCFunction)p_set_buffer_size, METH_VARARGS, "set the buffer size for a not-yet-activated capture handle"},
  {"activate", (PyCFunction)p_activate, METH_NOARGS, "activate a capture handle created using create()"},
  {"__enter__", (PyCFunction) p__enter__, METH_NOARGS, NULL},
  {"__exit__", (PyCFunction) p_close, METH_VARARGS, NULL},
#ifndef WIN32
  {"getfd", (PyCFunction) p_getfd, METH_VARARGS, "get selectable pcap fd"},
  {"set_rfmon", (PyCFunction)p_set_rfmon, METH_VARARGS, "set monitor mode for a not-yet-activated capture handle"}, /* Available on Npcap, not on Winpcap. */
#endif
  {NULL, NULL}	/* sentinel */
};

static PyObject*
pcap_getattr(pcapobject* pp, char* name)
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


PyTypeObject Pcaptype = {
#if PY_MAJOR_VERSION >= 3
  PyVarObject_HEAD_INIT(&PyType_Type, 0)
  "Reader",                  /* tp_name */
  sizeof(pcapobject),        /* tp_basicsize */
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
  "Reader",
  sizeof(pcapobject),
  0,
  /* methods */
  (destructor)pcap_dealloc,    /* tp_dealloc*/
  0,                           /* tp_print*/
  (getattrfunc)pcap_getattr,   /* tp_getattr*/
  0,                           /* tp_setattr*/
  0,                           /* tp_compare*/
  0,                           /* tp_repr*/
  0,                           /* tp_as_number*/
  0,                           /* tp_as_sequence*/
  0,                           /* tp_as_mapping*/
  0,                           /* tp_hash */
  0,                           /* tp_call */
  0,                           /* tp_str */
  0,                           /* tp_getattro */
  0,                           /* tp_setattro */
  0,                           /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT,          /* tp_flags */
  NULL,                        /* tp_doc */
  0,                           /* tp_traverse */
  0,                           /* tp_clear */
  0,                           /* tp_richcompare */
  0,                           /* tp_weaklistoffset */
  0,                           /* tp_iter */
  0,                           /* tp_iternext */
  p_methods,                   /* tp_methods */
  0,                           /* tp_members */
  0,                           /* tp_getset */
  0,                           /* tp_base */
  0,                           /* tp_dict */
  0,                           /* tp_descr_get */
  0,                           /* tp_descr_set */
  0,                           /* tp_dictoffset */
  0,                           /* tp_init */
  0,                           /* tp_alloc */
  0,                           /* tp_new */
#endif
};


PyObject*
new_pcapobject(pcap_t *pcap, bpf_u_int32 net, bpf_u_int32 mask)
{
  if (PyType_Ready(&Pcaptype) < 0)
    return NULL;

  pcapobject *pp;

  pp = PyObject_New(pcapobject, &Pcaptype);
  if (pp == NULL)
    return NULL;

  pp->pcap = pcap;
  pp->net = net;
  pp->mask = mask;

  return (PyObject*)pp;
}

static void ntos(char* dst, unsigned int n, int ip)
{
  ip = htonl(ip);
  snprintf(dst, n, "%i.%i.%i.%i",
	   ((ip >> 24) & 0xFF),
	   ((ip >> 16) & 0xFF),
	   ((ip >> 8) & 0xFF),
	   (ip & 0xFF));
}

static PyObject*
p_getnet(register pcapobject* pp, PyObject* args)
{
  if (Py_TYPE(pp) != &Pcaptype)
    {
      PyErr_SetString(PcapError, "Not a pcap object");
      return NULL;
    }

  if (!pp->pcap)
    return err_closed();

  char ip_str[20];
  ntos(ip_str, sizeof(ip_str), pp->net);
  return Py_BuildValue("s", ip_str);
}

static PyObject*
p_getmask(register pcapobject* pp, PyObject* args)
{
  if (Py_TYPE(pp) != &Pcaptype)
    {
      PyErr_SetString(PcapError, "Not a pcap object");
      return NULL;
    }

  if (!pp->pcap)
    return err_closed();

  char ip_str[20];
  ntos(ip_str, sizeof(ip_str), pp->mask);
  return Py_BuildValue("s", ip_str);
}

static PyObject*
p_setfilter(register pcapobject* pp, PyObject* args)
{
  struct bpf_program bpfprog;
  int status;
  char* str;

  if (Py_TYPE(pp) != &Pcaptype)
    {
      PyErr_SetString(PcapError, "Not a pcap object");
	return NULL;
    }

  if (!pp->pcap)
    return err_closed();

  if (!PyArg_ParseTuple(args,"s:setfilter",&str))
    return NULL;

  status = pcap_compile(pp->pcap, &bpfprog, str, 1, pp->mask);
  if (status)
    {
      PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
      return NULL;
    }

  status = pcap_setfilter(pp->pcap, &bpfprog);
  if (status)
    {
      PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
      return NULL;
    }

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject*
p_next(register pcapobject* pp, PyObject*)
{
  struct pcap_pkthdr *hdr = NULL;
  const unsigned char *buf = (const unsigned char*)"";
  int err_code = 1;

  if (Py_TYPE(pp) != &Pcaptype)
  {
    PyErr_SetString(PcapError, "Not a pcap object");
    return NULL;
  }

  if (!pp->pcap)
    return err_closed();

  // allow threads as this might block
  Py_BEGIN_ALLOW_THREADS;
  err_code = pcap_next_ex(pp->pcap, &hdr, &buf);
  Py_END_ALLOW_THREADS;

  if(err_code == -1)
  {
    PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
    return NULL;
  }


  PyObject *pkthdr;
  int _caplen = 0;
  if (err_code == 1) {
    pkthdr = new_pcap_pkthdr(hdr);
    _caplen = hdr->caplen;
  } else {
    pkthdr = Py_None;
    Py_INCREF(pkthdr);
    _caplen = 0;
  }


  if (pkthdr)
  {
    PyObject *ret = NULL;

    #if PY_MAJOR_VERSION >= 3
      /* return bytes */
      ret = Py_BuildValue("(Oy#)", pkthdr, buf, _caplen);
    #else
      ret = Py_BuildValue("(Os#)", pkthdr, buf, _caplen);
    #endif

    Py_DECREF(pkthdr);
    return ret;
  }

  PyErr_SetString(PcapError, "Can't build pkthdr");
  return NULL;
}

struct PcapCallbackContext {
  PcapCallbackContext(pcap_t* p, PyObject* f, PyThreadState* ts)
    : ppcap_t(p), pyfunc(f), thread_state(ts)
  {
    Py_INCREF(pyfunc);
  }
  ~PcapCallbackContext()
  {
    Py_DECREF(pyfunc);
  }

  pcap_t* ppcap_t;
  PyObject *pyfunc;
  PyThreadState *thread_state;

};


static void
PythonCallBack(u_char *user,
	       const struct pcap_pkthdr *header,
	       const u_char *packetdata)
{
  PyObject *arglist, *result;
  unsigned int *len;
  PcapCallbackContext *pctx;
  len    = (unsigned int *)&header->caplen;
  pctx = (PcapCallbackContext *)user;

  PyEval_RestoreThread(pctx->thread_state);

  PyObject *hdr = new_pcap_pkthdr(header);

#if PY_MAJOR_VERSION >= 3
  /* pass bytes */
  arglist = Py_BuildValue("Oy#", hdr, packetdata, *len);
#else
  arglist = Py_BuildValue("Os#", hdr, packetdata, *len);
#endif

  result = PyEval_CallObject(pctx->pyfunc,arglist);

  Py_XDECREF(arglist);
  if (result)
    Py_DECREF(result);

  Py_DECREF(hdr);

  if (!result)
    pcap_breakloop(pctx->ppcap_t);

  PyEval_SaveThread();
}

static PyObject*
p_dispatch(register pcapobject* pp, PyObject* args)
{
  int cant, ret;
  PyObject *PyFunc;

  if (Py_TYPE(pp) != &Pcaptype)
    {
      PyErr_SetString(PcapError, "Not a pcap object");
      return NULL;
    }

  if (!pp->pcap)
    return err_closed();

  if(!PyArg_ParseTuple(args,"iO:dispatch",&cant,&PyFunc))
    return NULL;

  PcapCallbackContext ctx(pp->pcap, PyFunc, PyThreadState_Get());
  PyEval_SaveThread();
  ret = pcap_dispatch(pp->pcap, cant, PythonCallBack, (u_char*)&ctx);
  PyEval_RestoreThread(ctx.thread_state);

  if(ret<0) {
    if (ret!=-2)
      /* pcap error, pcap_breakloop was not called so error is not set */
      PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
    return NULL;
  }

  return Py_BuildValue("i", ret);
}

static PyObject*
p_stats(register pcapobject* pp, PyObject*)
{
  if (Py_TYPE(pp) != &Pcaptype)
     {
	   PyErr_SetString(PcapError, "Not a pcap object");
	   return NULL;
	 }

  if (!pp->pcap)
    return err_closed();

  struct pcap_stat stats;

  if (-1 == pcap_stats(pp->pcap, &stats)) {
     PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
	 return NULL;
  }

	return Py_BuildValue("III", stats.ps_recv, stats.ps_drop, stats.ps_ifdrop);
}

static PyObject*
p__enter__( register pcapobject* pp, PyObject*)
{
  if (Py_TYPE(pp) != &Pcaptype)
    {
      PyErr_SetString(PcapError, "Not a pcap object");
      return NULL;
    }

  if (!pp->pcap)
    return err_closed();

  Py_INCREF(pp);
  return (PyObject*)pp;
}

static PyObject*
p_dump_open(register pcapobject* pp, PyObject* args)
{
  char *filename;
  pcap_dumper_t *ret;

  if (Py_TYPE(pp) != &Pcaptype)
    {
      PyErr_SetString(PcapError, "Not a pcap object");
      return NULL;
    }

  if (!pp->pcap)
    return err_closed();

  if(!PyArg_ParseTuple(args,"s",&filename))
    return NULL;

  ret = pcap_dump_open(pp->pcap, filename);

  if (ret==NULL) {
    PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
    return NULL;
  }

  return new_pcapdumper(ret);
}


static PyObject*
p_loop(register pcapobject* pp, PyObject* args)
{
  int cant, ret;
  PyObject *PyFunc;

  if (Py_TYPE(pp) != &Pcaptype)
    {
      PyErr_SetString(PcapError, "Not a pcap object");
      return NULL;
    }

  if (!pp->pcap)
    return err_closed();

  if(!PyArg_ParseTuple(args,"iO:loop",&cant,&PyFunc))
    return NULL;

  PcapCallbackContext ctx(pp->pcap, PyFunc, PyThreadState_Get());
  PyEval_SaveThread();
  ret = pcap_loop(pp->pcap, cant, PythonCallBack, (u_char*)&ctx);
  PyEval_RestoreThread(ctx.thread_state);

  if(ret<0) {
    if (ret!=-2)
      /* pcap error, pcap_breakloop was not called so error is not set */
      PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
    return NULL;
  }

  Py_INCREF(Py_None);
  return Py_None;
}


static PyObject*
p_datalink(register pcapobject* pp, PyObject* args)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	int type = pcap_datalink(pp->pcap);

	return Py_BuildValue("i", type);
}

static PyObject*
p_setdirection(register pcapobject* pp, PyObject* args)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	pcap_direction_t direction;

	if (!PyArg_ParseTuple(args, "i", &direction))
		return NULL;

	int ret = pcap_setdirection(pp->pcap, direction);
	if (-1 == ret) {
		PyErr_SetString(PcapError, "Failed setting direction");
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject*
p_setnonblock(register pcapobject* pp, PyObject* args)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	int state;

	if (!PyArg_ParseTuple(args, "i", &state))
		return NULL;

	char errbuf[PCAP_ERRBUF_SIZE];
	int ret = pcap_setnonblock(pp->pcap, state, errbuf);
	if (-1 == ret) {
		PyErr_SetString(PcapError, errbuf);
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject*
p_getnonblock(register pcapobject* pp, PyObject* args)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	char errbuf[PCAP_ERRBUF_SIZE];
	int state = pcap_getnonblock(pp->pcap, errbuf);
	if (-1 == state) {
		PyErr_SetString(PcapError, errbuf);
		return NULL;
	}

	return Py_BuildValue("i", state);
}

static PyObject*
p_set_snaplen(register pcapobject* pp, PyObject* args)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	int snaplen;

	if (!PyArg_ParseTuple(args, "i", &snaplen))
		return NULL;

	int ret = pcap_set_snaplen(pp->pcap, snaplen);
	return Py_BuildValue("i", ret);
}

static PyObject*
p_set_promisc(register pcapobject* pp, PyObject* args)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	int promisc;

	if (!PyArg_ParseTuple(args, "i", &promisc))
		return NULL;

	int ret = pcap_set_promisc(pp->pcap, promisc);
	return Py_BuildValue("i", ret);
}

static PyObject*
p_set_timeout(register pcapobject* pp, PyObject* args)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	int to_ms;

	if (!PyArg_ParseTuple(args, "i", &to_ms))
		return NULL;

	int ret = pcap_set_timeout(pp->pcap, to_ms);
	return Py_BuildValue("i", ret);
}

static PyObject*
p_set_buffer_size(register pcapobject* pp, PyObject* args)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	int buffer_size;

	if (!PyArg_ParseTuple(args, "i", &buffer_size))
		return NULL;

	int ret = pcap_set_buffer_size(pp->pcap, buffer_size);
	return Py_BuildValue("i", ret);
}

static PyObject*
p_set_rfmon(register pcapobject* pp, PyObject* args)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	int rfmon;

	if (!PyArg_ParseTuple(args, "i", &rfmon))
		return NULL;

	int ret = pcap_set_rfmon(pp->pcap, rfmon);
	return Py_BuildValue("i", ret);
}

static PyObject*
p_activate(register pcapobject* pp, PyObject*)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	int ret = pcap_activate(pp->pcap);
	return Py_BuildValue("i", ret);
}


static PyObject*
p_sendpacket(register pcapobject* pp, PyObject* args)
{
  int status;
  unsigned char* str;
  unsigned int length;

  if (Py_TYPE(pp) != &Pcaptype)
    {
      PyErr_SetString(PcapError, "Not a pcap object");
      return NULL;
    }

  if (!pp->pcap)
    return err_closed();

#if PY_MAJOR_VERSION >= 3
  /* accept bytes */
  if (!PyArg_ParseTuple(args,"y#", &str, &length)) {
    return NULL;
  }
#else
  if (!PyArg_ParseTuple(args,"s#", &str, &length)) {
    return NULL;
  }
#endif


  status = pcap_sendpacket(pp->pcap, str, length);
  if (status)
    {
      PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
      return NULL;
    }

  Py_INCREF(Py_None);
  return Py_None;
}

#ifndef WIN32
static PyObject*
p_getfd(register pcapobject* pp, PyObject* args)
{
  if (Py_TYPE(pp) != &Pcaptype)
    {
      PyErr_SetString(PcapError, "Not a pcap object");
      return NULL;
    }

  if (!pp->pcap)
    return err_closed();

  int fd = pcap_get_selectable_fd(pp->pcap);
  return Py_BuildValue("i", fd);
}
#endif
