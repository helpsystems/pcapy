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
#ifdef WIN32
#include <Iphlpapi.h> // IPHelper API for luid/guid conversions
#endif

#include "pcapy.h"
#include "pcapobj.h"
#include "bpfobj.h"
#include "pcapdumper.h"
#include "pcap_pkthdr.h"


PyObject *PcapError;



// module methods

static PyObject*
lookupdev(PyObject* self, PyObject* args)
{
  char errbuff[PCAP_ERRBUF_SIZE];
  char* dev;

  dev = pcap_lookupdev(errbuff);
  if(!dev)
    {
      PyErr_SetString(PcapError, errbuff);
      return NULL;
    }

  return Py_BuildValue("u", dev);
}

static PyObject*
findalldevs(PyObject *self, PyObject *args)
{
  char errbuff[PCAP_ERRBUF_SIZE];
  pcap_if_t *devs;

  int status = pcap_findalldevs(&devs, errbuff);
  if(status)
    {
      PyErr_SetString(PcapError, errbuff);
      return NULL;
    }

  if(devs==NULL)
    {
      PyErr_SetString(PcapError, "No valid interfaces to open");
      return NULL;
    }

  pcap_if_t *cursor = devs;
  PyObject* list = PyList_New(0);
  while(cursor)
    {
#ifdef WIN32 
/* If we are on windows, then display LUID's like "Local Area Connection"
 * instead of GUID's like "\Device\NPF_{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}".
 */
      char *luid = get_windows_interface_friendly_name(cursor->name);
      PyList_Append(list, Py_BuildValue("s", luid));
      free(luid);
#else
      PyList_Append(list, Py_BuildValue("s", cursor->name));
#endif
      cursor = cursor->next;
    }

  pcap_freealldevs(devs);

  return list;
}

static PyObject*
open_live(PyObject *self, PyObject *args)
{
  char errbuff[PCAP_ERRBUF_SIZE];
  char * device;
  int  snaplen;
  int  promisc;
  int  to_ms;

  bpf_u_int32 net, mask;


  if(!PyArg_ParseTuple(args,"siii:open_live",&device,&snaplen,&promisc,&to_ms))
    return NULL;

#ifdef WIN32
/* If we are on windows, then device is an LUID like "Local Area Connection".
 * pcap on Windows needs a GUID like "\Device\NPF_{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}".
 */
      device = luid_to_guid(device);
#endif
  int status = pcap_lookupnet(device, &net, &mask, errbuff);
  if(status)
    {
      net = 0;
      mask = 0;
    }

  pcap_t* pt;

  pt = pcap_open_live(device, snaplen, promisc!=0, to_ms, errbuff);
#ifdef WIN32
      free(device);
#endif
  
  if(!pt)
    {
      PyErr_SetString(PcapError, errbuff);
      return NULL;
    }
#ifdef WIN32
  //According to the doc
  //      pcap_setmintocopy() changes the minimum amount of data in the kernel buffer that causes a read from the application to return (unless the timeout expires)
  //      [...] pcap_open_live() sets a default mintocopy value of 16000 bytes.
  //It is a better practice to set it to 0, so that we are transparent about what we receive
  pcap_setmintocopy(pt, 0);
#endif

  return new_pcapobject( pt, net, mask );
}

static PyObject*
pcap_create(PyObject *self, PyObject *args)
{
	char errbuff[PCAP_ERRBUF_SIZE];
	char * device;

	bpf_u_int32 net, mask;


	if (!PyArg_ParseTuple(args, "s:pcap_create", &device))
		return NULL;

	int status = pcap_lookupnet(device, &net, &mask, errbuff);
	if (status)
	{
		net = 0;
		mask = 0;
	}

	pcap_t* pt;

	pt = pcap_create(device, errbuff);
	if (!pt)
	{
		PyErr_SetString(PcapError, errbuff);
		return NULL;
	}
#ifdef WIN32
  //Same than in open_live
  pcap_setmintocopy(pt, 0);
#endif

	return new_pcapobject(pt, net, mask);
}

static PyObject*
open_offline(PyObject *self, PyObject *args)
{
  char errbuff[PCAP_ERRBUF_SIZE];
  char * filename;


  if(!PyArg_ParseTuple(args,"s",&filename))
    return NULL;

  pcap_t* pt;

  pt = pcap_open_offline(filename, errbuff);
  if(!pt)
    {
      PyErr_SetString(PcapError, errbuff);
      return NULL;
    }
#ifdef WIN32
  pcap_setmintocopy(pt, 0);
#endif

  return new_pcapobject( pt );
}


static PyObject*
bpf_compile(PyObject* self, PyObject* args)
{
  int linktype;
  int  snaplen;
  char *filter;
  int optimize;
  unsigned int netmask;

  if(!PyArg_ParseTuple(args,
		       "iisiI:compile",
		       &linktype,
		       &snaplen,
		       &filter,
		       &optimize,
		       &netmask))
    return NULL;

  pcap_t *pp;

  pp = pcap_open_dead(linktype, snaplen);
  if(pp == NULL)
    return NULL;

  struct bpf_program bpf;
  int status = pcap_compile(pp, &bpf, filter, optimize, netmask);
  pcap_close(pp);

  if(status)
    {
      PyErr_SetString(PcapError, pcap_geterr(pp));
      return NULL;
    }

  return new_bpfobject( bpf );
}


static PyMethodDef pcap_methods[] = {
  {"open_live", open_live, METH_VARARGS, "open_live(device, snaplen, promisc, to_ms) opens a pcap device"},
  {"open_offline", open_offline, METH_VARARGS, "open_offline(filename) opens a pcap formated file"},
  {"lookupdev", lookupdev, METH_VARARGS, "lookupdev() looks up a pcap device"},
  {"findalldevs", findalldevs, METH_VARARGS, "findalldevs() lists all available interfaces"},
  {"compile", bpf_compile, METH_VARARGS, "compile(linktype, snaplen, filter, optimize, netmask) creates a bpfprogram object"},
  {"create", pcap_create, METH_VARARGS, "create(device) is used to create a packet capture handle to look at packets on the network."},
  {NULL, NULL}
};

#if PY_MAJOR_VERSION >= 3
PyDoc_STRVAR(pcap_doc,
"A wrapper for the Packet Capture (PCAP) library");

static struct PyModuleDef pcapy_module = {
	PyModuleDef_HEAD_INIT,
	"pcapy",      /* m_name */
	pcap_doc,     /* m_doc */
	-1,           /* m_size */
	pcap_methods, /* m_methods */
	NULL,         /* m_reload */
	NULL,         /* m_traverse */
	NULL,         /* m_clear */
	NULL,         /* m_free */
};
#else

static char *pcap_doc =
"\nA wrapper for the Packet Capture (PCAP) library\n";
#endif //PY_MAJOR_VERSION >= 3


#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC
PyInit_pcapy(void)
#else
void
initpcapy(void)
#endif //PY_MAJOR_VERSION >= 3


{
  PyObject *m, *d;


#if PY_MAJOR_VERSION < 3
  Pcaptype.ob_type = &PyType_Type;
  Pkthdr_type.ob_type = &PyType_Type;
  Pdumpertype.ob_type = &PyType_Type;
#endif


#if PY_MAJOR_VERSION >= 3
  m = PyModule_Create(&pcapy_module);
#else
  m = Py_InitModule3("pcapy", pcap_methods, pcap_doc);
#endif

  if (PyType_Ready(&BPFProgramType) < 0) {
    #if PY_MAJOR_VERSION >= 3
    return NULL;
    #else
    return;
    #endif //PY_MAJOR_VERSION >= 3
  }

  PyModule_AddObject(m, "BPFProgram", (PyObject *) &BPFProgramType);

  /* Direct from pcap's net/bpf.h. */
  PyModule_AddIntConstant(m, "DLT_NULL", 0);
  PyModule_AddIntConstant(m, "DLT_EN10MB", 1);
  PyModule_AddIntConstant(m, "DLT_IEEE802", 6);
  PyModule_AddIntConstant(m, "DLT_ARCNET", 7);
  PyModule_AddIntConstant(m, "DLT_SLIP", 8);
  PyModule_AddIntConstant(m, "DLT_PPP", 9);
  PyModule_AddIntConstant(m, "DLT_FDDI", 10);
  PyModule_AddIntConstant(m, "DLT_ATM_RFC1483", 11);
  PyModule_AddIntConstant(m, "DLT_RAW", 12);
  PyModule_AddIntConstant(m, "DLT_PPP_SERIAL", 50);
  PyModule_AddIntConstant(m, "DLT_PPP_ETHER", 51);
  PyModule_AddIntConstant(m, "DLT_C_HDLC", 104);
  PyModule_AddIntConstant(m, "DLT_IEEE802_11", 105);
  PyModule_AddIntConstant(m, "DLT_LOOP", 108);
  PyModule_AddIntConstant(m, "DLT_LINUX_SLL", 113);
  PyModule_AddIntConstant(m, "DLT_LTALK", 114);

  /* Direct from pcap's net/pcap.h.*/
  PyModule_AddIntConstant(m, "PCAP_D_INOUT", 0);
  PyModule_AddIntConstant(m, "PCAP_D_IN", 1);
  PyModule_AddIntConstant(m, "PCAP_D_OUT", 2);

  d = PyModule_GetDict(m);
  PcapError = PyErr_NewException("pcapy.PcapError", NULL, NULL );
  BPFError = PyErr_NewException("pcapy.BPFError", NULL, NULL );
  if( PcapError )
  {
    PyDict_SetItemString( d, "PcapError", PcapError );
  }

  if ( BPFError )
  {
    PyDict_SetItemString( d, "BPFError", BPFError );
  }
#if PY_MAJOR_VERSION >= 3
  return m;
#endif  //PY_MAJOR_VERSION >= 3
}
/* vim: set tabstop=2 shiftwidth=2 expandtab: */

#ifdef WIN32
/* All of the following code takes care of LUID/GUID conversions.
 * Copied from Wireshark.
 */

 static BOOL gethexdigit(const char *p)
{
    if(*p >= '0' && *p <= '9'){
        return *p - '0';
    }else if(*p >= 'A' && *p <= 'F'){
        return *p - 'A' + 0xA;
    }else if(*p >= 'a' && *p <= 'f'){
        return *p - 'a' + 0xa;
    }else{
        return -1; /* Not a hex digit */
    }
}

 static BOOL get8hexdigits(const char *p, DWORD *d)
{
    int digit;
    DWORD val;
    int i;

     val = 0;
    for(i = 0; i < 8; i++){
        digit = gethexdigit(p++);
        if(digit == -1){
            return FALSE; /* Not a hex digit */
        }
        val = (val << 4) | digit;
    }
    *d = val;
    return TRUE;
}

 static BOOL get4hexdigits(const char *p, WORD *w)
{
    int digit;
    WORD val;
    int i;

     val = 0;
    for(i = 0; i < 4; i++){
        digit = gethexdigit(p++);
        if(digit == -1){
            return FALSE; /* Not a hex digit */
        }
        val = (val << 4) | digit;
    }
    *w = val;
    return TRUE;
}

 static BOOL
parse_as_guid(const char *guid_text, GUID *guid)
{
    int i;
    int digit1, digit2;

     if(*guid_text != '{'){
        return FALSE; /* Nope, not enclosed in {} */
    }
    guid_text++;
    /* There must be 8 hex digits; if so, they go into guid->Data1 */
    if(!get8hexdigits(guid_text, &guid->Data1)){
        return FALSE; /* nope, not 8 hex digits */
    }
    guid_text += 8;
    /* Now there must be a hyphen */
    if(*guid_text != '-'){
        return FALSE; /* Nope */
    }
    guid_text++;
    /* There must be 4 hex digits; if so, they go into guid->Data2 */
    if(!get4hexdigits(guid_text, &guid->Data2)){
        return FALSE; /* nope, not 4 hex digits */
    }
    guid_text += 4;
    /* Now there must be a hyphen */
    if(*guid_text != '-'){
        return FALSE; /* Nope */
    }
    guid_text++;
    /* There must be 4 hex digits; if so, they go into guid->Data3 */
    if(!get4hexdigits(guid_text, &guid->Data3)){
        return FALSE; /* nope, not 4 hex digits */
    }
    guid_text += 4;
    /* Now there must be a hyphen */
    if(*guid_text != '-'){
        return FALSE; /* Nope */
    }
    guid_text++;
    /*
     * There must be 4 hex digits; if so, they go into the first 2 bytes
     * of guid->Data4.
     */
    for(i = 0; i < 2; i++){
        digit1 = gethexdigit(guid_text);
        if(digit1 == -1){
            return FALSE; /* Not a hex digit */
        }
        guid_text++;
        digit2 = gethexdigit(guid_text);
        if(digit2 == -1){
            return FALSE; /* Not a hex digit */
        }
        guid_text++;
        guid->Data4[i] = (digit1 << 4)|(digit2);
    }
    /* Now there must be a hyphen */
    if(*guid_text != '-'){
        return FALSE; /* Nope */
    }
    guid_text++;
    /*
     * There must be 12 hex digits; if so,t hey go into the next 6 bytes
     * of guid->Data4.
     */
    for(i = 0; i < 6; i++){
        digit1 = gethexdigit(guid_text);
        if(digit1 == -1){
            return FALSE; /* Not a hex digit */
        }
        guid_text++;
        digit2 = gethexdigit(guid_text);
        if(digit2 == -1){
            return FALSE; /* Not a hex digit */
        }
        guid_text++;
        guid->Data4[i+2] = (digit1 << 4)|(digit2);
    }
    /* Now there must be a closing } */
    if(*guid_text != '}'){
        return FALSE; /* Nope */
    }
    guid_text++;
    /* And that must be the end of the string */
    if(*guid_text != '\0'){
        return FALSE; /* Nope */
    }
    return TRUE;
}


 static char* luid_to_guid(char *luid)
{
  char errbuff[PCAP_ERRBUF_SIZE];
  pcap_if_t *devs;

   int status = pcap_findalldevs(&devs, errbuff);
  if(status)
    {
      PyErr_SetString(PcapError, errbuff);
      return NULL;
    }

   if(devs==NULL)
    {
      PyErr_SetString(PcapError, "No valid interfaces to open");
      return NULL;
    }

   pcap_if_t *cursor = devs;

     char* cursor_luid;
    char *ret_guid = NULL;
    while(cursor)
    {
        cursor_luid = get_windows_interface_friendly_name(cursor->name);


         if (!strcmp(cursor_luid, luid))
        {
            ret_guid = strdup(cursor->name);
            goto done;
        }

         free(cursor_luid);

         cursor = cursor->next;
    }

 done:

   pcap_freealldevs(devs);

   return ret_guid;
}

 static char* guid_to_luid(GUID *guid)
{
    BOOL status;
    int size;
    char *name;

     WCHAR wName[128 + 1];
    HMODULE hIPHlpApi = LoadLibrary(TEXT("iphlpapi.dll"));

     typedef HRESULT (WINAPI *ProcAddr_nhGINFG) ( GUID *InterfaceGuid,  PCWSTR InterfaceAlias, DWORD *LengthAddress, wchar_t *a4, wchar_t *a5);

     ProcAddr_nhGINFG Proc_nhGetInterfaceNameFromGuid = NULL;
    Proc_nhGetInterfaceNameFromGuid = (ProcAddr_nhGINFG) GetProcAddress(hIPHlpApi, "NhGetInterfaceNameFromGuid");
    if (Proc_nhGetInterfaceNameFromGuid!= NULL)
    {
        wchar_t *p4=NULL, *p5=NULL;
        DWORD NameSize;

         /* testing of nhGetInterfaceNameFromGuid indicates the unpublished API function expects the 3rd parameter
        * to be the available space in bytes (as compared to wchar's) available in the second parameter buffer
        * to receive the friendly name (in unicode format) including the space for the nul termination.*/
        NameSize = sizeof(wName);

         /* do the guid->friendlyname lookup */
        status = ( 0 == Proc_nhGetInterfaceNameFromGuid(guid, wName, &NameSize, p4, p5) );
    }

     /* we have finished with iphlpapi.dll - release it */
    FreeLibrary(hIPHlpApi);

     if(FALSE == status){
        /* failed to get the friendly name, nothing further to do */
        return NULL;
    }

     /* Get the required buffer size, and then convert the string
    * from UTF-16 to UTF-8. */
    size=WideCharToMultiByte(CP_UTF8, 0, wName, -1, NULL, 0, NULL, NULL);
    name=(char *) malloc(size);
    if (name == NULL){
        return NULL;
    }
    size=WideCharToMultiByte(CP_UTF8, 0, wName, -1, name, size, NULL, NULL);
    if(size==0){
        /* bytes written == 0, indicating some form of error*/
        free(name);
        return NULL;
    }
    return name;
}

 char *
get_windows_interface_friendly_name(const char *interface_devicename)
{
    const char* guid_text;
    GUID guid;

     /* Extract the guid text from the interface device name */
    if(strncmp("\\Device\\NPF_", interface_devicename, 12)==0){
        guid_text=interface_devicename+12; /* skip over the '\Device\NPF_' prefix, assume the rest is the guid text */
    }else{
        guid_text=interface_devicename;

     }

     if (!parse_as_guid(guid_text, &guid)){
        return strdup(interface_devicename); /* not a GUID, so no friendly name */
    }

     /* guid okay, get the interface friendly name associated with the guid */
    return guid_to_luid(&guid);
}
#endif