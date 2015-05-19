# $Id: setup.py 47 2010-08-25 19:07:28Z aweil $

import sys, os
from setuptools import setup, Extension

PACKAGE_NAME = 'pcapy'

# You might want to change these to reflect your specific configuration
include_dirs = []
library_dirs = []
libraries = []

if sys.platform =='win32':
    # WinPcap include files
    include_dirs.append(r'c:\devel\oss\wpdpack\Include')
    # WinPcap library files
    library_dirs.append(r'c:\devel\oss\wpdpack\Lib')
    libraries = ['wpcap', 'packet', 'ws2_32']
else:
    libraries = ['pcap', 'stdc++']


# end of user configurable parameters
macros = []
sources = ['pcapdumper.cc',
           'bpfobj.cc',
           'pcapy.cc',
           'pcapobj.cc',
           'pcap_pkthdr.cc',
           ]

if sys.platform == 'win32':
    sources.append(os.path.join('win32', 'dllmain.cc'))
    macros.append(('WIN32', '1'))

# HACK replace linker gcc with g++
from distutils import sysconfig
save_init_posix = sysconfig._init_posix
def my_init_posix():
	save_init_posix()
	g = sysconfig._config_vars
	if g['LDSHARED'][:3]=='gcc':
		print 'my_init_posix: changing LDSHARED =',`g['LDSHARED']`,
		g['LDSHARED'] = 'g++'+g['LDSHARED'][3:]
		print 'to',`g['LDSHARED']`
sysconfig._init_posix = my_init_posix

setup(name = PACKAGE_NAME,
      version = "0.10.9",
      url = "https://github.com/CoreSecurity/pcapy",
      author = "CORE Security",
      author_email = "oss@coresecurity.com",
      maintainer = "CORE Security",
      maintainer_email = "oss@coresecurity.com",
      description = "Python pcap extension",
      license = "Apache modified",
      ext_modules = [Extension(
          name = PACKAGE_NAME,
          sources = sources,
          define_macros = macros,
          include_dirs = include_dirs,
          library_dirs = library_dirs,
          libraries = libraries)],
      scripts = ['tests/pcapytests.py', 'tests/96pings.pcap'],
      data_files = [(os.path.join('share', 'doc', PACKAGE_NAME),
                     ['README', 'LICENSE', 'pcapy.html'])],
      )

