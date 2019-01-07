import sys
import os
import glob
from setuptools import setup, Extension

PACKAGE_NAME = 'pcapy'

# You might want to change these to reflect your specific configuration
include_dirs = []
library_dirs = []
libraries = []

if sys.platform == 'win32':
    if os.environ.get('WPDPACK_BASE'):
        wpdpack = os.environ['WPDPACK_BASE']
        include_dirs.append(os.path.join(wpdpack, 'Include'))
        if sys.maxsize > 2**32:  # x64 Python interpreter
            library_dirs.append(os.path.join(wpdpack, 'Lib', 'x64'))
        else:  # x86 Python interpreter
            library_dirs.append(os.path.join(wpdpack, 'Lib'))
    else:
        # WinPcap include files
        include_dirs.append(r'c:\wpdpack\Include')
        # WinPcap library files
        if sys.maxsize > 2**32:  # x64 Python interpreter
            library_dirs.append(r'c:\wpdpack\Lib\x64')
        else:  # x86 Python interpreter
            library_dirs.append(r'c:\wpdpack\Lib')
    libraries = ['wpcap', 'packet', 'ws2_32']
else:
    libraries = ['pcap']


# end of user configurable parameters
macros = []
sources = ['pcapdumper.cc',
           'bpfobj.cc',
           'pcapobj.cc',
           'pcap_pkthdr.cc',
           'pcapy.cc'
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
    compiler = g['LDSHARED'].split()[0]
    flags = g['LDSHARED'].split()[1:]
    if compiler == 'gcc':
        g['LDSHARED'] = ' '.join(['g++'] + flags)
    elif compiler == 'clang':
        g['LDSHARED'] = ' '.join(['clang++'] + flags)
        print('my_init_posix: changing LDSHARED =',
              repr(g['LDSHARED']))
        print('to', repr(g['LDSHARED']))
sysconfig._init_posix = my_init_posix


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name=PACKAGE_NAME,
      version="0.11.5-dev",
      url="https://github.com/CoreSecurity/pcapy",
      author="CORE Security",
      author_email="oss@coresecurity.com",
      maintainer="CORE Security",
      maintainer_email="oss@coresecurity.com",
      platforms=["Unix", "Windows"],
      description="Python pcap extension",
      long_description=read('README'),
      license="Apache modified",
      ext_modules=[Extension(
          name=PACKAGE_NAME,
          sources=sources,
          define_macros=macros,
          include_dirs=include_dirs,
          library_dirs=library_dirs,
          libraries=libraries)],
      #scripts=['tests/pcapytests.py', 'tests/96pings.pcap'],
      data_files=[
          (os.path.join('share', 'doc', PACKAGE_NAME), ['README', 'LICENSE', 'pcapy.html']),
          (os.path.join('share', 'doc', PACKAGE_NAME, 'tests'), glob.glob('tests/*'))]
      )
