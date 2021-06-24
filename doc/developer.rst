.. toctree::

.. _developer-guide:

===============
Developer Guide
===============

This guide describes how to get started developing for Pcapyplus.

.. contents:: Table of Contents
   :local:


Setup Development Environment
=============================

#. Install ``pip3`` and development dependencies:

   .. code-block:: sh

      wget https://bootstrap.pypa.io/get-pip.py
      sudo python3 get-pip.py
      sudo pip3 install tox

#. Install a native toolchain to build extensions and other required tools:

   .. code-block:: sh

      sudo apt install python3-dev build-essential graphviz

#. Optionally, it is recommended to install the ``webdev`` package to run a
   development web server from a local directory:

   .. code-block:: sh

      sudo pip3 install webdev
      webdev .tox/doc/tmp/html


Building Package
================

.. code-block:: sh

   tox -e build

Output will be available at ``dist/``.

- Source distribution: ``pcapyplus-<version>.tar.gz``.
- Python wheel: ``pcapyplus-<version>-py3-none-any.whl``
- Binary wheel: ``pcapyplus-<version>-cp36-cp36m-linux_x86_64.whl``

.. note::

   The tags of the binary wheel will change depending on the interpreter and
   operating system you build the binary wheel on.


Building Documentation
======================

.. code-block:: sh

   tox -e doc

Output documentation will be available at ``.tox/doc/tmp/html``.
To view the documentation execute:

.. code-block:: sh

   webdev .tox/doc/tmp/html


Running Tests
=============

.. code-block:: sh

   tox -e test

Results will be available at ``.tox/test/tmp/``. To view the results
execute:

.. code-block:: sh

   webdev .tox/test/tmp/

- Test XML results: ``tests.xml``.
- Coverage XML results: ``coverage.xml``.
- Coverage HTML report: ``htmlcov/index.html``.
