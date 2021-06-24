# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Hewlett Packard Enterprise Development LP.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.


"""
Sphinx configuration file.
"""

from sphinx_readable_theme import get_html_theme_path

from pcapyplus import __version__ as version


########################
# Project Setup        #
########################

# Extensions to enable for this project.
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.inheritance_diagram',
    'sphinx.ext.intersphinx',
    'autoapi.sphinx',
    'plantweb.directive',
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# The suffix(es) of source filenames (.rst, .md).
source_suffix = ['.rst']

# The master toctree document.
master_doc = 'index'


########################
# Project Information  #
########################

project = 'Pcapyplus'
author = 'Hewlett Packard Enterprise Development LP'
copyright = '2021, ' + author
release = version


########################
# HTML Output          #
########################

html_theme = 'readable'

# Add any paths that contain custom themes here, relative to this directory.
html_theme_path = [get_html_theme_path()]

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# Add any extra paths that contain custom files (such as robots.txt or
# .htaccess) here, relative to this directory. These files are copied
# directly to the root of the documentation.
html_extra_path = []

# If not '', a 'Last updated on:' timestamp is inserted at every page bottom,
# using the given strftime format.
html_last_updated_fmt = '%Y-%m-%d'


# Add style overrides
def setup(app):
    app.add_css_file('styles/custom.css')


########################
# Plugins Setup        #
########################

# autoapi configuration
autoapi_modules = {
    'pcapyplus': None,
}

# Plantweb configuration
plantweb_defaults = {
    'use_cache': True,
    'format': 'svg',
}

# Configure Graphviz
graphviz_output_format = 'svg'

# Example configuration for intersphinx: refer to the Python standard library.
intersphinx_mapping = {
    'python': ('https://docs.python.org/3.8', None)
}
