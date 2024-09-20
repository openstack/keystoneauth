# keystoneauth1 documentation build configuration file

import os
import sys


sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
)
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
)

# -- General configuration ----------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom ones.
extensions = [
    'sphinx.ext.todo',
    'sphinx.ext.coverage',
    'sphinx.ext.intersphinx',
    'openstackdocstheme',
    'ext.list_plugins',
    'sphinxcontrib.apidoc',
]

# sphinxcontrib.apidoc options
apidoc_module_dir = '../../keystoneauth1'
apidoc_output_dir = 'api'
apidoc_excluded_paths = ['hacking', 'tests/*', 'tests', 'test']
apidoc_separate_modules = True
todo_include_todos = True

# Add any paths that contain templates here, relative to this directory.
# templates_path = ['_templates']

# The suffix of source filenames.
source_suffix = '.rst'

# The master toctree document.
master_doc = 'index'

# General information about the project.
project = 'keystoneauth1'
copyright = 'OpenStack Contributors'

# List of directories, relative to source directory, that shouldn't be searched
# for source files.
exclude_trees = []

# If true, '()' will be appended to :func: etc. cross-reference text.
add_function_parentheses = True

# If true, the current module name will be prepended to all description
# unit titles (such as .. function::).
add_module_names = True

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'native'

# A list of ignored prefixes for module index sorting.
modindex_common_prefix = ['keystoneauth1.']


# -- Options for HTML output --------------------------------------------------

# The theme to use for HTML and HTML Help pages.
html_theme = 'openstackdocs'


# -- Options for LaTeX output -------------------------------------------------

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title, author, documentclass [howto/manual])
# .
latex_documents = [
    (
        'index',
        'doc-keystoneauth.tex',
        'keystoneauth1 Documentation',
        'Openstack Developers',
        'manual',
        True,
    )
]

# Disable usage of xindy https://bugzilla.redhat.com/show_bug.cgi?id=1643664
latex_use_xindy = False

latex_domain_indices = False

latex_elements = {
    'makeindex': '',
    'printindex': '',
    'preamble': r'\setcounter{tocdepth}{3}',
}

intersphinx_mapping = {
    'python': ('http://docs.python.org/', None),
    'osloconfig': ('https://docs.openstack.org/oslo.config/latest/', None),
    'keystoneclient': (
        'https://docs.openstack.org/python-keystoneclient/latest/',
        None,
    ),
}


# -- Options for openstackdocstheme -------------------------------------------

openstackdocs_repo_name = 'openstack/keystoneauth'
openstackdocs_pdf_link = True
openstackdocs_auto_name = False
openstackdocs_bug_project = 'keystoneauth'
openstackdocs_bug_tag = 'doc'
