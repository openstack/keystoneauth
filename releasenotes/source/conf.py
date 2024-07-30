# keystoneauth Release Notes documentation build configuration file

# -- General configuration ------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'openstackdocstheme',
    'reno.sphinxext',
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# The suffix of source filenames.
source_suffix = '.rst'

# The master toctree document.
master_doc = 'index'

# General information about the project.
project = 'keystoneauth Release Notes'
copyright = '2015-, Keystone Developers'

# Release notes are version independent.

# The short X.Y version.

# The full version, including alpha/beta/rc tags.
release = ''
# The short X.Y version.
version = ''

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = []

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'native'


# -- Options for HTML output ----------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
html_theme = 'openstackdocs'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']


# -- Options for LaTeX output ---------------------------------------------

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title,
#  author, documentclass [howto, manual, or own class]).
latex_documents = [
    (
        'index',
        'keystoneauthReleaseNotes.tex',
        'keystoneauth Release Notes Documentation',
        'Keystone Developers',
        'manual',
    ),
]


# -- Options for Internationalization output ------------------------------
locale_dirs = ['locale/']


# -- Options for openstackdocstheme -------------------------------------------
openstackdocs_repo_name = 'openstack/keystoneauth'
openstackdocs_auto_name = False
openstackdocs_bug_project = 'keystoneauth'
openstackdocs_bug_tag = 'doc'
