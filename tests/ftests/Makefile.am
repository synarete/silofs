-include $(top_builddir)/common.mk
-include $(top_builddir)/sedsub.mk

bin_SCRIPTS = $(NULL)
bin_SCRIPTS += silofs-ftests

nobase_python_PYTHON = $(NULL)
nobase_python_PYTHON += silofs/__init__.py
nobase_python_PYTHON += silofs/funtestsmain.py
nobase_python_PYTHON += silofs/funtests/__init__.py
nobase_python_PYTHON += silofs/funtests/context.py
nobase_python_PYTHON += silofs/funtests/test_basics.py
nobase_python_PYTHON += silofs/funtests/tests.py

EXTRA_DIST = silofs-ftests.in
CLEANFILES = silofs-ftests

silofs-ftests: silofs-ftests.in
	@echo "  SED      $@"; $(PATSUBST) "$<" > "$@" ; chmod +x "$@" ;
