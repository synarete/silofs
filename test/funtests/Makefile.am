-include $(top_builddir)/common.mk
-include $(top_builddir)/sedsub.mk

bin_SCRIPTS = $(NULL)
bin_SCRIPTS += silofs-funtests

nobase_python_PYTHON = $(NULL)
nobase_python_PYTHON += silofs/__init__.py
nobase_python_PYTHON += silofs/funtestsmain.py
nobase_python_PYTHON += silofs/funtests/__init__.py
nobase_python_PYTHON += silofs/funtests/context.py
nobase_python_PYTHON += silofs/funtests/test_basics.py
nobase_python_PYTHON += silofs/funtests/tests.py

EXTRA_DIST = silofs-funtests.in
CLEANFILES = silofs-funtests

silofs-funtests: silofs-funtests.in
	@echo "  SED      $@"; $(PATSUBST) "$<" > "$@" ; chmod +x "$@" ;
