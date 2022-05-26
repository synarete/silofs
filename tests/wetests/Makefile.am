-include $(top_builddir)/common.mk
-include $(top_builddir)/sedsub.mk

bin_SCRIPTS = $(NULL)
bin_SCRIPTS += silofs-wetests

nobase_python_PYTHON = $(NULL)
nobase_python_PYTHON += silofs/__init__.py
nobase_python_PYTHON += silofs/wetestsmain.py
nobase_python_PYTHON += silofs/wetests/__init__.py
nobase_python_PYTHON += silofs/wetests/cmd.py
nobase_python_PYTHON += silofs/wetests/ctx.py
nobase_python_PYTHON += silofs/wetests/run.py
nobase_python_PYTHON += silofs/wetests/test_basics.py

EXTRA_DIST = silofs-wetests.in
CLEANFILES = silofs-wetests

silofs-wetests: silofs-wetests.in
	@echo "  SED      $@"; $(PATSUBST) "$<" > "$@" ; chmod +x "$@" ;
