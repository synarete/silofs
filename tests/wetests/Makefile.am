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

noinst_SCRIPTS = wetests-lint.sh

CLEANFILES = silofs-wetests
EXTRA_DIST = $(NULL)
EXTRA_DIST += silofs-wetests.in
EXTRA_DIST += wetests-lint.sh
EXTRA_DIST += pylintrc


silofs-wetests: silofs-wetests.in
	@echo "  SED      $@"; $(PATSUBST) "$<" > "$@" ; chmod +x "$@" ;

all-local: wetests-lint.sh
	@echo "  PYLINT     "; sh "$<" $(srcdir) ;
