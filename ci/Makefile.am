-include $(top_builddir)/common.mk
-include $(top_builddir)/sedsub.mk

bin_SCRIPTS = $(NULL)
bin_SCRIPTS += silofs-ci-tests
noinst_SCRIPTS = pylint.sh

silofs_ci_testsdir = $(pythondir)/silofs/ci
nobase_silofs_ci_tests_PYTHON = $(NULL)
nobase_silofs_ci_tests_PYTHON += __init__.py
nobase_silofs_ci_tests_PYTHON += main.py
nobase_silofs_ci_tests_PYTHON += tests/__init__.py
nobase_silofs_ci_tests_PYTHON += tests/cmd.py
nobase_silofs_ci_tests_PYTHON += tests/ctx.py
nobase_silofs_ci_tests_PYTHON += tests/fsutils.py
nobase_silofs_ci_tests_PYTHON += tests/run.py
nobase_silofs_ci_tests_PYTHON += tests/test_basics.py

CLEANFILES = silofs-ci-tests pylint-ci-tests
EXTRA_DIST = $(NULL)
EXTRA_DIST += silofs-ci-tests.in
EXTRA_DIST += pylint.sh
EXTRA_DIST += pylintrc

silofs-ci-tests: silofs-ci-tests.in
	@echo "  SED      $@"; $(PATSUBST) "$<" > "$@" ; chmod +x "$@" ;

pylint-ci-tests: $(nobase_silofs_ci_tests_PYTHON)
	@echo "  PYLINT   $@"; sh "$(srcdir)/pylint.sh" "$(srcdir)" > "$@" ;

all-local: pylint-ci-tests
