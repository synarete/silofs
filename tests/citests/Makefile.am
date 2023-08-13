-include $(top_builddir)/common.mk
-include $(top_builddir)/sedsub.mk

dist_bin_SCRIPTS = silofs-citests
noinst_SCRIPTS = pycheck.sh

silofs_citestsdir = $(pythondir)/silofs/citests
silofs_citests_PYTHON = $(NULL)
silofs_citests_PYTHON += __init__.py
silofs_citests_PYTHON += __main__.py
silofs_citests_PYTHON += cmd.py
silofs_citests_PYTHON += ctx.py
silofs_citests_PYTHON += expect.py
silofs_citests_PYTHON += log.py
silofs_citests_PYTHON += run.py
silofs_citests_PYTHON += start.py
silofs_citests_PYTHON += test_all.py
silofs_citests_PYTHON += test_fillfs.py
silofs_citests_PYTHON += test_basic.py
silofs_citests_PYTHON += test_fsck.py
silofs_citests_PYTHON += test_io.py
silofs_citests_PYTHON += test_ltp.py
silofs_citests_PYTHON += test_self.py
silofs_citests_PYTHON += test_snap.py
silofs_citests_PYTHON += test_xprogs.py
silofs_citests_PYTHON += utils.py

EXTRA_DIST = $(NULL)
EXTRA_DIST += silofs-citests.in
EXTRA_DIST += pycheck.sh
EXTRA_DIST += pylintrc

CLEANFILES = pycheck-citests silofs-citests

silofs-citests: silofs-citests.in
	@echo "  SED      $@"; $(PATSUBST) "$<" > "$@" ; chmod +x "$@" ;

pycheck-citests: $(silofs_citests_PYTHON)
	@echo "  PYCHECK  $@"; \
		VERBOSE=0 sh -c "$(srcdir)/pycheck.sh" "$(srcdir)" > "$@" ;

all-local: pycheck-citests
