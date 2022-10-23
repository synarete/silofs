-include $(top_builddir)/common.mk
-include $(top_builddir)/sedsub.mk

dist_bin_SCRIPTS = silofs-citests
noinst_SCRIPTS = pylint.sh

silofs_citestsdir = $(pythondir)/silofs/citests
silofs_citests_PYTHON = $(NULL)
silofs_citests_PYTHON += __init__.py
silofs_citests_PYTHON += __main__.py
silofs_citests_PYTHON += cmd.py
silofs_citests_PYTHON += ctx.py
silofs_citests_PYTHON += expect.py
silofs_citests_PYTHON += run.py
silofs_citests_PYTHON += test_all.py
silofs_citests_PYTHON += test_basic.py
silofs_citests_PYTHON += test_fsck.py
silofs_citests_PYTHON += test_io.py
silofs_citests_PYTHON += test_pack.py
silofs_citests_PYTHON += test_self.py
silofs_citests_PYTHON += test_snap.py
silofs_citests_PYTHON += test_xprogs.py
silofs_citests_PYTHON += utils.py

EXTRA_DIST = $(NULL)
EXTRA_DIST += silofs-citests.in
EXTRA_DIST += pylint.sh
EXTRA_DIST += pylintrc

CLEANFILES = pylint-citests silofs-citests

silofs-citests: silofs-citests.in
	@echo "  SED      $@"; $(PATSUBST) "$<" > "$@" ; chmod +x "$@" ;

pylint-citests: $(silofs_citests_PYTHON)
	@echo "  PYLINT   $@"; sh "$(srcdir)/pylint.sh" "$(srcdir)" > "$@" ;

all-local: pylint-citests
