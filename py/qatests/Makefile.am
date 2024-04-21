silofs_qatestsdir = $(pythondir)/silofs/qatests
silofs_qatests_PYTHON = $(NULL)
silofs_qatests_PYTHON += __init__.py
silofs_qatests_PYTHON += __main__.py
silofs_qatests_PYTHON += bconf.py
silofs_qatests_PYTHON += cmd.py
silofs_qatests_PYTHON += ctx.py
silofs_qatests_PYTHON += expect.py
silofs_qatests_PYTHON += log.py
silofs_qatests_PYTHON += run.py
silofs_qatests_PYTHON += start.py
silofs_qatests_PYTHON += test_all.py
silofs_qatests_PYTHON += test_fillfs.py
silofs_qatests_PYTHON += test_fio.py
silofs_qatests_PYTHON += test_basic.py
silofs_qatests_PYTHON += test_fsck.py
silofs_qatests_PYTHON += test_io.py
silofs_qatests_PYTHON += test_ltp.py
silofs_qatests_PYTHON += test_self.py
silofs_qatests_PYTHON += test_snap.py
silofs_qatests_PYTHON += test_view.py
silofs_qatests_PYTHON += test_xprogs.py
silofs_qatests_PYTHON += utils.py

pycheck = $(srcdir)/../pycheck.sh
pycheck_verbose = $(pycheck_verbose_@AM_V@)
pycheck_verbose_ = $(pycheck_verbose_@AM_DEFAULT_V@)
pycheck_verbose_0 = $(AM_V)echo "  PYCHECK  $@";

CLEANFILES = pycheck-qatests

pycheck-qatests: $(silofs_qatests_PYTHON)
	$(pycheck_verbose)VERBOSE=0 "$(pycheck)" "$(srcdir)" > "$@" ;

all-local: pycheck-qatests
