silofs_archivedir = $(pythondir)/silofs/archive
silofs_archive_PYTHON = $(NULL)
silofs_archive_PYTHON += __init__.py
silofs_archive_PYTHON += __main__.py
silofs_archive_PYTHON += archive.py
silofs_archive_PYTHON += blobs.py
silofs_archive_PYTHON += execute.py
silofs_archive_PYTHON += local.py
silofs_archive_PYTHON += model.py
silofs_archive_PYTHON += remote.py
silofs_archive_PYTHON += subcmd.py
silofs_archive_PYTHON += utils.py

CLEANFILES = pycheck-archive

pycheck-archive: $(silofs_archive_PYTHON)
	@echo "  PYCHECK  $@";
	@VERBOSE=0 "$(srcdir)/../pycheck.sh" "$(srcdir)" > "$@" ;

all-local: pycheck-archive
