/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
 *
 * Silofs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#define _GNU_SOURCE 1
#include "cmd.h"
#include <silofs/snprintf.h>
#include <stdarg.h>

static void cmd_env_create(enum silofs_flags flags, struct silofs_env **penv)
{
	int err;

	err = silofs_create_env(0, flags, penv);
	if (err) {
		cmd_die(err, "failed to create env: flags=0x%x", flags);
	}
}

static void
cmd_env_open(struct silofs_env *env, const struct silofs_spec *spec)
{
	int err;

	err = silofs_open_env(env, spec);
	if (err) {
		cmd_die(err, "failed to open env: %s", spec->bref[0].repodir);
	}
}

void cmd_env_setup(const struct silofs_spec *spec, struct silofs_env **penv)
{
	cmd_env_create(spec->flags, penv);
	cmd_env_open(*penv, spec);
}

void cmd_env_destroy(struct silofs_env **penv)
{
	if ((penv != nullptr) && (*penv != nullptr)) {
		silofs_destroy_env(*penv);
		*penv = nullptr;
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_report_err_and_die(const struct silofs_env *env, int status,
                                   const char *msg)
{
	const char *xmsg = msg ? msg : "";
	const char *xtag = msg ? ": " : "";
	int err;

	/* no error */
	if (status == 0) {
		return;
	}

	/* internal errors */
	err = abs(status);
	switch (err) {
	case SILOFS_ENOREPO:
		cmd_die(err, "%s%smissing repo", xmsg, xtag);
		break;
	case SILOFS_EBADREPO:
		cmd_die(err, "%s%sbad repo", xmsg, xtag);
		break;
	case SILOFS_ENOMBR:
		cmd_die(err, "%s%smissing mbr", xmsg, xtag);
		break;
	case SILOFS_EBADMBR:
		cmd_die(err, "%s%sbad mbr", xmsg, xtag);
		break;
	case SILOFS_EMBRMODE:
		cmd_die(err, "%s%swrong mbr mode", xmsg, xtag);
		break;
	case SILOFS_EKEYEXPIRED:
		cmd_die(err, "%s%sbad password", xmsg, xtag);
		break;
	case SILOFS_EMOUNT:
		cmd_die(err, "%s%smount failure", xmsg, xtag);
		break;
	case SILOFS_EUMOUNT:
		cmd_die(err, "%s%sumount error", xmsg, xtag);
		break;
	case SILOFS_EFSCORRUPTED:
		cmd_die(err, "%s%scorrupted fs", xmsg, xtag);
		break;
	case SILOFS_ECSUM:
		cmd_die(err, "%s%schecksum error", xmsg, xtag);
		break;
	case SILOFS_EILLSTR:
		cmd_die(err, "%s%sillegal string", xmsg, xtag);
		break;
	case SILOFS_EILLPASS:
		cmd_die(err, "%s%spassword is not FIPS 140-2 compliant", xmsg,
		        xtag);
		break;
	default:
		break;
	}

	/* standard errors */
	err = abs(silofs_remap_status_code(status));
	switch (err) {
	case EWOULDBLOCK:
		cmd_die(err, "%s%scan not lock", xmsg, xtag);
		break;
	case EROFS:
		cmd_die(err, "%s%sread-only fs", xmsg, xtag);
		break;
	case EUCLEAN:
		cmd_die(err, "%s%sunclean", xmsg, xtag);
		break;
	case EKEYEXPIRED:
		cmd_die(err, "%s%sbad password", xmsg, xtag);
		break;
	case ENOENT:
		cmd_diez("%s%snot exist", xmsg, xtag);
		break;
	default:
		cmd_die(err, "%s%s", xmsg, xtag);
		break;
	}

	/* TODO: pass ctx and use */
	(void)env;
}

#define attr_printf34 silofs_attr_printf(3, 4)

attr_printf34 static void
cmd_report_err_and_dief(const struct silofs_env *env, int status,
                        const char *fmt, ...)
{
	char msg[1024] = "";
	va_list ap;

	va_start(ap, fmt);
	silofs_vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	cmd_report_err_and_die(env, status, msg);
}

void cmd_format_repo(struct silofs_env *env)
{
	int err;

	err = silofs_format_repo(env);
	if (err) {
		cmd_report_err_and_die(env, err, "format repo error");
	}
}

static void
cmd_die_by_fsref(const struct silofs_env *env, int err, const char *msg_prefix,
                 const struct silofs_fsref *fsref)
{
	cmd_report_err_and_dief(env, err, "%s: %s", msg_prefix,
	                        fsref->mbaddr.mba);
}

void cmd_sense_fs(struct silofs_env *env, const struct silofs_fsref *fsref)
{
	int err;

	err = silofs_sense_fs(env, fsref);
	if (err) {
		cmd_die_by_fsref(env, err, "sense failure", fsref);
	}
}

void cmd_format_fs(struct silofs_env *env, struct silofs_fsref *out_fsref)
{
	int err;

	err = silofs_format_fs(env, out_fsref);
	if (err) {
		cmd_report_err_and_die(env, err, "format failure");
	}
}

void cmd_reload_fs(struct silofs_env *env, const struct silofs_fsref *fsref)
{
	int err;

	err = silofs_reload_fs(env, fsref);
	if (err) {
		cmd_die_by_fsref(env, err, "reload failure", fsref);
	}
}

void cmd_unload_fs(struct silofs_env *env)
{
	int err;

	err = silofs_unload_fs(env);
	if (err) {
		cmd_report_err_and_die(env, err, "close failure");
	}
}

void cmd_exec_fs(struct silofs_env *env, const char *mntdir)
{
	int err;

	err = silofs_exec_fs(env, mntdir);
	if (err) {
		cmd_report_err_and_dief(env, err, "exec failure: mntdir=%s",
		                        mntdir);
	}
}

void cmd_fork_fs(struct silofs_env *env, struct silofs_fsrefs *out_fsrefs)
{
	int err;

	err = silofs_fork_fs(env, out_fsrefs);
	if (err) {
		cmd_report_err_and_die(env, err, "fork failure");
	}
}

void cmd_remove_fs(struct silofs_env *env, const struct silofs_fsref *fsref)
{
	int err;

	err = silofs_remove_fs(env, fsref);
	if (err) {
		cmd_die_by_fsref(env, err, "remove failure", fsref);
	}
}

void cmd_inspect_fs(struct silofs_env *env, bool view)
{
	int err;

	err = silofs_inspect_fs(env, view);
	if (err) {
		cmd_report_err_and_die(env, err, "failed to inspect");
	}
}
