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
#include <stdarg.h>

void cmd_new_env(const struct silofs_args *args, struct silofs_env **p_env)
{
	int err;

	err = silofs_create_env(args, p_env);
	if (err) {
		cmd_die(err, "failed to create fs instance");
	}
}

void cmd_del_env(struct silofs_env **p_env)
{
	if (p_env && *p_env) {
		silofs_destroy_env(*p_env);
		*p_env = nullptr;
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static char *cmd_baseref_path(const struct silofs_env *env)
{
	struct silofs_baseref baseref = {};

	silofs_get_baseref(env, &baseref);
	return cmd_path_join(baseref.repodir, baseref.refname);
}

static void cmd_report_err_and_die(const struct silofs_env *env, int status,
                                   const char *msg)
{
	char       *rpath = nullptr;
	const char *xmsg  = msg ? msg : "";
	const char *xtag  = msg ? ": " : "";
	int         err;

	/* no error */
	if (status == 0) {
		return;
	}

	rpath = cmd_baseref_path(env);

	/* internal errors */
	err = abs(status);
	switch (err) {
	case SILOFS_ENOREPO:
		cmd_die(err, "%s%smissing repo: %s", xmsg, xtag, rpath);
		break;
	case SILOFS_EBADREPO:
		cmd_die(err, "%s%sbad repo: %s", xmsg, xtag, rpath);
		break;
	case SILOFS_ENOMBR:
		cmd_die(err, "%s%smissing mbr: %s", xmsg, xtag, rpath);
		break;
	case SILOFS_EBADMBR:
		cmd_die(err, "%s%sbad mbr: %s", xmsg, xtag, rpath);
		break;
	case SILOFS_EMBRMODE:
		cmd_die(err, "%s%swrong mbr mode: %s", xmsg, xtag, rpath);
		break;
	case SILOFS_EKEYEXPIRED:
		cmd_die(err, "%s%sbad password: %s", xmsg, xtag, rpath);
		break;
	case SILOFS_EMOUNT:
		cmd_die(err, "%s%scan not mount: %s", xmsg, xtag, rpath);
		break;
	case SILOFS_EUMOUNT:
		cmd_die(err, "%s%scan not umount: %s", xmsg, xtag, rpath);
		break;
	case SILOFS_EFSCORRUPTED:
		cmd_die(err, "%s%scorrupted fs: %s", xmsg, xtag, rpath);
		break;
	case SILOFS_ECSUM:
		cmd_die(err, "%s%schecksum error: %s", xmsg, xtag, rpath);
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
		cmd_die(err, "%s%scan not lock: %s", xmsg, xtag, rpath);
		break;
	case EROFS:
		cmd_die(err, "%s%sread-only fs: %s", xmsg, xtag, rpath);
		break;
	case EUCLEAN:
		cmd_die(err, "%s%sunclean: %s", xmsg, xtag, rpath);
		break;
	case EKEYEXPIRED:
		cmd_die(err, "%s%sbad password: %s", xmsg, xtag, rpath);
		break;
	case ENOENT:
		cmd_diez("%s%snot exist: %s", xmsg, xtag, rpath);
		break;
	default:
		cmd_die(err, "%s%s%s", xmsg, xtag, rpath);
		break;
	}

	cmd_pstrfree(&rpath);
}

#define attr_printf34 silofs_attr_printf(3, 4)

attr_printf34 static void
cmd_report_err_and_dief(const struct silofs_env *env, int status,
                        const char *restrict fmt, ...)
{
	char    msg[1024];
	va_list ap = { 0 };
	int     ret;

	va_start(ap, fmt);
	ret = vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	if (ret < 0) {
		msg[0] = '\0';
	} else if (ret >= (int)sizeof(msg)) {
		msg[sizeof(msg) - 1] = '\0';
	}

	cmd_report_err_and_die(env, status, msg);
}

void cmd_format_repo(struct silofs_env *env)
{
	int err;

	err = silofs_format_repo(env);
	if (err) {
		cmd_report_err_and_die(env, err, "format repo failure");
	}
}

void cmd_open_repo(struct silofs_env *env)
{
	int err;

	err = silofs_open_repo(env);
	if (err) {
		cmd_report_err_and_die(env, err, "open repo failure");
	}
}

void cmd_close_repo(struct silofs_env *env)
{
	int err;

	err = silofs_close_repo(env);
	if (err) {
		cmd_report_err_and_die(env, err, "close repo failure");
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

void cmd_open_fs(struct silofs_env *env, const struct silofs_fsref *fsref)
{
	int err;

	err = silofs_open_fs(env, fsref);
	if (err) {
		cmd_die_by_fsref(env, err, "open failure", fsref);
	}
}

void cmd_close_fs(struct silofs_env *env)
{
	int err;

	err = silofs_close_fs(env);
	if (err) {
		cmd_report_err_and_die(env, err, "close failure");
	}
}

void cmd_exec_fs(struct silofs_env *env)
{
	int err;

	err = silofs_exec_fs(env);
	if (err) {
		cmd_report_err_and_die(env, err, "exec failure");
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

void cmd_archive_fs(struct silofs_env *env, const struct silofs_fsref *fsref,
                    struct silofs_fsref *out_fsref)
{
	int err;

	err = silofs_archive_fs(env, fsref, out_fsref);
	if (err) {
		cmd_die_by_fsref(env, err, "archive failure", fsref);
	}
}

void cmd_restore_fs(struct silofs_env *env, const struct silofs_fsref *fsref,
                    struct silofs_fsref *out_fsref)
{
	int err;

	err = silofs_restore_fs(env, fsref, out_fsref);
	if (err) {
		cmd_die_by_fsref(env, err, "restore failure", fsref);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_setup_args(struct silofs_args *args)
{
	memset(args, 0, sizeof(*args));
	cmd_fsids_setup(&args->fsids);
	args->uid   = getuid();
	args->gid   = getgid();
	args->pid   = getpid();
	args->umask = 0077;
}

void cmd_destroy_args(struct silofs_args *args)
{
	cmd_fsids_clear(&args->fsids);
	memset(args, 0, sizeof(*args));
}
