/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "cmd.h"

void cmd_new_env(const struct silofs_args *env_args, struct silofs_env **p_env)
{
	int err;

	err = silofs_create_env(env_args, p_env);
	if (err) {
		cmd_die(err, "failed to create fs instance");
	}
}

void cmd_del_env(struct silofs_env **p_env)
{
	if (p_env && *p_env) {
		silofs_destroy_env(*p_env);
		*p_env = NULL;
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static char *cmd_repodir_name(const struct silofs_env *env)
{
	struct silofs_args args;
	char *ret = NULL;

	silofs_get_args(env, &args);
	cmd_join_path(args.boot.repodir, args.boot.fsname, &ret);
	return ret;
}

static void cmd_report_err_and_die(const struct silofs_env *env, int status,
                                   const char *msg)
{
	char *rname = NULL;
	const char *xmsg = msg ? msg : "";
	const char *xtag = msg ? ": " : "";
	int err;

	/* no error */
	if (status == 0) {
		return;
	}
	rname = cmd_repodir_name(env);

	/* internal errors */
	err = abs(status);
	switch (err) {
	case SILOFS_ENOREPO:
		cmd_die(err, "%s%smissing repo: %s", xmsg, xtag, rname);
		break;
	case SILOFS_EBADREPO:
		cmd_die(err, "%s%sbad repo: %s", xmsg, xtag, rname);
		break;
	case SILOFS_ENOREF:
		cmd_die(err, "%s%smissing ref: %s", xmsg, xtag, rname);
		break;
	case SILOFS_EBADREF:
		cmd_die(err, "%s%sbad ref: %s", xmsg, xtag, rname);
		break;
	case SILOFS_ENOUBER:
		cmd_die(err, "%s%smissing boot: %s", xmsg, xtag, rname);
		break;
	case SILOFS_EBADUBER:
		cmd_die(err, "%s%sbad boot: %s", xmsg, xtag, rname);
		break;
	case SILOFS_EKEYEXPIRED:
		cmd_die(err, "%s%sbad password: %s", xmsg, xtag, rname);
		break;
	case SILOFS_EMOUNT:
		cmd_die(err, "%s%scan not mount: %s", xmsg, xtag, rname);
		break;
	case SILOFS_EUMOUNT:
		cmd_die(err, "%s%scan not umount: %s", xmsg, xtag, rname);
		break;
	case SILOFS_EFSCORRUPTED:
		cmd_die(err, "%s%scorrupted fs: %s", xmsg, xtag, rname);
		break;
	case SILOFS_ECSUM:
		cmd_die(err, "%s%schecksum error: %s", xmsg, xtag, rname);
		break;
	case SILOFS_EILLSTR:
		cmd_die(err, "%s%sillegal string", xmsg, xtag);
		break;
	default:
		break;
	}

	/* standard errors */
	err = abs(silofs_remap_status_code(status));
	switch (err) {
	case EWOULDBLOCK:
		cmd_die(err, "%s%scan not lock: %s", xmsg, xtag, rname);
		break;
	case EROFS:
		cmd_die(err, "%s%sread-only fs: %s", xmsg, xtag, rname);
		break;
	case EUCLEAN:
		cmd_die(err, "%s%sunclean: %s", xmsg, xtag, rname);
		break;
	case EKEYEXPIRED:
		cmd_die(err, "%s%sbad password: %s", xmsg, xtag, rname);
		break;
	case ENOENT:
		cmd_die(0, "%s%snot exist: %s", xmsg, xtag, rname);
		break;
	default:
		cmd_die(err, "%s%s%s", xmsg, xtag, rname);
		break;
	}

	cmd_pstrfree(&rname);
}

static void
cmd_require_ok(const struct silofs_env *env, int status, const char *msg)
{
	if (status != 0) {
		cmd_report_err_and_die(env, status, msg);
	}
}

silofs_attr_printf(3, 4) static void cmd_require_okf(
	const struct silofs_env *env, int status, const char *fmt, ...)
{
	char msg[512] = "";
	va_list ap;

	if (status != 0) {
		va_start(ap, fmt);
		vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
		va_end(ap);
		cmd_report_err_and_die(env, status, msg);
	}
}

void cmd_format_repo(struct silofs_env *env)
{
	int err;

	err = silofs_format_repo(env);
	cmd_require_ok(env, err, "failed to format repo");
}

void cmd_open_repo(struct silofs_env *env)
{
	int err;

	err = silofs_open_repo(env);
	cmd_require_ok(env, err, "failed to open repo");
}

void cmd_close_repo(struct silofs_env *env)
{
	int err;

	err = silofs_close_repo(env);
	cmd_require_ok(env, err, "failed to close repo");
}

void cmd_poke_fs(struct silofs_env *env)
{
	int err;

	err = silofs_poke_fs(env);
	cmd_require_ok(env, err, "can not poke fs");
}

void cmd_poke_ar(struct silofs_env *env, const struct silofs_xref *ba)
{
	int err;

	err = silofs_poke_ar(env, ba);
	cmd_require_okf(env, err, "can not poke archive '%s'", ba->s);
}

void cmd_format_fs(struct silofs_env *env, struct silofs_xref *out_xref)
{
	int err;

	err = silofs_format_fs(env);
	cmd_require_ok(env, err, "failed to format fs");
	err = silofs_get_fs_xref(env, out_xref);
	cmd_require_ok(env, err, "post format fs failure");
}

void cmd_close_fs(struct silofs_env *env)
{
	int err;

	err = silofs_close_fs(env);
	cmd_require_ok(env, err, "failed to close fs");
}

void cmd_open_fs(struct silofs_env *env)
{
	int err;

	err = silofs_open_fs(env);
	cmd_require_ok(env, err, "failed to open fs");
}

void cmd_exec_fs(struct silofs_env *env)
{
	int err;

	err = silofs_run_fs(env);
	cmd_require_ok(env, err, "failed to exec fs");
}

void cmd_fork_fs(struct silofs_env *env, struct silofs_xrefs *out_bas)
{
	int err;

	err = silofs_fork_fs(env, out_bas);
	cmd_require_ok(env, err, "failed to fork fs");
}

void cmd_unref_fs(struct silofs_env *env)
{
	int err;

	err = silofs_unref_fs(env);
	cmd_require_ok(env, err, "failed to unref fs");
}

void cmd_inspect_fs(struct silofs_env *env, silofs_visit_laddr_fn cb,
                    void *user_ctx)
{
	int err;

	err = silofs_inspect_fs(env, cb, user_ctx);
	cmd_require_ok(env, err, "inspect-fs error");
}

void cmd_archive_fs(struct silofs_env *env, struct silofs_xref *out_xref)
{
	int err;

	err = silofs_archive_fs(env);
	cmd_require_ok(env, err, "failed to archive");
	err = silofs_get_ar_xref(env, out_xref);
	cmd_require_ok(env, err, "resolve archive failure");
}

void cmd_restore_fs(struct silofs_env *env, struct silofs_xref *out_ba)
{
	int err;

	err = silofs_restore_fs(env, out_ba);
	cmd_require_ok(env, err, "restore-fs failure");
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_setup_env_args(struct silofs_args *args)
{
	memset(args, 0, sizeof(*args));
	cmd_fs_ids_init(&args->ids);
	args->uid = getuid();
	args->gid = getgid();
	args->pid = getpid();
	args->umask = 0022;
}

void cmd_destroy_env_args(struct silofs_args *args)
{
	cmd_fs_ids_fini(&args->ids);
	memset(args, 0, sizeof(*args));
}
