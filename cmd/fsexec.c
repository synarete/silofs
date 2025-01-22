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
#include "cmd.h"

void cmd_new_env(const struct silofs_env_args *env_args,
                 struct silofs_env **p_env)
{
	int err;

	err = silofs_new_env(env_args, p_env);
	if (err) {
		cmd_die(err, "failed to create fs instance");
	}
}

void cmd_del_env(struct silofs_env **p_env)
{
	if (p_env && *p_env) {
		silofs_del_env(*p_env);
		*p_env = NULL;
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static char *cmd_repodir_name(const struct silofs_env *env)
{
	const struct silofs_bootref *bref = &env->args.bref;
	char *ret = NULL;

	cmd_join_path(bref->repodir, bref->name, &ret);
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
	case SILOFS_ENOBOOT:
		cmd_die(err, "%s%smissing boot: %s", xmsg, xtag, rname);
		break;
	case SILOFS_EBADBOOT:
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

void cmd_poke_fs(struct silofs_env *env, const struct silofs_bootref *bref)
{
	int err;

	err = silofs_poke_fs(env, &bref->caddr);
	cmd_require_ok(env, err, "can not poke fs");
}

void cmd_poke_archive(struct silofs_env *env,
                      const struct silofs_bootref *bref)
{
	int err;

	err = silofs_poke_archive(env, &bref->caddr);
	cmd_require_ok(env, err, "can not poke archive");
}

void cmd_format_fs(struct silofs_env *env, struct silofs_bootref *bref)
{
	int err;

	err = silofs_format_fs(env, &bref->caddr);
	cmd_require_ok(env, err, "failed to format fs");
}

void cmd_close_fs(struct silofs_env *env)
{
	int err;

	err = silofs_close_fs(env);
	cmd_require_ok(env, err, "failed to close fs");
}

void cmd_open_fs(struct silofs_env *env, const struct silofs_bootref *bref)
{
	int err;

	err = silofs_open_fs(env, &bref->caddr);
	cmd_require_ok(env, err, "failed to open fs");
}

void cmd_exec_fs(struct silofs_env *env)
{
	int err;

	err = silofs_run_fs(env);
	cmd_require_ok(env, err, "failed to exec fs");
}

void cmd_fork_fs(struct silofs_env *env, struct silofs_caddr *out_new,
                 struct silofs_caddr *out_alt)
{
	int err;

	err = silofs_fork_fs(env, out_new, out_alt);
	cmd_require_ok(env, err, "failed to fork fs");
}

void cmd_unref_fs(struct silofs_env *env, const struct silofs_bootref *bref)
{
	int err;

	err = silofs_unref_fs(env, &bref->caddr);
	cmd_require_ok(env, err, "unref-fs error");
}

void cmd_inspect_fs(struct silofs_env *env, silofs_visit_laddr_fn cb,
                    void *user_ctx)
{
	int err;

	err = silofs_inspect_fs(env, cb, user_ctx);
	cmd_require_ok(env, err, "inspect-fs error");
}

void cmd_archive_fs(struct silofs_env *env, struct silofs_caddr *out_caddr)
{
	int err;

	err = silofs_archive_fs(env, out_caddr);
	cmd_require_ok(env, err, "archive-fs failure");
}

void cmd_restore_fs(struct silofs_env *env, struct silofs_caddr *out_caddr)
{
	int err;

	err = silofs_restore_fs(env, out_caddr);
	cmd_require_ok(env, err, "restore-fs failure");
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_setup_env_args(struct silofs_env_args *args)
{
	memset(args, 0, sizeof(*args));
	silofs_bootref_init(&args->bref);
	cmd_fs_ids_init(&args->ids);
	args->uid = getuid();
	args->gid = getgid();
	args->pid = getpid();
	args->umask = 0022;
}

void cmd_destroy_env_args(struct silofs_env_args *args)
{
	silofs_bootref_fini(&args->bref);
	cmd_fs_ids_fini(&args->ids);
	args->umask = 0;
}
