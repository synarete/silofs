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

void cmd_new_env(const struct silofs_env_args *env_args,
                 struct silofs_env           **p_env)
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
	struct silofs_boot_args boot_args = {};

	silofs_get_boot_args(env, &boot_args);
	return cmd_join_path(boot_args.repodir, boot_args.fs_name);
}

static void cmd_report_err_and_die(const struct silofs_env *env, int status,
                                   const char *msg)
{
	char       *rname = NULL;
	const char *xmsg  = msg ? msg : "";
	const char *xtag  = msg ? ": " : "";
	int         err;

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
	case SILOFS_ENOMBR:
		cmd_die(err, "%s%smissing boot: %s", xmsg, xtag, rname);
		break;
	case SILOFS_EBADMBR:
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
		cmd_diez("%s%snot exist: %s", xmsg, xtag, rname);
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

#define attr_printf34 silofs_attr_printf(3, 4)

attr_printf34 static void
cmd_requiref_ok(const struct silofs_env *env, int status,
                const char *restrict fmt, ...)
{
	char    msg[1024];
	va_list ap = { 0 };
	int     ret;

	if (status != 0) {
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

static void cmd_require_blobid_ok(const struct silofs_env *env, int err,
                                  const char                 *prefix_msg,
                                  const struct silofs_blobid *blobid)
{
	char bid[256] = "";

	silofs_encode_blobid(blobid, bid, sizeof(bid) - 1);
	cmd_requiref_ok(env, err, "%s: blobid=%s", prefix_msg, bid);
}

void cmd_sense_fs(struct silofs_env *env, const struct silofs_blobid *blobid)
{
	int err;

	err = silofs_sense_fs(env, blobid);
	cmd_require_blobid_ok(env, err, "can not sense fs", blobid);
}

void cmd_sense_ar(struct silofs_env *env, const struct silofs_blobid *blobid)
{
	int err;

	err = silofs_sense_ar(env, blobid);
	cmd_require_blobid_ok(env, err, "failed to sense archive", blobid);
}

void cmd_format_fs(struct silofs_env *env, struct silofs_blobid *out_blobid)
{
	int err;

	err = silofs_format_fs(env, out_blobid);
	cmd_require_ok(env, err, "failed to format fs");
}

void cmd_open_fs(struct silofs_env *env, const struct silofs_blobid *blobid)
{
	int err;

	err = silofs_open_fs(env, blobid);
	cmd_require_blobid_ok(env, err, "failed to open fs", blobid);
}

void cmd_close_fs(struct silofs_env *env)
{
	int err;

	err = silofs_close_fs(env);
	cmd_require_ok(env, err, "failed to close fs");
}

void cmd_exec_fs(struct silofs_env *env)
{
	int err;

	err = silofs_exec_fs(env);
	cmd_require_ok(env, err, "failed to exec fs");
}

void cmd_fork_fs(struct silofs_env *env, struct silofs_blobid *out_main,
                 struct silofs_blobid *out_fork)
{
	int err;

	err = silofs_fork_fs(env, out_main, out_fork);
	cmd_require_ok(env, err, "failed to fork fs");
}

void cmd_remove_fs(struct silofs_env *env, const struct silofs_blobid *blobid)
{
	int err;

	err = silofs_remove_fs(env, blobid);
	cmd_require_blobid_ok(env, err, "failed to remove fs", blobid);
}

void cmd_inspect_fs(struct silofs_env *env, bool view)
{
	int err;

	err = silofs_inspect_fs(env, view);
	cmd_require_ok(env, err, "failed to inspect fs");
}

void cmd_archive_fs(struct silofs_env          *env,
                    const struct silofs_blobid *fs_blobid,
                    struct silofs_blobid       *out_ar_blobid)
{
	int err;

	err = silofs_archive_fs(env, fs_blobid, out_ar_blobid);
	cmd_require_blobid_ok(env, err, "failed to archive", fs_blobid);
}

void cmd_restore_fs(struct silofs_env          *env,
                    const struct silofs_blobid *ar_blobid,
                    struct silofs_blobid       *out_fs_blobid)
{
	int err;

	err = silofs_restore_fs(env, ar_blobid, out_fs_blobid);
	cmd_require_blobid_ok(env, err, "failed to restore", ar_blobid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_setup_env_args(struct silofs_env_args *env_args)
{
	memset(env_args, 0, sizeof(*env_args));
	cmd_setup_fsids(&env_args->ugids);
	env_args->uid   = getuid();
	env_args->gid   = getgid();
	env_args->pid   = getpid();
	env_args->umask = 0077;
}

void cmd_destroy_env_args(struct silofs_env_args *env_args)
{
	cmd_reset_fsids(&env_args->ugids);
	memset(env_args, 0, sizeof(*env_args));
}
