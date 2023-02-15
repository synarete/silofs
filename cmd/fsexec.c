/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#include "cmd.h"


void cmd_new_env(struct silofs_fs_env **pfse,
                 const struct silofs_fs_args *args)
{
	int err;

	err = silofs_fse_new(args, pfse);
	if (err) {
		cmd_dief(err, "failed to create instance");
	}
}

void cmd_del_env(struct silofs_fs_env **pfse)
{
	if (pfse && *pfse) {
		silofs_fse_del(*pfse);
		*pfse = NULL;
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_repodir_name(const struct silofs_fs_env *fse, char **out_path)
{
	cmd_join_path(fse->fs_args.repodir, fse->fs_args.name, out_path);
}

static void cmd_report_err_and_die(const struct silofs_fs_env *fse,
                                   int err, const char *msg)
{
	char *repodir_name = NULL;
	const char *xmsg = msg ? msg : "";
	const char *xtag = msg ? ": " : "";

	cmd_repodir_name(fse, &repodir_name);
	if (err == SILOFS_ENOREPO) {
		cmd_dief(err, "%s%smissing repo: %s",
		         xmsg, xtag, repodir_name);
	} else if (err == SILOFS_EBADREPO) {
		cmd_dief(err, "%s%sillegal repo: %s",
		         xmsg, xtag, repodir_name);
	} else if (err == SILOFS_ENOBOOT) {
		cmd_dief(err, "%s%smissing boot: %s",
		         xmsg, xtag, repodir_name);
	} else if (err == SILOFS_EBADBOOT) {
		cmd_dief(err, "%s%scorrupted boot: %s",
		         xmsg, xtag, repodir_name);
	} else if (err == SILOFS_EMOUNT) {
		cmd_dief(err, "%s%scan not mount: %s",
		         xmsg, xtag, repodir_name);
	} else if (err == SILOFS_EUMOUNT) {
		cmd_dief(err, "%s%scan not umount: %s",
		         xmsg, xtag, repodir_name);
	} else if (err == SILOFS_EFSCORRUPTED) {
		cmd_dief(err, "%s%scorrupted: %s",
		         xmsg, xtag, repodir_name);
	} else if (err == EWOULDBLOCK) {
		cmd_dief(err, "%s%scan not lock: %s",
		         xmsg, xtag, repodir_name);
	} else if (err == EROFS) {
		cmd_dief(err, "%s%sread-only: %s",
		         xmsg, xtag, repodir_name);
	} else if (err == EUCLEAN) {
		cmd_dief(err, "%s%sunclean: %s",
		         xmsg, xtag, repodir_name);
	} else if (err == EKEYEXPIRED) {
		cmd_dief(err, "%s%sbad password: %s",
		         xmsg, xtag, repodir_name);
	} else if (err == ENOENT) {
		cmd_dief(0, "%s%snot exist: %s",
		         xmsg, xtag, repodir_name);
	} else if (err) {
		cmd_dief(err, "%s%s%s",
		         xmsg, xtag, repodir_name);
	}
	cmd_pstrfree(&repodir_name);
}

static void cmd_require_ok(const struct silofs_fs_env *fse,
                           int status, const char *msg)
{
	if (status != 0) {
		cmd_report_err_and_die(fse, abs(status), msg);
	}
}

void cmd_format_repo(struct silofs_fs_env *fse)
{
	int err;

	err = silofs_fse_format_repo(fse);
	cmd_require_ok(fse, err, "failed to format repo");
}

void cmd_open_repo(struct silofs_fs_env *fse)
{
	int err;

	err = silofs_fse_open_repo(fse);
	cmd_require_ok(fse, err, "failed to open repo");
}

void cmd_close_repo(struct silofs_fs_env *fse)
{
	int err;

	err = silofs_fse_close_repo(fse);
	cmd_require_ok(fse, err, "failed to close repo");
}

void cmd_require_fs(struct silofs_fs_env *fse, const struct silofs_uuid *uuid)
{
	int err;

	err = silofs_fse_poke_fs(fse, uuid);
	cmd_require_ok(fse, err, "failed to poke fs");
}

void cmd_format_fs(struct silofs_fs_env *fse, struct silofs_uuid *out_uuid)
{
	int err;

	err = silofs_fse_format_fs(fse, out_uuid);
	cmd_require_ok(fse, err, "failed to format fs");
}

void cmd_close_fs(struct silofs_fs_env *fse)
{
	int err;

	err = silofs_fse_close_fs(fse);
	cmd_require_ok(fse, err, "shutdown error");
}

void cmd_boot_fs(struct silofs_fs_env *fse, const struct silofs_uuid *uuid)
{
	int err;

	err = silofs_fse_boot_fs(fse, uuid);
	cmd_require_ok(fse, err, "failed to boot fs");
}

void cmd_open_fs(struct silofs_fs_env *fse)
{
	int err;

	err = silofs_fse_open_fs(fse);
	cmd_require_ok(fse, err, "failed to open fs");
}

void cmd_exec_fs(struct silofs_fs_env *fse)
{
	int err;

	err = silofs_fse_exec_fs(fse);
	cmd_require_ok(fse, err, "failed to exec fs");
}

void cmd_fork_fs(struct silofs_fs_env *fse,
                 struct silofs_uuid *out_uuid1, struct silofs_uuid *out_uuid2)
{
	int err;

	err = silofs_fse_fork_fs(fse, out_uuid1, out_uuid2);
	cmd_require_ok(fse, err, "failed to fork fs");
}

void cmd_unref_fs(struct silofs_fs_env *fse,
                  const struct silofs_uuid *uuid)
{
	int err;

	err = silofs_fse_unref_fs(fse, uuid);
	cmd_require_ok(fse, err, "rmfs error");
}

void cmd_inspect_fs(struct silofs_fs_env *fse)
{
	int err;

	err = silofs_fse_inspect_fs(fse);
	cmd_require_ok(fse, err, "fsck error");
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_init_fs_args(struct silofs_fs_args *fs_args)
{
	memset(fs_args, 0, sizeof(*fs_args));
	fs_args->uid = getuid();
	fs_args->gid = getgid();
	fs_args->pid = getpid();
	fs_args->umask = 0022;
}

