/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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


void cmd_new_fs_ctx(struct silofs_fs_ctx **p_fs_ctx,
                    const struct silofs_fs_args *fs_args)
{
	int err;

	err = silofs_new_ctx(fs_args, p_fs_ctx);
	if (err) {
		cmd_dief(err, "failed to create fs-context instance");
	}
}

void cmd_del_fs_ctx(struct silofs_fs_ctx **p_fs_ctx)
{
	if (p_fs_ctx && *p_fs_ctx) {
		silofs_del_ctx(*p_fs_ctx);
		*p_fs_ctx = NULL;
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static char *cmd_repodir_name(const struct silofs_fs_ctx *fse)
{
	char *ret = NULL;

	cmd_join_path(fse->fs_args.repodir, fse->fs_args.name, &ret);
	return ret;
}

static void cmd_report_err_and_die(const struct silofs_fs_ctx *fse,
                                   int status, const char *msg)
{
	char *repodir_name = cmd_repodir_name(fse);
	const char *xmsg = msg ? msg : "";
	const char *xtag = msg ? ": " : "";
	int err;

	err = abs(status);
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
		cmd_dief(err, "%s%sbad boot: %s",
		         xmsg, xtag, repodir_name);
	} else if (err == SILOFS_EKEYEXPIRED) {
		cmd_dief(err, "%s%sbad password: %s",
		         xmsg, xtag, repodir_name);
	} else if (err == SILOFS_EMOUNT) {
		cmd_dief(err, "%s%scan not mount: %s",
		         xmsg, xtag, repodir_name);
	} else if (err == SILOFS_EUMOUNT) {
		cmd_dief(err, "%s%scan not umount: %s",
		         xmsg, xtag, repodir_name);
	} else if (err == SILOFS_EFSCORRUPTED) {
		cmd_dief(err, "%s%scorrupted file-system: %s",
		         xmsg, xtag, repodir_name);
	} else if (err == SILOFS_ECSUM) {
		cmd_dief(err, "%s%schecksum error: %s",
		         xmsg, xtag, repodir_name);
	}

	err = abs(silofs_remap_status_code(status));
	if (err == EWOULDBLOCK) {
		cmd_dief(err, "%s%scan not lock: %s",
		         xmsg, xtag, repodir_name);
	} else if (err == EROFS) {
		cmd_dief(err, "%s%sread-only file-system: %s",
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

static void cmd_require_ok(const struct silofs_fs_ctx *fse,
                           int status, const char *msg)
{
	if (status != 0) {
		cmd_report_err_and_die(fse, status, msg);
	}
}

void cmd_format_repo(struct silofs_fs_ctx *fse)
{
	int err;

	err = silofs_format_repo(fse);
	cmd_require_ok(fse, err, "failed to format repo");
}

void cmd_open_repo(struct silofs_fs_ctx *fse)
{
	int err;

	err = silofs_open_repo(fse);
	cmd_require_ok(fse, err, "failed to open repo");
}

void cmd_close_repo(struct silofs_fs_ctx *fse)
{
	int err;

	err = silofs_close_repo(fse);
	cmd_require_ok(fse, err, "failed to close repo");
}

static void cmd_lvid_of(const struct silofs_fs_bconf *bconf,
                        struct silofs_lvid *out_lvid)
{
	silofs_lvid_by_uuid(out_lvid, &bconf->fs_uuid);
}

static void cmd_do_require_fs(struct silofs_fs_ctx *fse,
                              const struct silofs_lvid *lvid)
{
	struct silofs_bootrec brec;
	int err;

	err = silofs_poke_fs(fse, lvid, &brec);
	cmd_require_ok(fse, err, "can not load");
}

void cmd_require_fs(struct silofs_fs_ctx *fse,
                    const struct silofs_fs_bconf *bconf)
{
	struct silofs_lvid lvid;

	cmd_lvid_of(bconf, &lvid);
	cmd_do_require_fs(fse, &lvid);
}

static void cmd_do_format_fs(struct silofs_fs_ctx *fse,
                             struct silofs_lvid *out_lvid)
{
	int err;

	err = silofs_format_fs(fse, out_lvid);
	cmd_require_ok(fse, err, "failed to format fs");
}

void cmd_format_fs(struct silofs_fs_ctx *fse, struct silofs_fs_bconf *bconf)
{
	struct silofs_lvid lvid;

	cmd_do_format_fs(fse, &lvid);
	cmd_bconf_set_fsid(bconf, &lvid.uuid);
}

void cmd_close_fs(struct silofs_fs_ctx *fse)
{
	int err;

	err = silofs_close_fs(fse);
	cmd_require_ok(fse, err, "shutdown error");
}

static void cmd_do_boot_fs(struct silofs_fs_ctx *fse,
                           const struct silofs_lvid *lvid)
{
	int err;

	err = silofs_boot_fs(fse, lvid);
	cmd_require_ok(fse, err, "failed to boot fs");
}

void cmd_boot_fs(struct silofs_fs_ctx *fse,
                 const struct silofs_fs_bconf *bconf)
{
	struct silofs_lvid lvid;

	cmd_lvid_of(bconf, &lvid);
	cmd_do_boot_fs(fse, &lvid);
}

void cmd_open_fs(struct silofs_fs_ctx *fse)
{
	int err;

	err = silofs_open_fs(fse);
	cmd_require_ok(fse, err, "failed to open fs");
}

void cmd_exec_fs(struct silofs_fs_ctx *fse)
{
	int err;

	err = silofs_exec_fs(fse);
	cmd_require_ok(fse, err, "failed to exec fs");
}

void cmd_fork_fs(struct silofs_fs_ctx *fse,
                 struct silofs_lvid *out_new, struct silofs_lvid *out_alt)
{
	int err;

	err = silofs_fork_fs(fse, out_new, out_alt);
	cmd_require_ok(fse, err, "failed to fork fs");
}

static void cmd_do_unref_fs(struct silofs_fs_ctx *fse,
                            const struct silofs_lvid *lvid)
{
	int err;

	err = silofs_unref_fs(fse, lvid);
	cmd_require_ok(fse, err, "rmfs error");
}

void cmd_unref_fs(struct silofs_fs_ctx *fse,
                  const struct silofs_fs_bconf *bconf)
{
	struct silofs_lvid lvid;

	cmd_lvid_of(bconf, &lvid);
	cmd_do_unref_fs(fse, &lvid);
}

void cmd_inspect_fs(struct silofs_fs_ctx *fse,
                    silofs_visit_laddr_fn cb, void *user_ctx)
{
	int err;

	err = silofs_inspect_fs(fse, cb, user_ctx);
	cmd_require_ok(fse, err, "inspect error");
}

void cmd_archive_fs(struct silofs_fs_ctx *fse, const char *packdir,
                    struct silofs_packid *out_packid)
{
	int err;

	err = silofs_export_fs(fse, packdir, out_packid);
	cmd_require_ok(fse, err, "archive error");
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_init_fs_args(struct silofs_fs_args *fs_args)
{
	memset(fs_args, 0, sizeof(*fs_args));
	cmd_bconf_init(&fs_args->bconf);
	fs_args->uid = getuid();
	fs_args->gid = getgid();
	fs_args->pid = getpid();
	fs_args->umask = 0022;
}

