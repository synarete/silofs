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


void cmd_new_fsenv(const struct silofs_fs_args *fs_args,
                   struct silofs_fsenv **p_fsenv)
{
	int err;

	err = silofs_new_fsenv(fs_args, p_fsenv);
	if (err) {
		cmd_dief(err, "failed to create fs instance");
	}
}

void cmd_del_fsenv(struct silofs_fsenv **p_fsenv)
{
	if (p_fsenv && *p_fsenv) {
		silofs_del_fsenv(*p_fsenv);
		*p_fsenv = NULL;
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static char *cmd_repodir_name(const struct silofs_fsenv *fsenv)
{
	char *ret = NULL;

	cmd_join_path(fsenv->fse_args.repodir, fsenv->fse_args.name, &ret);
	return ret;
}

static void cmd_report_err_and_die(const struct silofs_fsenv *fsenv,
                                   int status, const char *msg)
{
	char *rname = NULL;
	const char *xmsg = msg ? msg : "";
	const char *xtag = msg ? ": " : "";
	int err;

	/* no error */
	if (status == 0) {
		return;
	}
	rname = cmd_repodir_name(fsenv);

	/* internal errors */
	err = abs(status);
	switch (err) {
	case SILOFS_ENOREPO:
		cmd_dief(err, "%s%smissing repo: %s", xmsg, xtag, rname);
		break;
	case SILOFS_EBADREPO:
		cmd_dief(err, "%s%sillegal repo: %s", xmsg, xtag, rname);
		break;
	case SILOFS_ENOBOOT:
		cmd_dief(err, "%s%smissing boot: %s", xmsg, xtag, rname);
		break;
	case SILOFS_EBADBOOT:
		cmd_dief(err, "%s%sbad boot: %s", xmsg, xtag, rname);
		break;
	case SILOFS_EKEYEXPIRED:
		cmd_dief(err, "%s%sbad password: %s", xmsg, xtag, rname);
		break;
	case SILOFS_EMOUNT:
		cmd_dief(err, "%s%scan not mount: %s", xmsg, xtag, rname);
		break;
	case SILOFS_EUMOUNT:
		cmd_dief(err, "%s%scan not umount: %s", xmsg, xtag, rname);
		break;
	case SILOFS_EFSCORRUPTED:
		cmd_dief(err, "%s%scorrupted fs: %s", xmsg, xtag, rname);
		break;
	case SILOFS_ECSUM:
		cmd_dief(err, "%s%schecksum error: %s", xmsg, xtag, rname);
		break;
	case SILOFS_EILLSTR:
		cmd_dief(err, "%s%sillegal string", xmsg, xtag);
		break;
	default:
		break;
	}

	/* standard errors */
	err = abs(silofs_remap_status_code(status));
	switch (err) {
	case EWOULDBLOCK:
		cmd_dief(err, "%s%scan not lock: %s", xmsg, xtag, rname);
		break;
	case EROFS:
		cmd_dief(err, "%s%sread-only fs: %s", xmsg, xtag, rname);
		break;
	case EUCLEAN:
		cmd_dief(err, "%s%sunclean: %s", xmsg, xtag, rname);
		break;
	case EKEYEXPIRED:
		cmd_dief(err, "%s%sbad password: %s", xmsg, xtag, rname);
		break;
	case ENOENT:
		cmd_dief(0, "%s%snot exist: %s", xmsg, xtag, rname);
		break;
	default:
		cmd_dief(err, "%s%s%s", xmsg, xtag, rname);
		break;
	}

	cmd_pstrfree(&rname);
}

static void cmd_require_ok(const struct silofs_fsenv *fsenv,
                           int status, const char *msg)
{
	if (status != 0) {
		cmd_report_err_and_die(fsenv, status, msg);
	}
}

void cmd_format_repo(struct silofs_fsenv *fsenv)
{
	int err;

	err = silofs_format_repo(fsenv);
	cmd_require_ok(fsenv, err, "failed to format repo");
}

void cmd_open_repo(struct silofs_fsenv *fsenv)
{
	int err;

	err = silofs_open_repo(fsenv);
	cmd_require_ok(fsenv, err, "failed to open repo");
}

void cmd_close_repo(struct silofs_fsenv *fsenv)
{
	int err;

	err = silofs_close_repo(fsenv);
	cmd_require_ok(fsenv, err, "failed to close repo");
}

void cmd_require_fs(struct silofs_fsenv *fsenv,
                    const struct silofs_fs_bconf *bconf)
{
	struct silofs_bootrec brec;
	int err;

	err = silofs_poke_fs(fsenv, &bconf->boot_ref, &brec);
	cmd_require_ok(fsenv, err, "can not load");
}

static void cmd_do_format_fs(struct silofs_fsenv *fsenv,
                             struct silofs_caddr *out_root_ref)
{
	int err;

	err = silofs_format_fs(fsenv, out_root_ref);
	cmd_require_ok(fsenv, err, "failed to format fs");
}

void cmd_format_fs(struct silofs_fsenv *fsenv, struct silofs_fs_bconf *bconf)
{
	struct silofs_caddr root_ref;

	cmd_do_format_fs(fsenv, &root_ref);
	cmd_bconf_set_boot_ref(bconf, &root_ref);
}

void cmd_close_fs(struct silofs_fsenv *fsenv)
{
	int err;

	err = silofs_close_fs(fsenv);
	cmd_require_ok(fsenv, err, "failed to close fs");
}

void cmd_boot_fs(struct silofs_fsenv *fsenv,
                 const struct silofs_fs_bconf *bconf)
{
	int err;

	err = silofs_boot_fs(fsenv, &bconf->boot_ref);
	cmd_require_ok(fsenv, err, "failed to boot fs");
}

void cmd_open_fs(struct silofs_fsenv *fsenv)
{
	int err;

	err = silofs_open_fs(fsenv);
	cmd_require_ok(fsenv, err, "failed to open fs");
}

void cmd_exec_fs(struct silofs_fsenv *fsenv)
{
	int err;

	err = silofs_exec_fs(fsenv);
	cmd_require_ok(fsenv, err, "failed to exec fs");
}

void cmd_fork_fs(struct silofs_fsenv *fsenv,
                 struct silofs_caddr *out_new, struct silofs_caddr *out_alt)
{
	int err;

	err = silofs_fork_fs(fsenv, out_new, out_alt);
	cmd_require_ok(fsenv, err, "failed to fork fs");
}

void cmd_unref_fs(struct silofs_fsenv *fsenv,
                  const struct silofs_fs_bconf *bconf)
{
	int err;

	err = silofs_unref_fs(fsenv, &bconf->boot_ref);
	cmd_require_ok(fsenv, err, "unref-fs error");
}

void cmd_inspect_fs(struct silofs_fsenv *fsenv,
                    silofs_visit_laddr_fn cb, void *user_ctx)
{
	int err;

	err = silofs_inspect_fs(fsenv, cb, user_ctx);
	cmd_require_ok(fsenv, err, "inspect-fs error");
}

void cmd_pack_fs(struct silofs_fsenv *fsenv, struct silofs_caddr *out_caddr)
{
	int err;

	err = silofs_pack_fs(fsenv, out_caddr);
	cmd_require_ok(fsenv, err, "pack-fs error");
}

void cmd_unpack_fs(struct silofs_fsenv *fsenv,
                   const struct silofs_caddr *caddr)
{
	int err;

	err = silofs_unpack_fs(fsenv, caddr);
	cmd_require_ok(fsenv, err, "unpack-fs error");
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
