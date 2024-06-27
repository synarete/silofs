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

	cmd_join_path(fse->args.repodir, fse->args.name, &ret);
	return ret;
}

static void cmd_report_err_and_die(const struct silofs_fs_ctx *fse,
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
	rname = cmd_repodir_name(fse);

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

static void cmd_require_ok(const struct silofs_fs_ctx *fse,
                           int status, const char *msg)
{
	if (status != 0) {
		cmd_report_err_and_die(fse, status, msg);
	}
}

void cmd_format_repo(struct silofs_fs_ctx *fs_ctx)
{
	int err;

	err = silofs_format_repo(fs_ctx->fsenv);
	cmd_require_ok(fs_ctx, err, "failed to format repo");
}

void cmd_open_repo(struct silofs_fs_ctx *fse)
{
	int err;

	err = silofs_open_repo(fse->fsenv);
	cmd_require_ok(fse, err, "failed to open repo");
}

void cmd_close_repo(struct silofs_fs_ctx *fs_ctx)
{
	int err;

	err = silofs_close_repo(fs_ctx->fsenv);
	cmd_require_ok(fs_ctx, err, "failed to close repo");
}

void cmd_require_fs(struct silofs_fs_ctx *fse,
                    const struct silofs_fs_bconf *bconf)
{
	struct silofs_bootrec brec;
	int err;

	err = silofs_poke_fs(fse->fsenv, &bconf->boot_ref, &brec);
	cmd_require_ok(fse, err, "can not load");
}

static void cmd_do_format_fs(struct silofs_fs_ctx *fse,
                             struct silofs_caddr *out_root_ref)
{
	int err;

	err = silofs_format_fs(fse->fsenv, out_root_ref);
	cmd_require_ok(fse, err, "failed to format fs");
}

void cmd_format_fs(struct silofs_fs_ctx *fse, struct silofs_fs_bconf *bconf)
{
	struct silofs_caddr root_ref;

	cmd_do_format_fs(fse, &root_ref);
	cmd_bconf_set_boot_ref(bconf, &root_ref);
}

void cmd_close_fs(struct silofs_fs_ctx *fse)
{
	int err;

	err = silofs_close_fs(fse->fsenv);
	cmd_require_ok(fse, err, "shutdown error");
}

void cmd_boot_fs(struct silofs_fs_ctx *fse,
                 const struct silofs_fs_bconf *bconf)
{
	int err;

	err = silofs_boot_fs(fse->fsenv, &bconf->boot_ref);
	cmd_require_ok(fse, err, "failed to boot fs");
}

void cmd_open_fs(struct silofs_fs_ctx *fse)
{
	int err;

	err = silofs_open_fs(fse->fsenv);
	cmd_require_ok(fse, err, "failed to open fs");
}

void cmd_exec_fs(struct silofs_fs_ctx *fse)
{
	int err;

	err = silofs_exec_fs(fse->fsenv);
	cmd_require_ok(fse, err, "failed to exec fs");
}

void cmd_fork_fs(struct silofs_fs_ctx *fse,
                 struct silofs_caddr *out_new, struct silofs_caddr *out_alt)
{
	int err;

	err = silofs_fork_fs(fse->fsenv, out_new, out_alt);
	cmd_require_ok(fse, err, "failed to fork fs");
}

void cmd_unref_fs(struct silofs_fs_ctx *fse,
                  const struct silofs_fs_bconf *bconf)
{
	int err;

	err = silofs_unref_fs(fse->fsenv, &bconf->boot_ref);
	cmd_require_ok(fse, err, "unref-fs error");
}

void cmd_inspect_fs(struct silofs_fs_ctx *fse,
                    silofs_visit_laddr_fn cb, void *user_ctx)
{
	int err;

	err = silofs_inspect_fs(fse->fsenv, cb, user_ctx);
	cmd_require_ok(fse, err, "inspect-fs error");
}

void cmd_pack_fs(struct silofs_fs_ctx *fse, struct silofs_caddr *out_caddr)
{
	int err;

	err = silofs_pack_fs(fse->fsenv, out_caddr);
	cmd_require_ok(fse, err, "pack-fs error");
}

void cmd_unpack_fs(struct silofs_fs_ctx *fse, const struct silofs_caddr *caddr)
{
	int err;

	err = silofs_unpack_fs(fse->fsenv, caddr);
	cmd_require_ok(fse, err, "unpack-fs error");
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
