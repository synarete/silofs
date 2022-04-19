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


void cmd_setup_bpath(struct silofs_bootpath *bpath,
                     const char *repodir, const char *name)
{
	int err;

	err = silofs_bootpath_setup(bpath, repodir, name);
	if (err) {
		if (name) {
			cmd_dief(err, "bad boot-path: %s/%s", repodir, name);
		} else {
			cmd_dief(err, "illegal repo dir-path: %s", repodir);
		}
	}
}

static void cmd_open_bootldr(struct silofs_bootldr *bldr,
                             const struct silofs_bootpath *bpath)
{
	int err;

	err = silofs_bootldr_init(bldr);
	if (err) {
		cmd_dief(err, "failed to init: %s", bpath->repodir.str);
	}
	err = silofs_bootldr_open(bldr, bpath);
	if (err) {
		cmd_dief(err, "failed to open repo: %s", bpath->repodir.str);
	}
}

static void cmd_close_bootldr(struct silofs_bootldr *bldr,
                              const struct silofs_bootpath *bpath)
{
	int err;

	err = silofs_bootldr_close(bldr);
	if (err) {
		cmd_dief(err, "close error: %s", bpath->repodir.str);
	}
	silofs_bootldr_fini(bldr);
}

void cmd_load_bsec(const struct silofs_bootpath *bpath,
                   struct silofs_bootsec *out_bsec)
{
	struct silofs_bootldr bldr;
	int err;

	cmd_open_bootldr(&bldr, bpath);
	err = silofs_bootldr_fetch(&bldr, bpath, out_bsec);
	if (err) {
		cmd_dief(err, "failed to load: %s/%s",
		         bpath->repodir.str, bpath->name.s.str);
	}
	cmd_close_bootldr(&bldr, bpath);
}

void cmd_save_bsec(const struct silofs_bootpath *bpath,
                   const struct silofs_bootsec *bsec)
{
	struct silofs_bootldr bldr;
	int err;

	cmd_open_bootldr(&bldr, bpath);
	err = silofs_bootldr_store(&bldr, bpath, bsec);
	if (err) {
		cmd_dief(err, "failed to save: %s/%s",
		         bpath->repodir.str,  bpath->name.s.str);
	}
	cmd_close_bootldr(&bldr, bpath);
}

void cmd_unref_bsec(const struct silofs_bootpath *bpath)
{
	struct silofs_bootldr bldr;
	int err;

	cmd_open_bootldr(&bldr, bpath);
	err = silofs_bootldr_unref(&bldr, bpath);
	if (err) {
		cmd_dief(err, "failed to unref: %s/%s",
		         bpath->repodir.str,  bpath->name.s.str);
	}
	cmd_close_bootldr(&bldr, bpath);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_format_repo(struct silofs_fs_env *fse)
{
	int err;

	err = silofs_fse_format_repos(fse);
	if (err) {
		cmd_dief(err, "failed to format repo: %s",
		         fse->fs_args.main_repodir);
	}
}

void cmd_open_repo(struct silofs_fs_env *fse)
{
	int err;

	err = silofs_fse_open_repos(fse);
	if (err) {
		cmd_dief(err, "failed to open repo: %s",
		         fse->fs_args.main_repodir);
	}
}

void cmd_close_repo(struct silofs_fs_env *fse)
{
	int err;

	err = silofs_fse_close_repos(fse);
	if (err) {
		cmd_dief(err, "failed to close repo: %s",
		         fse->fs_args.main_repodir);
	}
}

void cmd_format_fs(struct silofs_fs_env *fse,
                   struct silofs_bootsec *bsec)
{
	int err;

	err = silofs_fse_format_fs(fse, bsec);
	if (err) {
		cmd_dief(err, "failed to format fs: %s/%s",
		         fse->fs_args.main_repodir,
		         fse->fs_args.main_name);
	}
}

void cmd_shutdown_fs(struct silofs_fs_env *fse)
{
	int err;

	err = silofs_fse_shut(fse);
	if (err) {
		cmd_dief(err, "shutdown error: %s",
		         fse->fs_args.main_repodir);
	}
	err = silofs_fse_term(fse);
	if (err) {
		cmd_dief(err, "internal error: %s",
		         fse->fs_args.main_repodir);
	}
}

void cmd_snap_fs(struct silofs_fs_env *fse,
                 const struct silofs_bootsec *bsec,
                 struct silofs_bootsec *out_bsec)
{
	int err;

	err = silofs_fse_snap(fse, bsec, out_bsec);
	if (err) {
		cmd_dief(err, "failed to snap: %s/%s",
		         fse->fs_args.main_repodir,
		         fse->fs_args.main_name);
	}
}

void cmd_verify_fs(struct silofs_fs_env *fse,
                   const struct silofs_bootsec *bsec)
{
	int err;

	err = silofs_fse_verify(fse, bsec);
	if (err == -EUCLEAN) {
		cmd_dief(0, "bad repo: %s", fse->fs_args.main_repodir);
	} else if (err == -EKEYEXPIRED) {
		cmd_dief(0, "wrong passphrase: %s",
		         fse->fs_args.main_repodir);
	} else if (err == -ENOENT) {
		cmd_dief(0, "not exist: %s", fse->fs_args.main_repodir);
	} else if (err != 0) {
		cmd_dief(err, "illegal: %s/%s",
		         fse->fs_args.main_repodir,
		         fse->fs_args.main_name);
	}
}

void cmd_serve_fs(struct silofs_fs_env *fse,
                  const struct silofs_bootsec *bsec)
{
	int err;

	err = silofs_fse_serve(fse, bsec);
	if (err) {
		cmd_dief(err, "fs failure: %s %s",
		         fse->fs_args.main_repodir,
		         fse->fs_args.mntdir);
	}
}

static void cmd_archive_restore_err(const struct silofs_bootlink *src_blnk,
                                    const struct silofs_bootlink *dst_blnk,
                                    const char *oper_type, int err)
{
	cmd_dief(err, "%s failed: %s/%s --> %s/%s", oper_type,
	         src_blnk->bpath.repodir.str, src_blnk->bpath.name.s.str,
	         dst_blnk->bpath.repodir.str, dst_blnk->bpath.name.s.str);
}

void cmd_archive_fs(struct silofs_fs_env *fse,
                    const struct silofs_bootlink *src_blnk,
                    struct silofs_bootlink *dst_blnk)
{
	int err;

	err = silofs_fse_archive(fse, &src_blnk->bsec, &dst_blnk->bsec);
	if (err) {
		cmd_archive_restore_err(src_blnk, dst_blnk, "archive", err);
	}
}

void cmd_restore_fs(struct silofs_fs_env *fse,
                    const struct silofs_bootlink *src_blnk,
                    struct silofs_bootlink *dst_blnk)
{
	int err;

	err = silofs_fse_restore(fse, &src_blnk->bsec, &dst_blnk->bsec);
	if (err) {
		cmd_archive_restore_err(src_blnk, dst_blnk, "restore", err);
	}
}
