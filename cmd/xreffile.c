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
#include <string.h>
#include <limits.h>

static void
cmd_open_repodir(const struct silofs_boot_args *boot_args, int *out_dfd)
{
	const char *repodir = boot_args->repodir;
	int dfd = -1;
	int err;

	err = silofs_sys_open(repodir, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		cmd_die(err, "failed to open repodir: %s", repodir);
	}
	*out_dfd = dfd;
}

static void cmd_save_xref_at(int dfd, const char *name, const char *txt)
{
	char tmpname[NAME_MAX + 1] = "";
	int fd = -1;
	int err;

	snprintf(tmpname, sizeof(tmpname) - 1, "%s~", name);
	err = silofs_sys_openat(dfd, tmpname, O_CREAT | O_RDWR | O_TRUNC,
	                        S_IRUSR | S_IWUSR, &fd);
	if (err) {
		cmd_die(err, "failed to create: %s", tmpname);
	}
	err = silofs_sys_fchmod(fd, S_IRUSR);
	if (err) {
		cmd_die(err, "failed to change-mode: %s", tmpname);
	}
	err = silofs_sys_writen(fd, txt, strlen(txt));
	if (err) {
		cmd_die(err, "failed to write: %s", tmpname);
	}
	err = silofs_sys_writen(fd, "\n", 1);
	if (err) {
		cmd_die(err, "failed to write: %s", tmpname);
	}
	silofs_sys_closefd(&fd);

	silofs_sys_fchmodat(dfd, name, S_IRUSR | S_IWUSR, 0);
	err = silofs_sys_renameat(dfd, tmpname, dfd, name);
	if (err) {
		silofs_sys_fchmodat(dfd, name, S_IRUSR, 0);
		cmd_die(err, "failed to rename: %s", name);
	}
	err = silofs_sys_fchmodat(dfd, name, S_IRUSR, 0);
	if (err) {
		cmd_die(err, "failed to change-mode: %s", name);
	}
}

void cmd_save_fs_xref(const struct silofs_boot_args *boot_args)
{
	int dfd = -1;

	cmd_open_repodir(boot_args, &dfd);
	cmd_save_xref_at(dfd, boot_args->fs_name, boot_args->fs_xref.s);
	silofs_sys_closefd(&dfd);
}

void cmd_save_ar_xref(const struct silofs_boot_args *boot_args)
{
	int dfd = -1;

	cmd_open_repodir(boot_args, &dfd);
	cmd_save_xref_at(dfd, boot_args->ar_name, boot_args->ar_xref.s);
	silofs_sys_closefd(&dfd);
}

void cmd_unlink_fs_xref(const struct silofs_boot_args *boot_args)
{
	int dfd = -1;

	cmd_open_repodir(boot_args, &dfd);
	silofs_sys_unlinkat(dfd, boot_args->fs_name, 0);
	silofs_sys_closefd(&dfd);
}

static char *cmd_load_xref_at(int dfd, const char *name)
{
	char txt[SILOFS_XREFLEN_MAX + 2] = "";
	struct stat st = { .st_mode = 0 };
	size_t len = 0;
	char *end = NULL;
	int fd = -1;
	int err;

	err = silofs_sys_fstatat(dfd, name, &st, 0);
	if (err) {
		cmd_die(err, "stat failure: %s", name);
	}
	if (!S_ISREG(st.st_mode)) {
		cmd_diez("not a regular file: %s", name);
	}
	len = (size_t)st.st_size;
	if (len >= sizeof(txt)) {
		cmd_die(-EFBIG, "illegal xref: %s", name);
	}
	err = silofs_sys_openat(dfd, name, O_RDONLY, 0, &fd);
	if (err) {
		cmd_die(err, "failed to open: %s", name);
	}
	err = silofs_sys_readn(fd, txt, len - 1);
	silofs_sys_closefd(&fd);
	if (err) {
		cmd_die(err, "failed to read xref: %s", name);
	}
	end = strchr(txt, '\n');
	if (end != NULL) {
		*end = '\0';
	}
	return cmd_strdup(txt);
}

static void cmd_assign_xref(struct silofs_xref *xref, const char *txt)
{
	const size_t len = strlen(txt);

	if (len == 0) {
		cmd_diez("empty xref");
	}
	if (len >= sizeof(xref->s)) {
		cmd_diez("bad xref: '%s'", txt);
	}
	strncpy(xref->s, txt, sizeof(xref->s));
}

void cmd_load_fs_xref(struct silofs_boot_args *boot_args)
{
	struct silofs_xref *xref = &boot_args->fs_xref;
	char *txt = NULL;
	int dfd = -1;
	int err;

	cmd_open_repodir(boot_args, &dfd);
	txt = cmd_load_xref_at(dfd, boot_args->fs_name);
	silofs_sys_closefd(&dfd);

	cmd_assign_xref(xref, txt);
	err = silofs_check_fs_xref(xref);
	if (err == -SILOFS_EBADMBR) {
		cmd_diez("not a fs xref: %s (%s)", boot_args->fs_name,
		         xref->s);
	} else if (err) {
		cmd_diez("bad fs xref: %s (%s)", boot_args->fs_name, xref->s);
	}
}

void cmd_load_ar_xref(struct silofs_boot_args *boot_args)
{
	struct silofs_xref *xref = &boot_args->ar_xref;
	char *txt = NULL;
	int dfd = -1;
	int err;

	cmd_open_repodir(boot_args, &dfd);
	txt = cmd_load_xref_at(dfd, boot_args->ar_name);
	silofs_sys_closefd(&dfd);

	cmd_assign_xref(xref, txt);
	err = silofs_check_ar_xref(xref);
	if (err == -SILOFS_EBADPACK) {
		cmd_diez("not an archive xref: %s (%s)", boot_args->ar_name,
		         xref->s);
	} else if (err) {
		cmd_diez("bad archive xref: %s (%s)", boot_args->ar_name,
		         xref->s);
	}
}
