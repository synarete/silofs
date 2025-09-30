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
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <jansson.h>
#include "cmd.h"

static char *xref_to_json(const char *txt)
{
	json_t *root = nullptr;
	json_t *jstr = nullptr;
	char *out = nullptr;
	int err;

	root = json_object();
	if (root == nullptr) {
		cmd_diez("json: failed to create root");
	}
	jstr = json_string(txt);
	if (jstr == nullptr) {
		cmd_diez("json: failed to create string");
	}
	err = json_object_set_new(root, "xref", jstr);
	if (err) {
		cmd_diez("json: failed to set xref: err=%d", err);
	}
	out = json_dumps(root, JSON_INDENT(4));
	if (out == nullptr) {
		cmd_diez("json: failed to set dumps");
	}
	json_decref(root);
	return out;
}

static char *json_to_xref(const char *jtxt)
{
	json_t *root = nullptr;
	json_t *jstr = nullptr;
	json_error_t jerr;
	char *out = nullptr;

	root = json_loads(jtxt, 0, &jerr);
	if (root == nullptr) {
		cmd_diez("json: failed to parse: text='%s' line=%d column=%d",
		         jerr.text, jerr.line, jerr.column);
	}
	jstr = json_object_get(root, "xref");
	if (!json_is_string(jstr)) {
		cmd_diez("json: failed to parse xref as string");
	}
	out = cmd_strdup(json_string_value(jstr));
	json_decref(root);
	return out;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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

static void cmd_save_jref_at(int dfd, const char *name, const char *jtxt)
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
	err = silofs_sys_writen(fd, jtxt, strlen(jtxt));
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

static void cmd_save_xref_at(int dfd, const char *name, const char *txt)
{
	char *jtxt = nullptr;

	jtxt = xref_to_json(txt);
	cmd_save_jref_at(dfd, name, jtxt);
	free(jtxt);
}

void cmd_save_fs_xref(const struct silofs_boot_args *boot_args,
                      const struct silofs_xref *fs_xref)
{
	int dfd = -1;

	cmd_open_repodir(boot_args, &dfd);
	cmd_save_xref_at(dfd, boot_args->fs_name, fs_xref->s);
	silofs_sys_closefd(&dfd);
}

void cmd_save_ar_xref(const struct silofs_boot_args *boot_args,
                      const struct silofs_xref *ar_xref)
{
	int dfd = -1;

	cmd_open_repodir(boot_args, &dfd);
	cmd_save_xref_at(dfd, boot_args->ar_name, ar_xref->s);
	silofs_sys_closefd(&dfd);
}

void cmd_unlink_fs_xref(const struct silofs_boot_args *boot_args)
{
	int dfd = -1;

	cmd_open_repodir(boot_args, &dfd);
	silofs_sys_unlinkat(dfd, boot_args->fs_name, 0);
	silofs_sys_closefd(&dfd);
}

static char *cmd_load_jref_at(int dfd, const char *name)
{
	struct stat st = { .st_mode = 0 };
	const size_t jtxt_size_max = 1 << 20;
	char *jtxt = nullptr;
	size_t len = 0;
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
	if (len >= jtxt_size_max) {
		cmd_die(-EFBIG, "illegal xref: %s", name);
	}
	err = silofs_sys_openat(dfd, name, O_RDONLY, 0, &fd);
	if (err) {
		cmd_die(err, "failed to open: %s", name);
	}
	jtxt = cmd_zalloc(len + 1);
	err = silofs_sys_readn(fd, jtxt, len);
	silofs_sys_closefd(&fd);
	if (err) {
		cmd_die(err, "failed to read xref: %s", name);
	}
	return jtxt;
}

static char *cmd_load_xref_at(int dfd, const char *name)
{
	char *jtxt = nullptr;
	char *xref = nullptr;

	jtxt = cmd_load_jref_at(dfd, name);
	xref = json_to_xref(jtxt);
	cmd_pstrfree(&jtxt);

	return xref;
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

static void cmd_load_xref_of(const struct silofs_boot_args *boot_args, bool fs,
                             struct silofs_xref *out_xref)
{
	const char *name = fs ? boot_args->fs_name : boot_args->ar_name;
	char *txt = nullptr;
	int dfd = -1;
	int err;

	cmd_open_repodir(boot_args, &dfd);
	txt = cmd_load_xref_at(dfd, name);
	silofs_sys_closefd(&dfd);

	cmd_assign_xref(out_xref, txt);
	cmd_pstrfree(&txt);

	err = silofs_check_xref(out_xref);
	if (err == -SILOFS_EPROTO) {
		cmd_diez("unknown xref format: %s (%s)", name, out_xref->s);
	} else if (err) {
		cmd_diez("bad xref: %s (%s)", name, out_xref->s);
	}
}

void cmd_load_fs_xref(const struct silofs_boot_args *boot_args,
                      struct silofs_xref *out_xref)
{
	cmd_load_xref_of(boot_args, true, out_xref);
}

void cmd_load_ar_xref(struct silofs_boot_args *boot_args,
                      struct silofs_xref *out_xref)
{
	cmd_load_xref_of(boot_args, false, out_xref);
}
