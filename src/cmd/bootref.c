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
#include <uuid/uuid.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include "cmd.h"


static void cmd_load_bref_file(const char *pathname, char **out_txt)
{
	struct stat st = { .st_mode = 0 };
	size_t len = 0;
	char *txt = NULL;
	int fd = -1;
	int err;

	err = silofs_sys_stat(pathname, &st);
	if (err) {
		cmd_die(err, "stat failure: %s", pathname);
	}
	if (!S_ISREG(st.st_mode)) {
		cmd_die(0, "not a regular file: %s", pathname);
	}
	len = (size_t)st.st_size;
	if (len >= SILOFS_KILO) {
		cmd_die(-EFBIG, "illegal boot-ref file: %s", pathname);
	}
	err = silofs_sys_open(pathname, O_RDONLY, 0, &fd);
	if (err) {
		cmd_die(err, "failed to open boot-ref: %s", pathname);
	}
	txt = cmd_zalloc(len + 1);
	err = silofs_sys_readn(fd, txt, len);
	if (err) {
		cmd_die(err, "failed to read boot-ref: %s", pathname);
	}
	silofs_sys_close(fd);
	*out_txt = txt;
}

static char *cmd_bref_tmp_pathname(const char *pathname)
{
	const size_t len = strlen(pathname);
	char *tmp = NULL;

	tmp = cmd_zalloc(len + 2);
	memcpy(tmp, pathname, len);
	tmp[len] = '~';
	tmp[len + 1] = '\0';
	return tmp;
}

static void cmd_save_bref_file(const char *pathname, const char *txt)
{
	const size_t len = strlen(txt);
	char *tmp = NULL;
	int fd = -1;
	int err;

	tmp = cmd_bref_tmp_pathname(pathname);
	err = silofs_sys_open(tmp, O_CREAT | O_RDWR | O_TRUNC,
	                      S_IRUSR | S_IWUSR, &fd);
	if (err) {
		cmd_die(err, "failed to create boot-ref: %s", tmp);
	}
	err = silofs_sys_fchmod(fd, S_IRUSR);
	if (err) {
		cmd_die(err, "failed to change-mode of: %s", tmp);
	}
	err = silofs_sys_writen(fd, txt, len);
	if (err) {
		cmd_die(err, "failed to write boot-ref: %s", tmp);
	}
	err = silofs_sys_pwriten(fd, "\n", 1, (loff_t)len);
	if (err) {
		cmd_die(err, "failed to write boot-ref: %s", tmp);
	}
	silofs_sys_closefd(&fd);

	silofs_sys_chmod(pathname, S_IRUSR | S_IWUSR);
	err = silofs_sys_rename(tmp, pathname);
	if (err) {
		silofs_sys_chmod(pathname, S_IRUSR);
		cmd_die(err, "failed to rename boot-ref: %s", pathname);
	}
	err = silofs_sys_chmod(pathname, S_IRUSR);
	if (err) {
		cmd_die(err, "failed to chmod rdonly boot-ref: %s", pathname);
	}
	cmd_pstrfree(&tmp);
}

static void cmd_decode_bootref(struct silofs_fs_bref *bref, const char *txt)
{
	struct silofs_strbuf sbuf;
	struct silofs_substr ss;
	int err;

	silofs_substr_init(&ss, txt);
	silofs_substr_strip_ws(&ss, &ss);
	if (!silofs_substr_isascii(&ss)) {
		cmd_die(0, "non-ascii character in: %s", bref->name);
	}
	if (ss.len >= sizeof(sbuf.str)) {
		cmd_die(0, "illegal boot-ref length in: %s", bref->name);
	}
	silofs_strbuf_setup(&sbuf, &ss);
	err = silofs_bootref_import(bref, &sbuf);
	if (err) {
		cmd_die(err, "bad boot-ref in: %s", bref->name);
	}
}

static char *cmd_encode_bootref(const struct silofs_fs_bref *bref)
{
	struct silofs_strbuf sbuf;

	silofs_bootref_export(bref, &sbuf);
	return cmd_strdup(sbuf.str);
}

static char *cmd_bootref_path(const struct silofs_fs_bref *bref)
{
	char *path = NULL;

	cmd_join_path(bref->repodir, bref->name, &path);
	return path;
}

static void cmd_bootref_reload(struct silofs_fs_bref *bref)
{
	char *path = cmd_bootref_path(bref);
	char *text = NULL;

	cmd_load_bref_file(path, &text);
	cmd_decode_bootref(bref, text);
	cmd_pstrfree(&text);
	cmd_pstrfree(&path);
}

static void cmd_bootref_verify(const struct silofs_fs_bref *bref,
                               enum silofs_ctype ctype)
{
	if (bref->caddr.ctype != ctype) {
		if (ctype == SILOFS_CTYPE_BOOTREC) {
			cmd_die(0, "not fs boot-ref: %s", bref->name);
		} else if (ctype == SILOFS_CTYPE_PACKIDX) {
			cmd_die(0, "not archive boot-ref: %s", bref->name);
		} else {
			cmd_die(0, "bad boot-ref: %s", bref->name);
		}
	}
}

void cmd_bootref_load(struct silofs_fs_bref *bref)
{
	cmd_bootref_reload(bref);
	cmd_bootref_verify(bref, SILOFS_CTYPE_BOOTREC);
}

void cmd_bootref_load_ar(struct silofs_fs_bref *bref)
{
	cmd_bootref_reload(bref);
	cmd_bootref_verify(bref, SILOFS_CTYPE_PACKIDX);
}

void cmd_bootref_save(const struct silofs_fs_bref *bref)
{
	char *path = cmd_bootref_path(bref);
	char *text = NULL;

	text = cmd_encode_bootref(bref);
	cmd_save_bref_file(path, text);
	cmd_pstrfree(&text);
	cmd_pstrfree(&path);
}

void cmd_bootref_resave(const struct silofs_fs_bref *bref,
                        const struct silofs_caddr *caddr,
                        const char *newname)
{
	struct silofs_fs_bref bref_alt;

	silofs_bootref_init(&bref_alt);
	silofs_bootref_assign(&bref_alt, bref);
	silofs_bootref_update(&bref_alt, caddr, newname);
	cmd_bootref_save(&bref_alt);
	silofs_bootref_fini(&bref_alt);
}

void cmd_bootref_unlink(const struct silofs_fs_bref *bref)
{
	char *path = cmd_bootref_path(bref);

	silofs_sys_unlink(path);
	cmd_pstrfree(&path);
}
