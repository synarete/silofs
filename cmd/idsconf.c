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
#include <stdarg.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include "cmd.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t cmd_sysconf(int key)
{
	long ret;

	ret = sysconf(key);
	if (ret < 0) {
		cmd_die(errno, "sysconf error: key=%d", key);
	}
	return (size_t)key;
}

static size_t cmd_getxx_bsz(void)
{
	const size_t bsz1 = cmd_sysconf(_SC_GETPW_R_SIZE_MAX);
	const size_t bsz2 = cmd_sysconf(_SC_GETGR_R_SIZE_MAX);
	const size_t align = 1024;
	size_t bsz;

	bsz = (bsz1 > bsz2) ? bsz1 : bsz2;
	bsz = ((bsz + align - 1) / align) * align;
	return bsz;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

enum {
	CMD_IDSCONF_SIZE_MAX = 1L << 20,
};

static void cmd_load_idsconf_file(const char *pathname, char **out_txt)
{
	struct stat st = { .st_mode = 0 };
	size_t size = 0;
	char *txt = NULL;
	int fd = -1;
	int err;

	err = silofs_sys_stat(pathname, &st);
	if (err) {
		cmd_die(err, "stat failure: %s", pathname);
	}
	if (!S_ISREG(st.st_mode)) {
		cmd_diez("not a regular file: %s", pathname);
	}
	size = (size_t)st.st_size;
	if (size >= CMD_IDSCONF_SIZE_MAX) {
		cmd_die(-EFBIG, "illegal ids-config file: %s", pathname);
	}
	err = silofs_sys_open(pathname, O_RDONLY, 0, &fd);
	if (err) {
		cmd_die(err, "failed to open: %s", pathname);
	}

	txt = cmd_zalloc(size + 1);
	err = silofs_sys_readn(fd, txt, size);
	if (err) {
		cmd_die(err, "failed to read: %s", pathname);
	}
	silofs_sys_close(fd);

	*out_txt = txt;
}

static void cmd_save_idsconf_file(const char *pathname, const char *txt)
{
	const size_t len = txt ? strlen(txt) : 0;
	int fd = -1;
	int err;

	err = silofs_sys_open(pathname, O_CREAT | O_RDWR | O_TRUNC,
	                      S_IRUSR | S_IWUSR | S_IRGRP, &fd);
	if (err) {
		cmd_die(err, "failed to create ids-config: %s", pathname);
	}

	err = silofs_sys_writen(fd, txt, len);
	if (err) {
		cmd_die(err, "failed to write ids-config: %s", pathname);
	}
	silofs_sys_closefd(&fd);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_setup_fsids(struct silofs_ugids *ugids)
{
	ugids->users.uids = NULL;
	ugids->users.nuids = 0;
	ugids->groups.gids = NULL;
	ugids->groups.ngids = 0;
}

void cmd_reset_fsids(struct silofs_ugids *ugids)
{
	silofs_release_fsids(ugids, silofs_default_alloc);
}

static bool ugids_has_host_uid(const struct silofs_ugids *ids, uid_t uid)
{
	for (size_t i = 0; i < ids->users.nuids; ++i) {
		if (ids->users.uids[i].host_uid == uid) {
			return true;
		}
	}
	return false;
}

static bool ugids_has_host_gid(const struct silofs_ugids *ids, gid_t gid)
{
	for (size_t i = 0; i < ids->groups.ngids; ++i) {
		if (ids->groups.gids[i].host_gid == gid) {
			return true;
		}
	}
	return false;
}

void cmd_extend_fsids(struct silofs_ugids *ugids, const char *user,
                      bool with_sup_groups)
{
	int err;

	err = silofs_extend_fsids(ugids, silofs_default_alloc, user,
	                          with_sup_groups);
	if (err) {
		cmd_die(err, "failed to add user: %s", user);
	}
}

static char *cmd_fsids_confpath(const char *basedir)
{
	char *path = NULL;

	cmd_join_path(basedir, "fsids.conf", &path);
	return path;
}

void cmd_load_fsids(struct silofs_ugids *ugids, const char *basedir)
{
	char *path = cmd_fsids_confpath(basedir);
	char *text = NULL;
	int err;

	cmd_reset_fsids(ugids);
	cmd_load_idsconf_file(path, &text);
	err = silofs_parse_fsids(ugids, NULL, text);
	if (err) {
		cmd_die(err, "illegal fs-ids config: %s", path);
	}
	cmd_pstrfree(&text);
	cmd_pstrfree(&path);
}

void cmd_save_fsids(const struct silofs_ugids *ugids, const char *basedir)
{
	const size_t size = CMD_IDSCONF_SIZE_MAX;
	char *path = cmd_fsids_confpath(basedir);
	char *text = cmd_zalloc(CMD_IDSCONF_SIZE_MAX);
	int err;

	err = silofs_unparse_fsids(ugids, silofs_default_alloc, text, size);
	if (err) {
		cmd_die(err, "failed to create fs-ids config: %s", path);
	}
	cmd_save_idsconf_file(path, text);
	cmd_pstrfree(&text);
	cmd_pstrfree(&path);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_resolve_uidgid(const char *name, uid_t *out_uid, gid_t *out_gid)
{
	struct passwd pwd = { .pw_uid = (uid_t)(-1) };
	struct passwd *pw = NULL;
	char *buf = NULL;
	size_t bsz;
	int err;

	bsz = cmd_getxx_bsz();
	buf = cmd_zalloc(bsz);
	err = getpwnam_r(name, &pwd, buf, bsz, &pw);
	if (err) {
		cmd_die(err, "getpwnam failed: %s", name);
	}
	if (pw == NULL) {
		cmd_diez("unknown user name: %s", name);
	}
	*out_uid = pw->pw_uid;
	*out_gid = pw->pw_gid;
	cmd_zfree(buf, bsz);
}

void cmd_require_uidgid(const struct silofs_ugids *ugids, const char *name,
                        uid_t *out_uid, gid_t *out_gid)
{
	cmd_resolve_uidgid(name, out_uid, out_gid);
	if (!ugids_has_host_uid(ugids, *out_uid)) {
		cmd_diez("missing uid-mapping for user: '%s'", name);
	}
	if (!ugids_has_host_gid(ugids, *out_gid)) {
		cmd_diez("missing gid-mapping for user: '%s'", name);
	}
}

static char *cmd_getlogin(void)
{
	char name[LOGIN_NAME_MAX + 1] = "";
	int err;

	err = getlogin_r(name, sizeof(name) - 1);
	if (err) {
		return NULL;
	}
	if (!strlen(name)) {
		return NULL;
	}
	return cmd_strdup(name);
}

char *cmd_getpwuid(uid_t uid)
{
	struct passwd pwd = { .pw_uid = (uid_t)(-1) };
	struct passwd *pw = NULL;
	char *buf = NULL;
	size_t bsz;
	int err;

	bsz = cmd_getxx_bsz();
	buf = cmd_zalloc(bsz);
	err = getpwuid_r(uid, &pwd, buf, bsz, &pw);
	if (err) {
		cmd_diez("failed to resolve uid: %u", uid);
	}
	if ((pw == NULL) || (pw->pw_name == NULL)) {
		cmd_diez("unknown uid: %u", uid);
	}
	return cmd_strdup(pw->pw_name);
}

static char *cmd_getpwuid_self(void)
{
	return cmd_getpwuid(geteuid());
}

char *cmd_getusername(void)
{
	char *name = cmd_getlogin();

	return name ? name : cmd_getpwuid_self();
}
