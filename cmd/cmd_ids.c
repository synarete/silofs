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
#include <limits.h>
#include <pwd.h>
#include <grp.h>

static size_t cmd_sysconf(int key)
{
	long ret;

	ret = sysconf(key);
	if (ret < 0) {
		cmd_die(errno, "sysconf error: key=%d", key);
	}
	return (size_t)key;
}

static char *cmd_getlogin(void)
{
	char name[LOGIN_NAME_MAX + 1] = "";
	int  err;

	err = getlogin_r(name, sizeof(name) - 1);
	if (err) {
		return nullptr;
	}
	if (!strlen(name)) {
		return nullptr;
	}
	return cmd_strdup(name);
}

static char *cmd_self_username(void)
{
	return cmd_resolve_uid_to_name(geteuid());
}

char *cmd_getusername(void)
{
	char *name;

	name = cmd_getlogin();
	if (name == nullptr) {
		name = cmd_self_username();
	}
	return name;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t getxx_bsz(void)
{
	const size_t align = 1024;
	const size_t bsz1  = cmd_sysconf(_SC_GETPW_R_SIZE_MAX);
	const size_t bsz2  = cmd_sysconf(_SC_GETGR_R_SIZE_MAX);
	const size_t bsz   = (bsz1 > bsz2) ? bsz1 : bsz2;

	return ((bsz + align - 1) / align) * align;
}

static char *cmd_dup_user_group_name(const char *name)
{
	const size_t len = strnlen(name, NAME_MAX + 1);

	if (!len || (len > NAME_MAX)) {
		cmd_diez("bad user name: '%s'", name);
	}
	return cmd_strndup(name, len);
}

uid_t cmd_resolve_name_to_uid(const char *name)
{
	struct passwd  pwd = { .pw_uid = (uid_t)(-1) };
	struct passwd *pw  = nullptr;
	const size_t   bsz = getxx_bsz();
	void          *buf = cmd_zalloc(bsz);
	uid_t          uid = (uid_t)(-1);
	int            err;

	errno = 0;
	err   = getpwnam_r(name, &pwd, buf, bsz, &pw);
	if (err) {
		cmd_die(errno, "failed to resolve user: %s", name);
	}
	if (pw == nullptr) {
		cmd_die(errno, "unknown user: %s", name);
	}
	uid = pw->pw_uid;

	cmd_zfree(buf, bsz);
	return uid;
}

void cmd_resolve_name_to_uidgid(const char *name, uid_t *out_uid,
                                gid_t *out_gid)
{
	struct passwd  pwd = { .pw_uid = (uid_t)(-1) };
	struct passwd *pw  = nullptr;
	const size_t   bsz = getxx_bsz();
	void          *buf = cmd_zalloc(bsz);
	int            err;

	errno = 0;
	err   = getpwnam_r(name, &pwd, buf, bsz, &pw);
	if (err) {
		cmd_die(errno, "failed to resolve user: %s", name);
	}
	if (pw == nullptr) {
		cmd_die(errno, "unknown user: %s", name);
	}
	*out_uid = pw->pw_uid;
	*out_gid = pw->pw_gid;

	cmd_zfree(buf, bsz);
}

char *cmd_resolve_uid_to_name(uid_t uid)
{
	struct passwd  pwd  = { .pw_uid = (uid_t)(-1) };
	struct passwd *pw   = nullptr;
	const size_t   bsz  = getxx_bsz();
	void          *buf  = cmd_zalloc(bsz);
	char          *name = nullptr;
	int            err;

	errno = 0;
	err   = getpwuid_r(uid, &pwd, buf, bsz, &pw);
	if (err) {
		cmd_die(errno, "failed to resolve uid: %u", uid);
	}
	if ((pw == nullptr) || (pw->pw_name == nullptr)) {
		cmd_die(errno, "unknown user: uid=%u", uid);
	}
	name = cmd_dup_user_group_name(pw->pw_name);

	cmd_zfree(buf, bsz);
	return name;
}

gid_t cmd_resolve_name_to_gid(const char *name)
{
	struct group  grp = { .gr_gid = (gid_t)(-1) };
	struct group *gr  = nullptr;
	const size_t  bsz = getxx_bsz();
	void         *buf = cmd_zalloc(bsz);
	gid_t         gid = (gid_t)(-1);
	int           err;

	errno = 0;
	err   = getgrnam_r(name, &grp, buf, bsz, &gr);
	if (err) {
		cmd_die(errno, "failed to resolve group: %s", name);
	}
	if (gr == nullptr) {
		cmd_die(errno, "unknown group: %s", name);
	}
	gid = gr->gr_gid;

	cmd_zfree(buf, bsz);
	return gid;
}

char *cmd_resolve_gid_to_name(gid_t gid)
{
	struct group  grp  = { .gr_gid = (gid_t)(-1) };
	struct group *gr   = nullptr;
	const size_t  bsz  = getxx_bsz();
	void         *buf  = cmd_zalloc(bsz);
	char         *name = nullptr;
	int           err;

	errno = 0;
	err   = getgrgid_r(gid, &grp, buf, bsz, &gr);
	if (err) {
		cmd_die(errno, "failed to resolve gid: %u", gid);
	}
	if ((gr == nullptr) || (gr->gr_name == nullptr)) {
		cmd_die(errno, "unknown group: gid=%u", gid);
	}
	name = cmd_dup_user_group_name(gr->gr_name);

	cmd_zfree(buf, bsz);
	return name;
}

size_t cmd_resolve_supgroups(const char *user, gid_t *groups, size_t ngroups)
{
	const gid_t gid_none = (gid_t)(-1);
	gid_t       gids[64] = { gid_none };
	size_t      ngids    = SILOFS_ARRAY_SIZE(gids);
	int         ngrp     = (int)((ngroups > ngids) ? ngids : ngroups);
	int         err;

	errno = 0;
	err   = getgrouplist(user, gid_none, gids, &ngrp);
	if ((err < 0) || (ngrp > (int)ngroups)) {
		cmd_die(errno, "failed to resolve group-list: user='%s'",
		        user);
	}
	ngids = 0;
	for (int i = 0; i < ngrp; ++i) {
		if (gids[i] == gid_none) {
			continue;
		}
		groups[ngids++] = gids[i];
	}
	return ngids;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define NIDS_MAX (4096)

static void cmd_alloc_users_ids(struct silofs_users_ids *uids)
{
	if (uids->uids == nullptr) {
		uids->uids  = cmd_zalloc(NIDS_MAX * sizeof(uids->uids[0]));
		uids->nuids = 0;
	}
}

static void cmd_dealloc_users_ids(struct silofs_users_ids *uids)
{
	if (uids->uids != nullptr) {
		cmd_zfree(uids->uids, NIDS_MAX * sizeof(uids->uids[0]));
		uids->uids  = nullptr;
		uids->nuids = 0;
	}
}

static void cmd_alloc_groups_ids(struct silofs_groups_ids *gids)
{
	if (gids->gids == nullptr) {
		gids->gids  = cmd_zalloc(NIDS_MAX * sizeof(gids->gids[0]));
		gids->ngids = 0;
	}
}

static void cmd_dealloc_groups_ids(struct silofs_groups_ids *gids)
{
	if (gids->gids != nullptr) {
		cmd_zfree(gids->gids, NIDS_MAX * sizeof(gids->gids[0]));
		gids->gids  = nullptr;
		gids->ngids = 0;
	}
}

static struct silofs_uids *cmd_next_uids(struct silofs_users_ids *uids)
{
	if (uids->nuids == NIDS_MAX) {
		cmd_diez("too many users");
	}
	cmd_alloc_users_ids(uids);
	return &uids->uids[uids->nuids++];
}

static void cmd_require_uniq_uids(const struct silofs_users_ids *uids,
                                  uid_t host_uid, uid_t fs_uid)
{
	for (size_t i = 0; i < uids->nuids; ++i) {
		if (uids->uids[i].host_uid == host_uid) {
			cmd_diez("duplicate host uid: %u", host_uid);
		}
		if (uids->uids[i].fs_uid == fs_uid) {
			cmd_diez("duplicate fs uid: %u", fs_uid);
		}
	}
}

static bool fsids_has_host_uid(const struct silofs_ugids *fsids, uid_t uid)
{
	for (size_t i = 0; i < fsids->users.nuids; ++i) {
		if (fsids->users.uids[i].host_uid == uid) {
			return true;
		}
	}
	return false;
}

static bool fsids_has_host_gid(const struct silofs_ugids *fsids, gid_t gid)
{
	for (size_t i = 0; i < fsids->groups.ngids; ++i) {
		if (fsids->groups.gids[i].host_gid == gid) {
			return true;
		}
	}
	return false;
}

void cmd_require_fsids(const struct silofs_ugids *fsids, uid_t host_uid,
                       gid_t host_gid)
{
	if (!fsids_has_host_uid(fsids, host_uid)) {
		cmd_diez("missing uid-mapping: uid=%u", host_uid);
	}
	if (!fsids_has_host_gid(fsids, host_gid)) {
		cmd_diez("missing gid-mapping: gid=%u", host_gid);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_append_uid_mapping(struct silofs_ugids *fsids, uid_t host_uid,
                            uid_t fs_uid)
{
	struct silofs_uids *uids;

	cmd_require_uniq_uids(&fsids->users, host_uid, fs_uid);
	uids           = cmd_next_uids(&fsids->users);
	uids->host_uid = host_uid;
	uids->fs_uid   = fs_uid;
}

static struct silofs_gids *cmd_next_gids(struct silofs_groups_ids *gids)
{
	if (gids->ngids == NIDS_MAX) {
		cmd_diez("too many groups");
	}
	cmd_alloc_groups_ids(gids);
	return &gids->gids[gids->ngids++];
}

static void cmd_require_uniq_gids(const struct silofs_groups_ids *gids,
                                  gid_t host_gid, gid_t fs_gid)
{
	for (size_t i = 0; i < gids->ngids; ++i) {
		if (gids->gids[i].host_gid == host_gid) {
			cmd_diez("duplicate host gid: %u", host_gid);
		}
		if (gids->gids[i].fs_gid == fs_gid) {
			cmd_diez("duplicate fs gid: %u", fs_gid);
		}
	}
}

void cmd_append_gid_mapping(struct silofs_ugids *fsids, uid_t host_gid,
                            uid_t fs_gid)
{
	struct silofs_gids *gids;

	cmd_require_uniq_gids(&fsids->groups, host_gid, fs_gid);
	gids           = cmd_next_gids(&fsids->groups);
	gids->host_gid = host_gid;
	gids->fs_gid   = fs_gid;
}

void cmd_append_user_uidgid(struct silofs_ugids *fsids, const char *name)
{
	uid_t uid = (uid_t)(-1);
	gid_t gid = (gid_t)(-1);

	cmd_resolve_name_to_uidgid(name, &uid, &gid);
	cmd_append_uid_mapping(fsids, uid, uid);
	cmd_append_gid_mapping(fsids, gid, gid);
}

void cmd_append_user_supgroups(struct silofs_ugids *fsids, const char *name)
{
	gid_t  gids[64];
	size_t ngids = 0;

	ngids = cmd_resolve_supgroups(name, gids, SILOFS_ARRAY_SIZE(gids));
	for (size_t i = 0; i < ngids; ++i) {
		cmd_append_gid_mapping(fsids, gids[i], gids[i]);
	}
}

void cmd_start_fsids(struct silofs_ugids *fsids)
{
	fsids->users.nuids  = 0;
	fsids->users.uids   = nullptr;
	fsids->groups.ngids = 0;
	fsids->groups.gids  = nullptr;
}

void cmd_finish_fsids(struct silofs_ugids *fsids)
{
	cmd_dealloc_users_ids(&fsids->users);
	cmd_dealloc_groups_ids(&fsids->groups);
}
