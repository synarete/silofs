/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include "cmd_jconf.h"
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

static size_t cmd_sysconf_getpwgr_rsize_max(void)
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

static uid_t cmd_resolve_name_to_uid(const char *name)
{
	struct passwd pwd = { .pw_uid = (uid_t)(-1) };
	struct passwd *pw = nullptr;
	const size_t bsz  = cmd_sysconf_getpwgr_rsize_max();
	void *buf         = cmd_zalloc(bsz);
	uid_t uid         = (uid_t)(-1);
	int err;

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

static void
cmd_resolve_name_to_uidgid(const char *name, uid_t *out_uid, gid_t *out_gid)
{
	struct passwd pwd = { .pw_uid = (uid_t)(-1) };
	struct passwd *pw = nullptr;
	const size_t bsz  = cmd_sysconf_getpwgr_rsize_max();
	void *buf         = cmd_zalloc(bsz);
	int err;

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

static char *cmd_resolve_uid_to_name(uid_t uid)
{
	struct passwd pwd = { .pw_uid = (uid_t)(-1) };
	struct passwd *pw = nullptr;
	const size_t bsz  = cmd_sysconf_getpwgr_rsize_max();
	void *buf         = cmd_zalloc(bsz);
	char *name        = nullptr;
	int err;

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

static gid_t cmd_resolve_name_to_gid(const char *name)
{
	struct group grp = { .gr_gid = (gid_t)(-1) };
	struct group *gr = nullptr;
	const size_t bsz = cmd_sysconf_getpwgr_rsize_max();
	void *buf        = cmd_zalloc(bsz);
	gid_t gid        = (gid_t)(-1);
	int err;

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

static char *cmd_resolve_gid_to_name(gid_t gid)
{
	struct group grp = { .gr_gid = (gid_t)(-1) };
	struct group *gr = nullptr;
	const size_t bsz = cmd_sysconf_getpwgr_rsize_max();
	void *buf        = cmd_zalloc(bsz);
	char *name       = nullptr;
	int err;

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

static size_t
cmd_resolve_supgroups_of(const char *user, gid_t *groups, size_t ngroups)
{
	const gid_t gid_none = (gid_t)(-1);
	gid_t gids[64]       = { gid_none };
	size_t ngids         = SILOFS_ARRAY_SIZE(gids);
	int ngrp             = (int)((ngroups > ngids) ? ngids : ngroups);
	int err;

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

static char *cmd_getlogin(void)
{
	char name[LOGIN_NAME_MAX + 1] = "";
	int err;

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

static void cmd_alloc_users_ids(struct silofs_users_ids *uids)
{
	if (uids->uids == nullptr) {
		uids->uids =
			cmd_zalloc(SILOFS_NIDS_MAX * sizeof(uids->uids[0]));
		uids->nuids = 0;
	}
}

static void cmd_dealloc_users_ids(struct silofs_users_ids *uids)
{
	if (uids->uids != nullptr) {
		cmd_zfree(uids->uids, SILOFS_NIDS_MAX * sizeof(uids->uids[0]));
		uids->uids  = nullptr;
		uids->nuids = 0;
	}
}

static void cmd_alloc_groups_ids(struct silofs_groups_ids *gids)
{
	if (gids->gids == nullptr) {
		gids->gids =
			cmd_zalloc(SILOFS_NIDS_MAX * sizeof(gids->gids[0]));
		gids->ngids = 0;
	}
}

static void cmd_dealloc_groups_ids(struct silofs_groups_ids *gids)
{
	if (gids->gids != nullptr) {
		cmd_zfree(gids->gids, SILOFS_NIDS_MAX * sizeof(gids->gids[0]));
		gids->gids  = nullptr;
		gids->ngids = 0;
	}
}

static bool
cmd_fsids_has_host_uid(const struct silofs_fsids *fsids, uid_t host_uid)
{
	for (size_t i = 0; i < fsids->users.nuids; ++i) {
		if (fsids->users.uids[i].host_uid == host_uid) {
			return true;
		}
	}
	return false;
}

static bool
cmd_fsids_has_fs_uid(const struct silofs_fsids *fsids, uid_t fs_uid)
{
	for (size_t i = 0; i < fsids->users.nuids; ++i) {
		if (fsids->users.uids[i].fs_uid == fs_uid) {
			return true;
		}
	}
	return false;
}

static void cmd_fsids_require_uniq_uids(const struct silofs_fsids *fsids,
                                        uid_t host_uid, uid_t fs_uid)
{
	if (cmd_fsids_has_host_uid(fsids, host_uid)) {
		cmd_diez("duplicate host uid: %u", host_uid);
	}
	if (cmd_fsids_has_fs_uid(fsids, fs_uid)) {
		cmd_diez("duplicate fs uid: %u", fs_uid);
	}
}

static void
cmd_fsids_require_host_uid(const struct silofs_fsids *fsids, uid_t host_uid)
{
	if (!cmd_fsids_has_host_uid(fsids, host_uid)) {
		cmd_diez("missing host uid mapping: uid=%u", host_uid);
	}
}

static bool
cmd_fsids_has_host_gid(const struct silofs_fsids *fsids, gid_t host_gid)
{
	for (size_t i = 0; i < fsids->groups.ngids; ++i) {
		if (fsids->groups.gids[i].host_gid == host_gid) {
			return true;
		}
	}
	return false;
}

static void
cmd_fsids_require_host_gid(const struct silofs_fsids *fsids, gid_t host_gid)
{
	if (!cmd_fsids_has_host_gid(fsids, host_gid)) {
		cmd_diez("missing host gid mapping: gid=%u", host_gid);
	}
}

static void cmd_fsids_need_uidgid(const struct silofs_fsids *fsids,
                                  uid_t host_uid, gid_t host_gid)
{
	cmd_fsids_require_host_uid(fsids, host_uid);
	cmd_fsids_require_host_gid(fsids, host_gid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_uids *cmd_fsids_next_uids(struct silofs_fsids *fsids)
{
	struct silofs_users_ids *uids = &fsids->users;

	if (uids->nuids == SILOFS_NIDS_MAX) {
		cmd_diez("too many users");
	}
	cmd_alloc_users_ids(uids);
	return &uids->uids[uids->nuids++];
}

static void cmd_fsids_add_uid_mapping(struct silofs_fsids *fsids,
                                      uid_t host_uid, uid_t fs_uid)
{
	struct silofs_uids *uids;

	cmd_fsids_require_uniq_uids(fsids, host_uid, fs_uid);
	uids           = cmd_fsids_next_uids(fsids);
	uids->host_uid = host_uid;
	uids->fs_uid   = fs_uid;
}

static struct silofs_gids *cmd_fsids_next_gids(struct silofs_fsids *fsids)
{
	struct silofs_groups_ids *gids = &fsids->groups;

	if (gids->ngids == SILOFS_NIDS_MAX) {
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

static void cmd_fsids_add_gid_mapping(struct silofs_fsids *fsids,
                                      uid_t host_gid, uid_t fs_gid)
{
	struct silofs_gids *gids;

	cmd_require_uniq_gids(&fsids->groups, host_gid, fs_gid);
	gids           = cmd_fsids_next_gids(fsids);
	gids->host_gid = host_gid;
	gids->fs_gid   = fs_gid;
}

static void
cmd_fsids_add_supgroups_of(struct silofs_fsids *fsids, const char *name)
{
	gid_t gids[64];
	size_t ngids = 0;

	ngids = cmd_resolve_supgroups_of(name, gids, SILOFS_ARRAY_SIZE(gids));
	for (size_t i = 0; i < ngids; ++i) {
		cmd_fsids_add_gid_mapping(fsids, gids[i], gids[i]);
	}
}

static void
cmd_fsids_need_user(const struct silofs_fsids *fsids, const char *name)
{
	uid_t host_uid = (uid_t)(-1);
	gid_t host_gid = (gid_t)(-1);

	cmd_resolve_name_to_uidgid(name, &host_uid, &host_gid);
	cmd_fsids_need_uidgid(fsids, host_uid, host_gid);
}

static void cmd_fsids_need_self(const struct silofs_fsids *fsids)
{
	char *username = cmd_getusername();

	cmd_fsids_need_user(fsids, username);
	cmd_pstrfree(&username);
}

static void cmd_fsids_setup(struct silofs_fsids *fsids)
{
	fsids->users.nuids  = 0;
	fsids->users.uids   = nullptr;
	fsids->groups.ngids = 0;
	fsids->groups.gids  = nullptr;
}

static void cmd_fsids_dealloc(struct silofs_fsids *fsids)
{
	cmd_dealloc_users_ids(&fsids->users);
	cmd_dealloc_groups_ids(&fsids->groups);
}

static void cmd_fsids_clear(struct silofs_fsids *fsids)
{
	cmd_fsids_dealloc(fsids);
	cmd_fsids_setup(fsids);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char cmd_jkey_fsmeta[]    = "fsmeta";
static const char cmd_jkey_fsref[]     = "fsref";
static const char cmd_jkey_fsids[]     = "fsids";
static const char cmd_jkey_users[]     = "users";
static const char cmd_jkey_username[]  = "username";
static const char cmd_jkey_uid[]       = "uid";
static const char cmd_jkey_groups[]    = "groups";
static const char cmd_jkey_groupname[] = "groupname";
static const char cmd_jkey_gid[]       = "gid";
static const char cmd_jkey_mbaddr[]    = "mbaddr";

static json_t *cmd_fsids_jencode_users(const struct silofs_fsids *fsids)
{
	json_t *jusers = nullptr;
	json_t *juser  = nullptr;
	json_t *jname  = nullptr;
	json_t *juid   = nullptr;
	char *name     = nullptr;
	uid_t host_uid, fs_uid;

	jusers = cmd_json_array();
	for (size_t idx = 0; idx < fsids->users.nuids; ++idx) {
		juser = cmd_json_object();

		host_uid = fsids->users.uids[idx].host_uid;
		name     = cmd_resolve_uid_to_name(host_uid);
		jname    = cmd_json_string(name);
		cmd_json_object_set_new(juser, cmd_jkey_username, jname);

		fs_uid = fsids->users.uids[idx].fs_uid;
		juid   = cmd_json_integer((long)fs_uid);
		cmd_json_object_set_new(juser, cmd_jkey_uid, juid);

		cmd_json_array_append(jusers, juser);
		cmd_pstrfree(&name);
	}
	return jusers;
}

static void
cmd_fsids_jdecode_users(struct silofs_fsids *fsids, const json_t *jusers)
{
	const json_t *juser = nullptr;
	const json_t *jname = nullptr;
	const json_t *juid  = nullptr;
	const char *name    = nullptr;
	uid_t host_uid, fs_uid;
	size_t size;

	size = cmd_json_array_size(jusers);
	for (size_t idx = 0; idx < size; ++idx) {
		juser = cmd_json_array_get(jusers, idx);
		jname = cmd_json_object_get_string(juser, cmd_jkey_username);
		name  = cmd_json_string_value(jname);
		host_uid = cmd_resolve_name_to_uid(name);

		juid   = cmd_json_object_get_integer(juser, cmd_jkey_uid);
		fs_uid = cmd_json_uint32_value(juid);

		cmd_fsids_add_uid_mapping(fsids, host_uid, fs_uid);
	}
}

static json_t *cmd_fsids_jencode_groups(const struct silofs_fsids *fsids)
{
	json_t *jgroups = nullptr;
	json_t *jgroup  = nullptr;
	json_t *jname   = nullptr;
	json_t *jgid    = nullptr;
	char *name      = nullptr;
	gid_t host_gid, fs_gid;

	jgroups = cmd_json_array();
	for (size_t idx = 0; idx < fsids->groups.ngids; ++idx) {
		jgroup = cmd_json_object();

		host_gid = fsids->groups.gids[idx].host_gid;
		name     = cmd_resolve_gid_to_name(host_gid);
		jname    = cmd_json_string(name);
		cmd_json_object_set_new(jgroup, cmd_jkey_groupname, jname);

		fs_gid = fsids->groups.gids[idx].fs_gid;
		jgid   = cmd_json_integer((long)fs_gid);
		cmd_json_object_set_new(jgroup, cmd_jkey_gid, jgid);

		cmd_json_array_append(jgroups, jgroup);
		cmd_pstrfree(&name);
	}
	return jgroups;
}

static void
cmd_fsids_jdecode_groups(struct silofs_fsids *fsids, const json_t *jgroups)
{
	const json_t *jgroup = nullptr;
	const json_t *jname  = nullptr;
	const json_t *jgid   = nullptr;
	const char *name     = nullptr;
	gid_t host_gid, fs_gid;
	size_t size;

	size = cmd_json_array_size(jgroups);
	for (size_t idx = 0; idx < size; ++idx) {
		jgroup = cmd_json_array_get(jgroups, idx);
		jname = cmd_json_object_get_string(jgroup, cmd_jkey_groupname);
		name  = cmd_json_string_value(jname);
		host_gid = cmd_resolve_name_to_gid(name);

		jgid   = cmd_json_object_get_integer(jgroup, cmd_jkey_gid);
		fs_gid = cmd_json_uint32_value(jgid);

		cmd_fsids_add_gid_mapping(fsids, host_gid, fs_gid);
	}
}

static json_t *cmd_fsids_jencode(const struct silofs_fsids *fsids)
{
	json_t *jfsids  = nullptr;
	json_t *jusers  = nullptr;
	json_t *jgroups = nullptr;

	jfsids = cmd_json_object();

	jusers = cmd_fsids_jencode_users(fsids);
	cmd_json_object_set_new(jfsids, cmd_jkey_users, jusers);

	jgroups = cmd_fsids_jencode_groups(fsids);
	cmd_json_object_set_new(jfsids, cmd_jkey_groups, jgroups);

	return jfsids;
}

static void cmd_fsids_jdecode(struct silofs_fsids *fsids, const json_t *jfsids)
{
	const json_t *jusers  = nullptr;
	const json_t *jgroups = nullptr;

	jusers = cmd_json_object_get_array(jfsids, cmd_jkey_users);
	cmd_fsids_jdecode_users(fsids, jusers);

	jgroups = cmd_json_object_get_array(jfsids, cmd_jkey_groups);
	cmd_fsids_jdecode_groups(fsids, jgroups);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_fsref_setup(struct silofs_fsref *fsref)
{
	memset(fsref, 0, sizeof(*fsref));
	silofs_getfsmeta(&fsref->fsmeta);
}

static json_t *cmd_fsref_jencode(const struct silofs_fsref *fsref)
{
	json_t *jfsref = nullptr;
	json_t *jsub   = nullptr;

	jfsref = cmd_json_object();

	jsub = cmd_json_mbaddr(&fsref->mbaddr);
	cmd_json_object_set_new(jfsref, cmd_jkey_mbaddr, jsub);

	return jfsref;
}

static void cmd_fsref_jdecode(struct silofs_fsref *fsref, const json_t *jobj)
{
	json_t *jfsref = nullptr;

	jfsref = cmd_json_object_get(jobj, cmd_jkey_mbaddr);
	cmd_json_mbaddr_value(jfsref, &fsref->mbaddr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static json_t *cmd_spec_jencode(const struct silofs_spec *spec)
{
	json_t *jspec   = nullptr;
	json_t *jfsmeta = nullptr;
	json_t *jfsref  = nullptr;
	json_t *jfsids  = nullptr;

	jspec = cmd_json_object();

	jfsmeta = cmd_json_fsmeta(&spec->fsref.fsmeta);
	cmd_json_object_set_new(jspec, cmd_jkey_fsmeta, jfsmeta);

	jfsref = cmd_fsref_jencode(&spec->fsref);
	cmd_json_object_set_new(jspec, cmd_jkey_fsref, jfsref);

	jfsids = cmd_fsids_jencode(&spec->fsids);
	cmd_json_object_set_new(jspec, cmd_jkey_fsids, jfsids);

	return jspec;
}

static void cmd_spec_jsave_at(const struct silofs_spec *spec,
                              const struct silofs_baseref *baseref)
{
	json_t *jspec = nullptr;

	jspec = cmd_spec_jencode(spec);
	cmd_json_save(jspec, baseref->repodir, baseref->refname);
	cmd_json_decref(jspec);
}

void cmd_spec_jsave(const struct silofs_spec *spec)
{
	cmd_spec_jsave_at(spec, &spec->bref[0]);
}

void cmd_spec_jsave2(const struct silofs_spec *spec)
{
	cmd_spec_jsave_at(spec, &spec->bref[1]);
}

static void cmd_spec_jdecode(struct silofs_spec *spec, const json_t *jspec)
{
	json_t *jfsmeta = nullptr;
	json_t *jfsref  = nullptr;
	json_t *jfsids  = nullptr;

	jfsmeta = cmd_json_object_get(jspec, cmd_jkey_fsmeta);
	cmd_json_fsmeta_value(jfsmeta, &spec->fsref.fsmeta);

	jfsref = cmd_json_object_get(jspec, cmd_jkey_fsref);
	cmd_fsref_jdecode(&spec->fsref, jfsref);

	jfsids = cmd_json_object_get(jspec, cmd_jkey_fsids);
	cmd_fsids_jdecode(&spec->fsids, jfsids);
}

static void cmd_spec_jload_at(struct silofs_spec *spec,
                              const struct silofs_baseref *baseref)
{
	json_t *jspec = nullptr;

	jspec = cmd_json_load(baseref->repodir, baseref->refname);
	cmd_spec_jdecode(spec, jspec);
	cmd_json_decref(jspec);
}

void cmd_spec_jload(struct silofs_spec *spec)
{
	cmd_spec_jload_at(spec, &spec->bref[0]);
}

void cmd_spec_jload2(struct silofs_spec *spec)
{
	cmd_spec_jload_at(spec, &spec->bref[1]);
}

void cmd_spec_junlink(const struct silofs_spec *spec)
{
	cmd_json_unlink(spec->bref[0].repodir, spec->bref[0].refname);
}

static void cmd_spec_bzero(struct silofs_spec *spec)
{
	memset(spec, 0, sizeof(*spec));
}

void cmd_spec_setup(struct silofs_spec *spec)
{
	cmd_spec_setup1(spec, 0);
}

void cmd_spec_setup1(struct silofs_spec *spec, int flags)
{
	cmd_spec_setup2(spec, 0, flags);
}

void cmd_spec_setup2(struct silofs_spec *spec, size_t fs_capacity, int flags)
{
	cmd_spec_bzero(spec);
	cmd_fsids_setup(&spec->fsids);
	cmd_fsref_setup(&spec->fsref);
	spec->fsowner.uid   = getuid();
	spec->fsowner.gid   = getgid();
	spec->fsowner.umask = 0077;
	spec->flags         = (enum silofs_flags)flags;
	spec->fscap         = fs_capacity;
}

void cmd_spec_update_fsref(struct silofs_spec *spec,
                           const struct silofs_fsref *fsref)
{
	memcpy(&spec->fsref, fsref, sizeof(spec->fsref));
}

static void cmd_spec_set_passwd(struct silofs_spec *spec, const char *passwd)
{
	cmd_mkpasswd(&spec->passwd, passwd);
}

void cmd_spec_own_passwd(struct silofs_spec *spec, char **passwd)
{
	cmd_spec_set_passwd(spec, *passwd);
	cmd_delpass(passwd);
}

void cmd_spec_set_baseref(struct silofs_spec *spec, const char *repodir,
                          const char *refname)
{
	spec->bref[0].repodir = repodir;
	spec->bref[0].refname = refname;
}

void cmd_spec_set_baseref2(struct silofs_spec *spec, const char *repodir,
                           const char *refname)
{
	spec->bref[1].repodir = repodir;
	spec->bref[1].refname = refname;
}

void cmd_spec_update_owner(struct silofs_spec *spec, const char *username,
                           bool with_sup_groups)
{
	uid_t uid;
	gid_t gid;

	cmd_resolve_name_to_uidgid(username, &uid, &gid);
	cmd_fsids_add_uid_mapping(&spec->fsids, uid, uid);
	cmd_fsids_add_gid_mapping(&spec->fsids, gid, gid);
	spec->fsowner.uid = uid;
	spec->fsowner.gid = gid;
	if (with_sup_groups) {
		cmd_fsids_add_supgroups_of(&spec->fsids, username);
	}
}

void cmd_spec_append_user(struct silofs_spec *spec, const char *username)
{
	uid_t uid;
	gid_t gid;

	cmd_resolve_name_to_uidgid(username, &uid, &gid);
	if (!cmd_fsids_has_host_uid(&spec->fsids, uid)) {
		cmd_fsids_add_uid_mapping(&spec->fsids, uid, uid);
	}
	if (!cmd_fsids_has_host_gid(&spec->fsids, gid)) {
		cmd_fsids_add_gid_mapping(&spec->fsids, gid, gid);
	}
}

void cmd_spec_clear_fsids(struct silofs_spec *spec)
{
	cmd_fsids_clear(&spec->fsids);
}

void cmd_spec_need_self(const struct silofs_spec *spec)
{
	cmd_fsids_need_self(&spec->fsids);
}

void cmd_spec_reset(struct silofs_spec *spec)
{
	cmd_spec_clear_fsids(spec);
	cmd_spec_bzero(spec);
}
