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
#include <time.h>
#include <jansson.h>
#include "cmd.h"

static char *cmd_current_time(void)
{
	char      ts[80] = "";
	time_t    curr_tm;
	struct tm tm;

	time(&curr_tm);
	if (localtime_r(&curr_tm, &tm) == nullptr) {
		cmd_diez("json: failed get local time");
	}
	if (strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm) == 0) {
		cmd_diez("json: failed format time");
	}
	return cmd_strdup(ts);
}

static json_t *cmd_json_object(void)
{
	json_t *jobj;

	jobj = json_object();
	if (jobj == nullptr) {
		cmd_diez("json: failed to create object");
	}
	return jobj;
}

static json_t *cmd_json_string(const char *s)
{
	json_t *jstr;

	jstr = json_string(s);
	if (jstr == nullptr) {
		cmd_diez("json: failed to create string: '%s'", s);
	}
	return jstr;
}

static json_t *cmd_json_integer(long n)
{
	json_t *jint;

	jint = json_integer(n);
	if (jint == nullptr) {
		cmd_diez("json: failed to create integer: %ld", n);
	}
	return jint;
}

static json_t *cmd_json_array(void)
{
	json_t *jarr;

	jarr = json_array();
	if (jarr == nullptr) {
		cmd_diez("json: failed to create array");
	}
	return jarr;
}

static size_t cmd_json_array_size(const json_t *jarr)
{
	if (!json_is_array(jarr)) {
		cmd_diez("json: not an array");
	}
	return json_array_size(jarr);
}

static json_t *cmd_json_array_get(const json_t *jarr, size_t idx)
{
	json_t *jsub;

	jsub = json_array_get(jarr, idx);
	if (jsub == nullptr) {
		cmd_diez("json: bad array index: %zu", idx);
	}
	return jsub;
}

static json_t *cmd_json_btime(void)
{
	char   *tnow;
	json_t *jstr;

	tnow = cmd_current_time();
	jstr = cmd_json_string(tnow);
	cmd_pstrfree(&tnow);
	return jstr;
}

static json_t *cmd_json_mbref(const struct silofs_mbref *mbref)
{
	char s[256] = "";
	int  err;

	err = silofs_encode_mbref(mbref, s, sizeof(s));
	if (err) {
		cmd_die(err, "json: failed to encode blobid");
	}
	return cmd_json_string(s);
}

static void cmd_json_object_set_new(json_t *jobj, const char *key, json_t *val)
{
	int err;

	err = json_object_set_new(jobj, key, val);
	if (err) {
		cmd_diez("json: failed to set new: key='%s' err=%d", key, err);
	}
}

static void cmd_json_append(json_t *jobj, json_t *jval)
{
	int err;

	err = json_array_append(jobj, jval);
	if (err) {
		cmd_diez("json: failed to grow array: err=%d", err);
	}
}

static char *cmd_json_dumps(json_t *root)
{
	char *out;

	out = json_dumps(root, JSON_INDENT(2));
	if (out == nullptr) {
		cmd_diez("json: failed to dumps");
	}
	return out;
}

static json_t *cmd_json_loads(const char *jtxt)
{
	json_t      *jobj;
	json_error_t jerr;

	jobj = json_loads(jtxt, 0, &jerr);
	if (jobj == nullptr) {
		cmd_diez("json: failed to parse: text='%s' line=%d column=%d",
		         jerr.text, jerr.line, jerr.column);
	}
	return jobj;
}

static json_t *cmd_json_object_get(const json_t *jobj, const char *key)
{
	json_t *jsub;

	jsub = json_object_get(jobj, key);
	if (jsub == nullptr) {
		cmd_diez("json: failed to parse: key='%s'", key);
	}
	return jsub;
}

static json_t *cmd_json_object_get_string(const json_t *jobj, const char *key)
{
	json_t *jstr;

	jstr = cmd_json_object_get(jobj, key);
	if (!json_is_string(jstr)) {
		cmd_diez("json: failed to parse string: key='%s'", key);
	}
	return jstr;
}

static const char *cmd_json_string_value(const json_t *jstr)
{
	const char *val;

	val = json_string_value(jstr);
	if (val == nullptr) {
		cmd_diez("json: bad string value");
	}
	return val;
}

static json_t *cmd_json_object_get_integer(const json_t *jobj, const char *key)
{
	json_t *jint;

	jint = cmd_json_object_get(jobj, key);
	if (!json_is_integer(jint)) {
		cmd_diez("json: failed to parse integer: key='%s'", key);
	}
	return jint;
}

static uint64_t cmd_json_uint64_value(const json_t *jint)
{
	json_int_t val;

	val = json_integer_value(jint);
	if (val < 0) {
		cmd_diez("json: bad unsigned-integer value: %lld", val);
	}
	return (uint64_t)val;
}

static uint32_t cmd_json_uint32_value(const json_t *jint)
{
	uint64_t u;

	u = cmd_json_uint64_value(jint);
	if (u > UINT32_MAX) {
		cmd_diez("json: bad uint32 value: %zu", u);
	}
	return (uint32_t)u;
}

static json_t *cmd_json_object_get_array(const json_t *jobj, const char *key)
{
	json_t *jstr;

	jstr = cmd_json_object_get(jobj, key);
	if (!json_is_array(jstr)) {
		cmd_diez("json: failed to parse array: key='%s'", key);
	}
	return jstr;
}

static void cmd_json_decref(json_t *root)
{
	json_decref(root);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char cmd_jkey_version[] = "version";
static const char cmd_jkey_fmtvers[] = "fmtvers";
static const char cmd_jkey_btime[]   = "btime";
static const char cmd_jkey_mbref[]   = "mbref";

static void cmd_jref_add_version(json_t *jobj)
{
	json_t *jsub;

	jsub = cmd_json_string(silofs_version.string);
	cmd_json_object_set_new(jobj, cmd_jkey_version, jsub);
}

static void cmd_jref_add_fmtrev(json_t *jobj)
{
	json_t *jsub;

	jsub = cmd_json_integer(SILOFS_FMT_VERSION);
	cmd_json_object_set_new(jobj, cmd_jkey_fmtvers, jsub);
}

static void cmd_jref_add_btime(json_t *jobj)
{
	json_t *jsub;

	jsub = cmd_json_btime();
	cmd_json_object_set_new(jobj, cmd_jkey_btime, jsub);
}

static void cmd_jref_add_mbref(json_t *jobj, const struct silofs_mbref *mbref)
{
	json_t *jsub;

	jsub = cmd_json_mbref(mbref);
	cmd_json_object_set_new(jobj, cmd_jkey_mbref, jsub);
}

static char *cmd_encode_jref(const struct silofs_mbref *mbref)
{
	json_t *jroot = nullptr;
	char   *jtxt  = nullptr;

	jroot = cmd_json_object();
	cmd_jref_add_version(jroot);
	cmd_jref_add_fmtrev(jroot);
	cmd_jref_add_btime(jroot);
	cmd_jref_add_mbref(jroot, mbref);
	jtxt = cmd_json_dumps(jroot);
	cmd_json_decref(jroot);
	return jtxt;
}

static void cmd_jref_get_version(const json_t *jobj)
{
	const json_t *jstr;

	jstr = cmd_json_object_get_string(jobj, cmd_jkey_version);
	(void)jstr;
}

static void cmd_jref_get_fmtvers(const json_t *jobj)
{
	const json_t *jint;
	uint32_t      vers;

	jint = cmd_json_object_get_integer(jobj, cmd_jkey_fmtvers);
	vers = cmd_json_uint32_value(jint);
	if (vers != SILOFS_FMT_VERSION) {
		cmd_diez("json: unsupported fmtvers: '%ld'", (long)vers);
	}
}

static void cmd_jref_get_btime(const json_t *jobj)
{
	json_t *jsub;

	jsub = cmd_json_object_get_string(jobj, cmd_jkey_btime);
	(void)jsub;
}

static void
cmd_jref_get_mbref(const json_t *jobj, struct silofs_mbref *out_mbref)
{
	json_t     *jsub;
	const char *str;
	int         err;

	jsub = cmd_json_object_get_string(jobj, cmd_jkey_mbref);
	str  = cmd_json_string_value(jsub);
	err  = silofs_decode_mbref(out_mbref, str);
	if (err) {
		cmd_die(err, "json: illegal mbref: '%s'", str);
	}
}

static void cmd_decode_jref(const char *jtxt, struct silofs_mbref *out_mbref)
{
	json_t *jroot;

	jroot = cmd_json_loads(jtxt);
	cmd_jref_get_version(jroot);
	cmd_jref_get_fmtvers(jroot);
	cmd_jref_get_btime(jroot);
	cmd_jref_get_mbref(jroot, out_mbref);
	cmd_json_decref(jroot);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
cmd_open_repodir(const struct silofs_boot_args *boot_args, int *out_dfd)
{
	const char *repodir = boot_args->repodir;
	int         dfd     = -1;
	int         err;

	err = silofs_sys_open(repodir, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		cmd_die(err, "failed to open repodir: %s", repodir);
	}
	*out_dfd = dfd;
}

static void
cmd_close_repodir(const struct silofs_boot_args *boot_args, int *dfd)
{
	const char *repodir = boot_args->repodir;
	int         err;

	err = silofs_sys_closefd(dfd);
	if (err) {
		cmd_die(err, "failed to open repodir: %s", repodir);
	}
}

static void cmd_save_jtext_at(int dfd, const char *name, const char *jtxt)
{
	char tmp[NAME_MAX + 1] = "";
	int  fd                = -1;
	int  err;

	snprintf(tmp, sizeof(tmp) - 1, "%s~", name);
	err = silofs_sys_openat(dfd, tmp, O_CREAT | O_RDWR | O_TRUNC,
	                        S_IRUSR | S_IWUSR, &fd);
	if (err) {
		cmd_die(err, "failed to create: %s", tmp);
	}
	err = silofs_sys_fchmod(fd, S_IRUSR);
	if (err) {
		cmd_die(err, "failed to change-mode: %s", tmp);
	}
	err = silofs_sys_writen(fd, jtxt, strlen(jtxt));
	if (err) {
		cmd_die(err, "failed to write: %s", tmp);
	}
	err = silofs_sys_writen(fd, "\n", 1);
	if (err) {
		cmd_die(err, "failed to write: %s", tmp);
	}
	silofs_sys_closefd(&fd);

	silofs_sys_fchmodat(dfd, name, S_IRUSR | S_IWUSR, 0);
	err = silofs_sys_renameat(dfd, tmp, dfd, name);
	if (err) {
		silofs_sys_fchmodat(dfd, name, S_IRUSR, 0);
		cmd_die(err, "failed to rename: %s", name);
	}
	err = silofs_sys_fchmodat(dfd, name, S_IRUSR, 0);
	if (err) {
		cmd_die(err, "failed to change-mode: %s", name);
	}
}

static char *cmd_load_jtext_at(int dfd, const char *name)
{
	struct stat  st       = { .st_mode = 0 };
	const size_t jtxt_max = 1 << 24;
	char        *jtxt     = nullptr;
	size_t       len      = 0;
	int          fd       = -1;
	int          err;

	err = silofs_sys_fstatat(dfd, name, &st, 0);
	if (err) {
		cmd_die(err, "stat failure: %s", name);
	}
	if (!S_ISREG(st.st_mode)) {
		cmd_diez("not a regular file: %s", name);
	}
	len = (size_t)st.st_size;
	if (len >= jtxt_max) {
		cmd_die(-EFBIG, "illegal json size: %s", name);
	}
	err = silofs_sys_openat(dfd, name, O_RDONLY, 0, &fd);
	if (err) {
		cmd_die(err, "failed to open: %s", name);
	}
	jtxt = cmd_zalloc(len + 1);
	err  = silofs_sys_readn(fd, jtxt, len);
	silofs_sys_closefd(&fd);
	if (err) {
		cmd_die(err, "failed to read blobid: %s", name);
	}
	return jtxt;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void
cmd_save_jref_at(int dfd, const char *name, const struct silofs_mbref *mbref)
{
	char *jtxt;

	jtxt = cmd_encode_jref(mbref);
	cmd_save_jtext_at(dfd, name, jtxt);
	free(jtxt);
}

void cmd_save_fs_jref(const struct silofs_boot_args *boot_args,
                      const struct silofs_mbref     *fs_mbref)
{
	int dfd = -1;

	cmd_open_repodir(boot_args, &dfd);
	cmd_save_jref_at(dfd, boot_args->fs_name, fs_mbref);
	cmd_close_repodir(boot_args, &dfd);
}

void cmd_save_ar_jref(const struct silofs_boot_args *boot_args,
                      const struct silofs_mbref     *ar_mbref)
{
	int dfd = -1;

	cmd_open_repodir(boot_args, &dfd);
	cmd_save_jref_at(dfd, boot_args->ar_name, ar_mbref);
	cmd_close_repodir(boot_args, &dfd);
}

static void
cmd_load_jref_at(int dfd, const char *name, struct silofs_mbref *out_mbref)
{
	char *jtxt = nullptr;

	jtxt = cmd_load_jtext_at(dfd, name);
	cmd_decode_jref(jtxt, out_mbref);
	cmd_pstrfree(&jtxt);
}

static void cmd_load_jref_of(const struct silofs_boot_args *boot_args, bool ar,
                             struct silofs_mbref *out_mbref)
{
	const char *name;
	int         dfd = -1;

	name = ar ? boot_args->ar_name : boot_args->fs_name;
	cmd_open_repodir(boot_args, &dfd);
	cmd_load_jref_at(dfd, name, out_mbref);
	cmd_close_repodir(boot_args, &dfd);
}

void cmd_load_fs_jref(const struct silofs_boot_args *boot_args,
                      struct silofs_mbref           *out_mbref)
{
	cmd_load_jref_of(boot_args, false, out_mbref);
}

void cmd_load_ar_jref(struct silofs_boot_args *boot_args,
                      struct silofs_mbref     *out_mbref)
{
	cmd_load_jref_of(boot_args, true, out_mbref);
}

void cmd_unlink_fs_jref(const struct silofs_boot_args *boot_args)
{
	int dfd = -1;

	cmd_open_repodir(boot_args, &dfd);
	silofs_sys_unlinkat(dfd, boot_args->fs_name, 0);
	cmd_close_repodir(boot_args, &dfd);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char cmd_jkey_users[]  = "users";
static const char cmd_jkey_user[]   = "user";
static const char cmd_jkey_uid[]    = "uid";
static const char cmd_jkey_groups[] = "groups";
static const char cmd_jkey_group[]  = "group";
static const char cmd_jkey_gid[]    = "gid";

static const char cmd_jfsids_filename[] = "fsids.json";

static json_t *cmd_encode_jfsids_users(const struct silofs_ugids *fsids)
{
	json_t *jusers = nullptr;
	json_t *juser  = nullptr;
	json_t *jname  = nullptr;
	json_t *juid   = nullptr;
	char   *name   = nullptr;
	uid_t   host_uid, fs_uid;

	jusers = cmd_json_array();
	for (size_t idx = 0; idx < fsids->users.nuids; ++idx) {
		juser = cmd_json_object();

		host_uid = fsids->users.uids[idx].host_uid;
		name     = cmd_resolve_uid_to_name(host_uid);
		jname    = cmd_json_string(name);
		cmd_json_object_set_new(juser, cmd_jkey_user, jname);

		fs_uid = fsids->users.uids[idx].fs_uid;
		juid   = cmd_json_integer((long)fs_uid);
		cmd_json_object_set_new(juser, cmd_jkey_uid, juid);

		cmd_json_append(jusers, juser);
		cmd_pstrfree(&name);
	}
	return jusers;
}

static void
cmd_decode_jfsids_users(const json_t *jusers, struct silofs_ugids *fsids)
{
	const json_t *juser = nullptr;
	const json_t *jname = nullptr;
	const json_t *juid  = nullptr;
	const char   *name  = nullptr;
	uid_t         host_uid, fs_uid;
	size_t        size;

	size = cmd_json_array_size(jusers);
	for (size_t idx = 0; idx < size; ++idx) {
		juser    = cmd_json_array_get(jusers, idx);
		jname    = cmd_json_object_get_string(juser, cmd_jkey_user);
		name     = cmd_json_string_value(jname);
		host_uid = cmd_resolve_name_to_uid(name);

		juid   = cmd_json_object_get_integer(juser, cmd_jkey_uid);
		fs_uid = cmd_json_uint32_value(juid);

		cmd_append_uid_mapping(fsids, host_uid, fs_uid);
	}
}

static json_t *cmd_encode_jfsids_groups(const struct silofs_ugids *fsids)
{
	json_t *jgroups = nullptr;
	json_t *jgroup  = nullptr;
	json_t *jname   = nullptr;
	json_t *jgid    = nullptr;
	char   *name    = nullptr;
	gid_t   host_gid, fs_gid;

	jgroups = cmd_json_array();
	for (size_t idx = 0; idx < fsids->groups.ngids; ++idx) {
		jgroup = cmd_json_object();

		host_gid = fsids->groups.gids[idx].host_gid;
		name     = cmd_resolve_gid_to_name(host_gid);
		jname    = cmd_json_string(name);
		cmd_json_object_set_new(jgroup, cmd_jkey_group, jname);

		fs_gid = fsids->groups.gids[idx].fs_gid;
		jgid   = cmd_json_integer((long)fs_gid);
		cmd_json_object_set_new(jgroup, cmd_jkey_gid, jgid);

		cmd_json_append(jgroups, jgroup);
		cmd_pstrfree(&name);
	}
	return jgroups;
}

static void
cmd_decode_jfsids_groups(const json_t *jgroups, struct silofs_ugids *fsids)
{
	const json_t *jgroup = nullptr;
	const json_t *jname  = nullptr;
	const json_t *jgid   = nullptr;
	const char   *name   = nullptr;
	gid_t         host_gid, fs_gid;
	size_t        size;

	size = cmd_json_array_size(jgroups);
	for (size_t idx = 0; idx < size; ++idx) {
		jgroup   = cmd_json_array_get(jgroups, idx);
		jname    = cmd_json_object_get_string(jgroup, cmd_jkey_group);
		name     = cmd_json_string_value(jname);
		host_gid = cmd_resolve_name_to_gid(name);

		jgid   = cmd_json_object_get_integer(jgroup, cmd_jkey_gid);
		fs_gid = cmd_json_uint32_value(jgid);

		cmd_append_gid_mapping(fsids, host_gid, fs_gid);
	}
}

static json_t *cmd_encode_jfsids(const struct silofs_ugids *fsids)
{
	json_t *jfsids  = nullptr;
	json_t *jusers  = nullptr;
	json_t *jgroups = nullptr;

	jfsids = cmd_json_object();

	jusers = cmd_encode_jfsids_users(fsids);
	cmd_json_object_set_new(jfsids, cmd_jkey_users, jusers);

	jgroups = cmd_encode_jfsids_groups(fsids);
	cmd_json_object_set_new(jfsids, cmd_jkey_groups, jgroups);

	return jfsids;
}

static void cmd_decode_jfsids(const json_t *jfsids, struct silofs_ugids *fsids)
{
	const json_t *jusers  = nullptr;
	const json_t *jgroups = nullptr;

	jusers = cmd_json_object_get_array(jfsids, cmd_jkey_users);
	cmd_decode_jfsids_users(jusers, fsids);

	jgroups = cmd_json_object_get_array(jfsids, cmd_jkey_groups);
	cmd_decode_jfsids_groups(jgroups, fsids);
}

static char *cmd_encode_jfsids_text(const struct silofs_ugids *fsids)
{
	json_t *jfsids = nullptr;
	char   *jtxt   = nullptr;

	jfsids = cmd_encode_jfsids(fsids);
	jtxt   = cmd_json_dumps(jfsids);
	cmd_json_decref(jfsids);
	return jtxt;
}
static void
cmd_decode_jfsids_text(const char *jtxt, struct silofs_ugids *fsids)
{
	json_t *jfsids = nullptr;

	jfsids = cmd_json_loads(jtxt);
	cmd_decode_jfsids(jfsids, fsids);
	cmd_json_decref(jfsids);
}

static void
cmd_save_jfsids_at(int dfd, const char *name, const struct silofs_ugids *fsids)
{
	char *jtxt;

	jtxt = cmd_encode_jfsids_text(fsids);
	cmd_save_jtext_at(dfd, name, jtxt);
	free(jtxt);
}

void cmd_save_jfsids(const struct silofs_boot_args *boot_args,
                     const struct silofs_ugids     *fsids)
{
	int dfd = -1;

	cmd_open_repodir(boot_args, &dfd);
	cmd_save_jfsids_at(dfd, cmd_jfsids_filename, fsids);
	cmd_close_repodir(boot_args, &dfd);
}

static void
cmd_load_jfsids_at(int dfd, const char *name, struct silofs_ugids *fsids)
{
	char *jtxt;

	jtxt = cmd_load_jtext_at(dfd, name);
	cmd_decode_jfsids_text(jtxt, fsids);
	free(jtxt);
}

void cmd_load_jfsids(const struct silofs_boot_args *boot_args,
                     struct silofs_ugids           *fsids)
{
	int dfd = -1;

	cmd_open_repodir(boot_args, &dfd);
	cmd_load_jfsids_at(dfd, cmd_jfsids_filename, fsids);
	cmd_close_repodir(boot_args, &dfd);
}
