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
	char ts[80] = "";
	time_t curr_tm;
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

static json_t *cmd_json_blobid(const struct silofs_blobid *blobid)
{
	char bid[256] = "";
	int err;

	err = silofs_encode_blobid(blobid, bid, sizeof(bid) - 1);
	if (err) {
		cmd_die(err, "json: failed to encode blobid");
	}
	return cmd_json_string(bid);
}

static void cmd_json_object_set_new(json_t *jobj, const char *key, json_t *val)
{
	int err;

	err = json_object_set_new(jobj, key, val);
	if (err) {
		cmd_diez("json: failed to set new: key='%s' err=%d", key, err);
	}
}

static char *cmd_json_dumps(json_t *root)
{
	char *out;

	out = json_dumps(root, JSON_INDENT(4));
	if (out == nullptr) {
		cmd_diez("json: failed to dumps");
	}
	return out;
}

static json_t *cmd_json_loads(const char *jtxt)
{
	json_t *jobj;
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

static json_t *cmd_json_object_get_integer(const json_t *jobj, const char *key)
{
	json_t *jstr;

	jstr = cmd_json_object_get(jobj, key);
	if (!json_is_integer(jstr)) {
		cmd_diez("json: failed to parse integer: key='%s'", key);
	}
	return jstr;
}

static void cmd_json_decref(json_t *root)
{
	json_decref(root);
}

static const char cmd_jkey_silofs_version[] = "silofs_version";
static const char cmd_jkey_fmt_revision[] = "fmt_revision";
static const char cmd_jkey_meta[] = "meta";
static const char cmd_jkey_btime[] = "birth_time";
static const char cmd_jkey_mode[] = "mode";
static const char cmd_jkey_blobid[] = "blobid";

static void cmd_encode_meta_json(const struct silofs_blobid *blobid,
                                 bool is_archive, char **out_json)
{
	json_t *root = nullptr;
	json_t *meta = nullptr;
	json_t *jobj = nullptr;
	char *tms = nullptr;

	root = cmd_json_object();

	jobj = cmd_json_string(silofs_version.string);
	cmd_json_object_set_new(root, cmd_jkey_silofs_version, jobj);

	jobj = cmd_json_integer(SILOFS_FMT_REVISION);
	cmd_json_object_set_new(root, cmd_jkey_fmt_revision, jobj);

	meta = cmd_json_object();

	tms = cmd_current_time();
	jobj = cmd_json_string(tms);
	cmd_json_object_set_new(meta, cmd_jkey_btime, jobj);
	cmd_pstrfree(&tms);

	jobj = cmd_json_string(is_archive ? "archive" : "filesystem");
	cmd_json_object_set_new(meta, cmd_jkey_mode, jobj);

	jobj = cmd_json_blobid(blobid);
	cmd_json_object_set_new(meta, cmd_jkey_blobid, jobj);

	cmd_json_object_set_new(root, cmd_jkey_meta, meta);

	*out_json = cmd_json_dumps(root);
	cmd_json_decref(root);
}

static void cmd_decode_blobid(const char *str, struct silofs_blobid *out)
{
	int err;

	err = silofs_decode_blobid(out, str);
	if (err) {
		cmd_die(err, "json: illegal blobid: '%s'", str);
	}
}

static void cmd_decode_meta_mode(const char *str, bool want_archive)
{
	const int ar = !strcmp(str, "archive");
	const int fs = !strcmp(str, "filesystem");

	if (!ar && !fs) {
		cmd_diez("json: illegal subtype: '%s'", str);
	}
	if (fs && want_archive) {
		cmd_diez("json: bad subtype for filesystem: '%s'", str);
	}
	if (ar && !want_archive) {
		cmd_diez("json: bad subtype for archive: '%s'", str);
	}
}

static void cmd_decode_meta_json(const char *jtxt, bool want_archive,
                                 struct silofs_blobid *out_blobid)
{
	json_t *root = nullptr;
	json_t *meta = nullptr;
	json_t *jobj = nullptr;

	root = cmd_json_loads(jtxt);
	meta = cmd_json_object_get(root, cmd_jkey_meta);

	jobj = cmd_json_object_get_string(root, cmd_jkey_silofs_version);

	jobj = cmd_json_object_get_integer(root, cmd_jkey_fmt_revision);

	jobj = cmd_json_object_get_string(meta, cmd_jkey_btime);

	jobj = cmd_json_object_get_string(meta, cmd_jkey_mode);
	cmd_decode_meta_mode(json_string_value(jobj), want_archive);

	jobj = cmd_json_object_get_string(meta, cmd_jkey_blobid);
	cmd_decode_blobid(json_string_value(jobj), out_blobid);

	cmd_json_decref(root);
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

static void
cmd_save_metaref_as_json(int dfd, const char *name,
                         const struct silofs_blobid *blobid, bool is_archive)
{
	char *jtxt = nullptr;

	cmd_encode_meta_json(blobid, is_archive, &jtxt);
	cmd_save_jref_at(dfd, name, jtxt);
	free(jtxt);
}

void cmd_save_fs_metaref(const struct silofs_boot_args *boot_args,
                         const struct silofs_blobid *fs_blobid)
{
	int dfd = -1;

	cmd_open_repodir(boot_args, &dfd);
	cmd_save_metaref_as_json(dfd, boot_args->fs_name, fs_blobid, false);
	silofs_sys_closefd(&dfd);
}

void cmd_save_ar_metaref(const struct silofs_boot_args *boot_args,
                         const struct silofs_blobid *ar_blobid)
{
	int dfd = -1;

	cmd_open_repodir(boot_args, &dfd);
	cmd_save_metaref_as_json(dfd, boot_args->ar_name, ar_blobid, true);
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
		cmd_die(-EFBIG, "illegal blobid: %s", name);
	}
	err = silofs_sys_openat(dfd, name, O_RDONLY, 0, &fd);
	if (err) {
		cmd_die(err, "failed to open: %s", name);
	}
	jtxt = cmd_zalloc(len + 1);
	err = silofs_sys_readn(fd, jtxt, len);
	silofs_sys_closefd(&fd);
	if (err) {
		cmd_die(err, "failed to read blobid: %s", name);
	}
	return jtxt;
}

static void
cmd_load_metaref_from_json(int dfd, const char *name, bool want_archive,
                           struct silofs_blobid *out_blobid)
{
	char *jtxt = nullptr;

	jtxt = cmd_load_jref_at(dfd, name);
	cmd_decode_meta_json(jtxt, want_archive, out_blobid);
	cmd_pstrfree(&jtxt);
}

static void
cmd_load_metaref_of(const struct silofs_boot_args *boot_args,
                    bool want_archive, struct silofs_blobid *out_blobid)
{
	const char *name;
	int dfd = -1;

	name = want_archive ? boot_args->ar_name : boot_args->fs_name;
	cmd_open_repodir(boot_args, &dfd);
	cmd_load_metaref_from_json(dfd, name, want_archive, out_blobid);
	silofs_sys_closefd(&dfd);
}

void cmd_load_fs_metaref(const struct silofs_boot_args *boot_args,
                         struct silofs_blobid *out_blobid)
{
	cmd_load_metaref_of(boot_args, false, out_blobid);
}

void cmd_load_ar_metaref(struct silofs_boot_args *boot_args,
                         struct silofs_blobid *out_blobid)
{
	cmd_load_metaref_of(boot_args, true, out_blobid);
}

void cmd_unlink_fs_metaref(const struct silofs_boot_args *boot_args)
{
	int dfd = -1;

	cmd_open_repodir(boot_args, &dfd);
	silofs_sys_unlinkat(dfd, boot_args->fs_name, 0);
	silofs_sys_closefd(&dfd);
}
