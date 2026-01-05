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

#include "cmd_jconf.h"

static char *cmd_localtime_str(time_t t)
{
	char      ts[80] = "";
	struct tm tm;

	if (localtime_r(&t, &tm) == nullptr) {
		cmd_diez("json: failed get local time");
	}
	if (strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm) == 0) {
		cmd_diez("json: failed format time");
	}
	return cmd_strdup(ts);
}

json_t *cmd_json_object(void)
{
	json_t *jobj;

	jobj = json_object();
	if (jobj == nullptr) {
		cmd_diez("json: failed to create object");
	}
	return jobj;
}

json_t *cmd_json_string(const char *s)
{
	json_t *jstr;

	jstr = json_string(s);
	if (jstr == nullptr) {
		cmd_diez("json: failed to create string: '%s'", s);
	}
	return jstr;
}

json_t *cmd_json_integer(long n)
{
	json_t *jint;

	jint = json_integer(n);
	if (jint == nullptr) {
		cmd_diez("json: failed to create integer: %ld", n);
	}
	return jint;
}

json_t *cmd_json_uint32(uint32_t n)
{
	return cmd_json_integer((long)n);
}

json_t *cmd_json_array(void)
{
	json_t *jarr;

	jarr = json_array();
	if (jarr == nullptr) {
		cmd_diez("json: failed to create array");
	}
	return jarr;
}

size_t cmd_json_array_size(const json_t *jarr)
{
	if (!json_is_array(jarr)) {
		cmd_diez("json: not an array");
	}
	return json_array_size(jarr);
}

json_t *cmd_json_array_get(const json_t *jarr, size_t idx)
{
	json_t *jsub;

	jsub = json_array_get(jarr, idx);
	if (jsub == nullptr) {
		cmd_diez("json: bad array index: %zu", idx);
	}
	return jsub;
}

json_t *cmd_json_time(time_t t)
{
	char   *tstr;
	json_t *jstr;

	tstr = cmd_localtime_str(t);
	jstr = cmd_json_string(tstr);
	cmd_pstrfree(&tstr);
	return jstr;
}

json_t *cmd_json_btime(void)
{
	return cmd_json_time(time(nullptr));
}

void cmd_json_object_set_new(json_t *jobj, const char *key, json_t *val)
{
	int err;

	err = json_object_set_new(jobj, key, val);
	if (err) {
		cmd_diez("json: failed to set new: key='%s' err=%d", key, err);
	}
}

void cmd_json_array_append(json_t *jobj, json_t *jval)
{
	int err;

	err = json_array_append(jobj, jval);
	if (err) {
		cmd_diez("json: failed to grow array: err=%d", err);
	}
}

static char *cmd_json_dumps(json_t *jobj)
{
	char *out;

	out = json_dumps(jobj, JSON_INDENT(2));
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

json_t *cmd_json_object_get(const json_t *jobj, const char *key)
{
	json_t *jsub;

	jsub = json_object_get(jobj, key);
	if (jsub == nullptr) {
		cmd_diez("json: failed to parse: key='%s'", key);
	}
	return jsub;
}

json_t *cmd_json_object_get_string(const json_t *jobj, const char *key)
{
	json_t *jstr;

	jstr = cmd_json_object_get(jobj, key);
	if (!json_is_string(jstr)) {
		cmd_diez("json: failed to parse string: key='%s'", key);
	}
	return jstr;
}

const char *cmd_json_string_value(const json_t *jstr)
{
	const char *val;

	val = json_string_value(jstr);
	if (val == nullptr) {
		cmd_diez("json: bad string value");
	}
	return val;
}

json_t *cmd_json_object_get_integer(const json_t *jobj, const char *key)
{
	json_t *jint;

	jint = cmd_json_object_get(jobj, key);
	if (!json_is_integer(jint)) {
		cmd_diez("json: failed to parse integer: key='%s'", key);
	}
	return jint;
}

uint64_t cmd_json_uint64_value(const json_t *jint)
{
	json_int_t val;

	val = json_integer_value(jint);
	if (val < 0) {
		cmd_diez("json: bad unsigned-integer value: %lld", val);
	}
	return (uint64_t)val;
}

uint32_t cmd_json_uint32_value(const json_t *jint)
{
	uint64_t u;

	u = cmd_json_uint64_value(jint);
	if (u > UINT32_MAX) {
		cmd_diez("json: bad uint32 value: %zu", u);
	}
	return (uint32_t)u;
}

json_t *cmd_json_object_get_array(const json_t *jobj, const char *key)
{
	json_t *jstr;

	jstr = cmd_json_object_get(jobj, key);
	if (!json_is_array(jstr)) {
		cmd_diez("json: failed to parse array: key='%s'", key);
	}
	return jstr;
}

void cmd_json_decref(json_t *jobj)
{
	json_decref(jobj);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const char cmd_jkey_version[] = "version";
static const char cmd_jkey_fmtvers[] = "fmtvers";
static const char cmd_jkey_btime[]   = "btime";

json_t *cmd_json_fsmeta(const struct silofs_fsmeta *fsmeta)
{
	json_t *jobj = nullptr;
	json_t *jsub = nullptr;

	jobj = cmd_json_object();

	jsub = cmd_json_string(fsmeta->version);
	cmd_json_object_set_new(jobj, cmd_jkey_version, jsub);

	jsub = cmd_json_integer(fsmeta->fmtvers);
	cmd_json_object_set_new(jobj, cmd_jkey_fmtvers, jsub);

	jsub = cmd_json_time((time_t)(fsmeta->btime));
	cmd_json_object_set_new(jobj, cmd_jkey_btime, jsub);

	return jobj;
}

void cmd_json_fsmeta_value(const json_t *jobj, struct silofs_fsmeta *fsmeta)
{
	const json_t *jsub = nullptr;
	const char   *str  = nullptr;
	size_t        len;

	memset(fsmeta, 0, sizeof(*fsmeta));

	jsub = cmd_json_object_get_string(jobj, cmd_jkey_version);
	str  = cmd_json_string_value(jsub);
	len  = strlen(str);
	if (len >= sizeof(fsmeta->version)) {
		cmd_diez("illegal fsmeta version: %s", str);
	}
	strncpy(fsmeta->version, str, sizeof(fsmeta->version));

	jsub            = cmd_json_object_get_integer(jobj, cmd_jkey_fmtvers);
	fsmeta->fmtvers = cmd_json_uint32_value(jsub);

	jsub          = cmd_json_object_get_string(jobj, cmd_jkey_btime);
	fsmeta->btime = 0; /* TODO: unparse btime */
	(void)jsub;
}

json_t *cmd_json_mbaddr(const struct silofs_mbaddr *mbaddr)
{
	return cmd_json_string(mbaddr->mba);
}

void cmd_json_mbaddr_value(const json_t *jstr, struct silofs_mbaddr *mbaddr)
{
	const char *str;
	size_t      len;

	memset(mbaddr, 0, sizeof(*mbaddr));

	str = cmd_json_string_value(jstr);
	len = strlen(str);
	if (!len || (len >= sizeof(mbaddr->mba))) {
		cmd_diez("json: illegal mbaddr: '%s'", str);
	}
	strncpy(mbaddr->mba, str, sizeof(mbaddr->mba));
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_open_jconfdir(const char *path, int *out_dfd)
{
	int err;

	err = silofs_sys_opendir(path, out_dfd);
	if (err) {
		cmd_die(err, "failed to open dir: %s", path);
	}
}

static void cmd_close_jconfdir(const char *path, int dfd)
{
	int err;

	err = silofs_sys_close(dfd);
	if (err) {
		cmd_die(err, "failed to close dir: %s", path);
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

static void cmd_json_save_at(json_t *jobj, int dfd, const char *name)
{
	char *jtxt;

	jtxt = cmd_json_dumps(jobj);
	cmd_save_jtext_at(dfd, name, jtxt);
	free(jtxt);
}

void cmd_json_save(json_t *jobj, const char *dirpath, const char *name)
{
	int dfd = -1;

	cmd_open_jconfdir(dirpath, &dfd);
	cmd_json_save_at(jobj, dfd, name);
	cmd_close_jconfdir(dirpath, dfd);
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

static json_t *cmd_json_load_at(int dfd, const char *name)
{
	json_t *jobj;
	char   *jtxt;

	jtxt = cmd_load_jtext_at(dfd, name);
	jobj = cmd_json_loads(jtxt);
	cmd_pstrfree(&jtxt);

	return jobj;
}

json_t *cmd_json_load(const char *dirpath, const char *name)
{
	json_t *jobj = nullptr;
	int     dfd  = -1;

	cmd_open_jconfdir(dirpath, &dfd);
	jobj = cmd_json_load_at(dfd, name);
	cmd_close_jconfdir(dirpath, dfd);

	return jobj;
}

void cmd_json_unlink(const char *dirpath, const char *name)
{
	int dfd = -1;

	cmd_open_jconfdir(dirpath, &dfd);
	silofs_sys_unlinkat(dfd, name, 0);
	cmd_close_jconfdir(dirpath, dfd);
}
