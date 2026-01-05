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
#include "cmd_jconf.h"

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

static void cmd_jref_add_mbref(json_t *jobj, const char *mbref)
{
	json_t *jsub;

	jsub = cmd_json_string(mbref);
	cmd_json_object_set_new(jobj, cmd_jkey_mbref, jsub);
}

static json_t *cmd_fsref_jencode(const struct silofs_fsref *fsref)
{
	json_t *jobj;

	jobj = cmd_json_object();
	cmd_jref_add_version(jobj);
	cmd_jref_add_fmtrev(jobj);
	cmd_jref_add_btime(jobj);
	cmd_jref_add_mbref(jobj, fsref->mbaddr.mba);
	return jobj;
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

static void cmd_jref_get_mbref(const json_t *jobj, char *s, size_t n)
{
	json_t     *jsub;
	const char *str;
	size_t      len;

	jsub = cmd_json_object_get_string(jobj, cmd_jkey_mbref);
	str  = cmd_json_string_value(jsub);
	len  = strlen(str);
	if (!len || (len >= n)) {
		cmd_diez("json: illegal mbref: '%s'", str);
	}
	strncpy(s, str, n);
}

static void cmd_fsref_jdecode(struct silofs_fsref *fsref, json_t *jfsref)
{
	cmd_jref_get_version(jfsref);
	cmd_jref_get_fmtvers(jfsref);
	cmd_jref_get_btime(jfsref);
	cmd_jref_get_mbref(jfsref, fsref->mbaddr.mba,
	                   sizeof(fsref->mbaddr.mba));
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void
cmd_fsref_save_at(const struct silofs_fsref *fsref, int dfd, const char *name)
{
	json_t *jobj;

	jobj = cmd_fsref_jencode(fsref);
	cmd_json_save_at(jobj, dfd, name);
	cmd_json_decref(jobj);
}

void cmd_fsref_save(const struct silofs_fsref    *fsref,
                    const struct silofs_boot_ref *boot_ref)
{
	int dfd = -1;

	cmd_open_jconfdir(boot_ref, &dfd);
	cmd_fsref_save_at(fsref, dfd, boot_ref->refname);
	cmd_close_jconfdir(boot_ref, dfd);
}

static void
cmd_fsref_load_at(struct silofs_fsref *fsref, int dfd, const char *name)
{
	json_t *jfsref;

	jfsref = cmd_json_load_at(dfd, name);
	cmd_fsref_jdecode(fsref, jfsref);
	cmd_json_decref(jfsref);
}

static void cmd_fsref_load_by(struct silofs_fsref          *fsref,
                              const struct silofs_boot_ref *boot_ref)
{
	int dfd = -1;

	cmd_open_jconfdir(boot_ref, &dfd);
	cmd_fsref_load_at(fsref, dfd, boot_ref->refname);
	cmd_close_jconfdir(boot_ref, dfd);
}

void cmd_fsref_load(struct silofs_fsref          *fsref,
                    const struct silofs_boot_ref *boot_ref)
{
	cmd_fsref_load_by(fsref, boot_ref);
}

void cmd_fsref_unlink(const struct silofs_boot_ref *boot_ref)
{
	int dfd = -1;

	cmd_open_jconfdir(boot_ref, &dfd);
	silofs_sys_unlinkat(dfd, boot_ref->refname, 0);
	cmd_close_jconfdir(boot_ref, dfd);
}
