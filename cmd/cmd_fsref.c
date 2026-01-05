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

static const char cmd_jkey_fsmeta[] = "fsmeta";
static const char cmd_jkey_mbaddr[] = "mbaddr";

static json_t *cmd_fsref_jencode(const struct silofs_fsref *fsref)
{
	json_t *jobj;
	json_t *jsub;

	jobj = cmd_json_object();

	jsub = cmd_json_fsmeta(&fsref->fsmeta);
	cmd_json_object_set_new(jobj, cmd_jkey_fsmeta, jsub);

	jsub = cmd_json_mbaddr(&fsref->mbaddr);
	cmd_json_object_set_new(jobj, cmd_jkey_mbaddr, jsub);

	return jobj;
}

static void cmd_fsref_jdecode(struct silofs_fsref *fsref, const json_t *jobj)
{
	json_t *jsub;

	jsub = cmd_json_object_get(jobj, cmd_jkey_fsmeta);
	cmd_json_fsmeta_value(jsub, &fsref->fsmeta);

	jsub = cmd_json_object_get(jobj, cmd_jkey_mbaddr);
	cmd_json_mbaddr_value(jsub, &fsref->mbaddr);
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
