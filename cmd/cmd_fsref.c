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

static const char cmd_jkey_gmeta[]  = "silofs-meta";
static const char cmd_jkey_mbaddr[] = "mbaddr";

static json_t *cmd_fsref_jencode(const struct silofs_fsref *fsref)
{
	json_t *jobj;
	json_t *jsub;

	jobj = cmd_json_object();

	jsub = cmd_json_gmeta(&fsref->gmeta);
	cmd_json_object_set_new(jobj, cmd_jkey_gmeta, jsub);

	jsub = cmd_json_mbaddr(&fsref->mbaddr);
	cmd_json_object_set_new(jobj, cmd_jkey_mbaddr, jsub);

	return jobj;
}

static void cmd_fsref_jdecode(struct silofs_fsref *fsref, const json_t *jobj)
{
	json_t *jsub;

	jsub = cmd_json_object_get(jobj, cmd_jkey_gmeta);
	cmd_json_gmeta_value(jsub, &fsref->gmeta);

	jsub = cmd_json_object_get(jobj, cmd_jkey_mbaddr);
	cmd_json_mbaddr_value(jsub, &fsref->mbaddr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_fsref_save(const struct silofs_fsref   *fsref,
                    const struct silofs_baseref *boot_ref)
{
	json_t *jfsref;

	jfsref = cmd_fsref_jencode(fsref);
	cmd_json_save(jfsref, boot_ref->repodir, boot_ref->refname);
	cmd_json_decref(jfsref);
}

void cmd_fsref_load(struct silofs_fsref         *fsref,
                    const struct silofs_baseref *boot_ref)
{
	json_t *jfsref;

	jfsref = cmd_json_load(boot_ref->repodir, boot_ref->refname);
	cmd_fsref_jdecode(fsref, jfsref);
	cmd_json_decref(jfsref);
}

void cmd_fsref_unlink(const struct silofs_baseref *boot_ref)
{
	cmd_json_unlink(boot_ref->repodir, boot_ref->refname);
}
