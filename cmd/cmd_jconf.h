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
#ifndef SILOFS_CMD_JCONF_H_
#define SILOFS_CMD_JCONF_H_

#include "cmd.h"
#include <time.h>
#include <limits.h>
#include <errno.h>
#include <jansson.h>

void cmd_json_decref(json_t *jobj);

json_t *cmd_json_object(void);

json_t *cmd_json_object_get(const json_t *jobj, const char *key);

json_t *cmd_json_object_get_string(const json_t *jobj, const char *key);

json_t *cmd_json_object_get_integer(const json_t *jobj, const char *key);

json_t *cmd_json_object_get_array(const json_t *jobj, const char *key);

void cmd_json_object_set_new(json_t *jobj, const char *key, json_t *val);

json_t *cmd_json_integer(long n);

json_t *cmd_json_uint32(uint32_t n);

uint64_t cmd_json_uint64_value(const json_t *jint);

uint32_t cmd_json_uint32_value(const json_t *jint);

json_t *cmd_json_time(time_t t);

json_t *cmd_json_btime(void);

json_t *cmd_json_string(const char *s);

const char *cmd_json_string_value(const json_t *jstr);

json_t *cmd_json_array(void);

size_t cmd_json_array_size(const json_t *jarr);

json_t *cmd_json_array_get(const json_t *jarr, size_t idx);

void cmd_json_array_append(json_t *jobj, json_t *jval);

json_t *cmd_json_fsmeta(const struct silofs_fsmeta *fsmeta);

void cmd_json_fsmeta_value(const json_t *jobj, struct silofs_fsmeta *fsmeta);

json_t *cmd_json_mbaddr(const struct silofs_mbaddr *mbaddr);

void cmd_json_mbaddr_value(const json_t *jstr, struct silofs_mbaddr *mbaddr);

void cmd_json_save(json_t *jobj, const char *dirpath, const char *name);

json_t *cmd_json_load(const char *dirpath, const char *name);

void cmd_json_unlink(const char *dirpath, const char *name);

#endif /* SILOFS_CMD_JCONF_H_ */
