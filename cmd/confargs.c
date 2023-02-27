/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#include <uuid/uuid.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include "cmd.h"

#define SEC_IGNORE      (0x00)
#define SEC_FS          (0x01)
#define SEC_USERS       (0x02)
#define SEC_GROUPS      (0x04)


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void substr_init(struct silofs_substr *ss, const char *s)
{
	silofs_substr_init(ss, s);
}

static void substr_initn(struct silofs_substr *ss, const char *s, size_t n)
{
	silofs_substr_init_rd(ss, s, n);
}

static bool substr_isempty(const struct silofs_substr *ss)
{
	return silofs_substr_isempty(ss);
}

static void substr_split_by(const struct silofs_substr *ss, char sep,
                            struct silofs_substr_pair *out_ss_pair)
{
	silofs_substr_split_chr(ss, sep, out_ss_pair);
}

static void substr_split_by_nl(const struct silofs_substr *ss,
                               struct silofs_substr_pair *out_ss_pair)
{
	substr_split_by(ss, '\n', out_ss_pair);
}

static void substr_strip_ws(const struct silofs_substr *ss,
                            struct silofs_substr *out_ss)
{
	silofs_substr_strip_ws(ss, out_ss);
}

static void substr_strip_any(const struct silofs_substr *ss, const char *set,
                             struct silofs_substr *out_ss)
{
	silofs_substr_strip_any_of(ss, set, out_ss);
}

static void substr_copyto(const struct silofs_substr *ss, char *s, size_t n)
{
	silofs_substr_copyto(ss, s, n);
}

static bool substr_isascii(const struct silofs_substr *ss)
{
	return silofs_substr_isascii(ss);
}

static bool substr_isequal(const struct silofs_substr *ss, const char *s)
{
	return silofs_substr_isequal(ss, s);
}

static bool substr_starts_with(const struct silofs_substr *ss, char c)
{
	return silofs_substr_starts_with(ss, c);
}

static bool substr_ends_with(const struct silofs_substr *ss, char c)
{
	return silofs_substr_ends_with(ss, c);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

__attribute__((__noreturn__))
static void cmd_die_by(const struct silofs_substr *ss, const char *prefix)
{
	if (ss != NULL) {
		cmd_dief(errno, "%s: '%.*s'", prefix, ss->len, ss->str);
	} else {
		cmd_dief(errno, "%s", prefix);
	}
	silofs_unreachable();
}

static void
cmd_parse_uid_by_value(const struct silofs_substr *ss, uid_t *out_uid)
{
	char str[64] = "";

	if (ss->len >= sizeof(str)) {
		cmd_die_by(ss, "not an integer");
	}
	substr_copyto(ss, str, sizeof(str));
	*out_uid = cmd_parse_str_as_uid(str);
}

static void
cmd_parse_gid_by_value(const struct silofs_substr *ss, gid_t *out_gid)
{
	char str[64] = "";

	if (ss->len >= sizeof(str)) {
		cmd_die_by(ss, "not an integer");
	}
	substr_copyto(ss, str, sizeof(str));
	*out_gid = cmd_parse_str_as_gid(str);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t cmd_sysconf(int key)
{
	long ret;

	ret = sysconf(key);
	if (ret < 0) {
		cmd_dief(errno, "sysconf error: key=%d", key);
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

static void cmd_resolve_uid_by_name(const char *name, uid_t *out_uid)
{
	struct passwd pwd;
	struct passwd *pw = NULL;
	char *buf = NULL;
	size_t bsz;
	int err;

	bsz = cmd_getxx_bsz();
	buf = cmd_zalloc(bsz);
	err = getpwnam_r(name, &pwd, buf, bsz, &pw);
	if (err) {
		cmd_dief(err, "unknown user name: %s", name);
	}
	*out_uid = pw->pw_uid;
	cmd_zfree(buf, bsz);
}

static void cmd_resolve_gid_by_name(const char *name, gid_t *out_gid)
{
	struct group grp;
	struct group *gr = NULL;
	char *buf = NULL;
	size_t bsz;
	int err;

	bsz = cmd_getxx_bsz();
	buf = cmd_zalloc(bsz);
	err = getgrnam_r(name, &grp, buf, bsz, &gr);
	if (err) {
		cmd_dief(err, "unknown group name: %s", name);
	}
	*out_gid = gr->gr_gid;
	cmd_zfree(buf, bsz);
}

static void cmd_resolve_uid_to_name(uid_t uid, char *name, size_t nsz)
{
	struct passwd pwd;
	struct passwd *pw = NULL;
	char *buf = NULL;
	size_t bsz;
	int err;

	bsz = cmd_getxx_bsz();
	buf = cmd_zalloc(bsz);
	err = getpwuid_r(uid, &pwd, buf, bsz, &pw);
	if (err) {
		cmd_dief(err, "unknown uid: %u", uid);
	}
	if (strlen(pw->pw_name) >= nsz) {
		cmd_dief(-ENAMETOOLONG, "bad user name: %s", pw->pw_name);
	}
	strncpy(name, pw->pw_name, nsz);
	cmd_zfree(buf, bsz);
}

static void cmd_resolve_gid_to_name(gid_t gid, char *name, size_t nsz)
{
	struct group grp;
	struct group *gr = NULL;
	char *buf = NULL;
	size_t bsz;
	int err;

	bsz = cmd_getxx_bsz();
	buf = cmd_zalloc(bsz);
	err = getgrgid_r(gid, &grp, buf, bsz, &gr);
	if (err) {
		cmd_dief(err, "unknown gid: %u", gid);
	}
	if (strlen(gr->gr_name) >= nsz) {
		cmd_dief(-ENAMETOOLONG, "bad group name: %s", gr->gr_name);
	}
	strncpy(name, gr->gr_name, nsz);
	cmd_zfree(buf, bsz);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_do_free_ids(struct silofs_id *ids, size_t nids)
{
	cmd_zfree(ids, nids * sizeof(ids[0]));
}

static void cmd_pfree_ids(struct silofs_id **ids, size_t *nids)
{
	if (*ids && *nids) {
		cmd_do_free_ids(*ids, *nids);
		*ids = NULL;
		*nids = 0;
	}
}

static void cmd_extend_ids(struct silofs_id **pids, size_t *pnids, size_t cnt)
{
	struct silofs_id *ids = NULL;
	size_t nids = *pnids + cnt;

	ids = cmd_zalloc(nids * sizeof(ids[0]));
	if (*pids && *pnids) {
		memcpy(ids, *pids, *pnids * sizeof(ids[0]));
		cmd_pfree_ids(pids, pnids);
	}
	*pids = ids;
	*pnids = nids;
}

static void cmd_append_id1(struct silofs_id **pids, size_t *pnids,
                           const struct silofs_id *id)
{
	struct silofs_id *dst;

	cmd_extend_ids(pids, pnids, 1);
	dst = &(*pids)[*pnids - 1];
	memcpy(dst, id, sizeof(*dst));
}

static void cmd_dup_ids(const struct silofs_id *ids, size_t nids,
                        struct silofs_id **out_ids, size_t *out_nids)
{
	const size_t id_size = sizeof(*ids);

	*out_ids = NULL;
	*out_nids = 0;
	if (ids && nids) {
		*out_ids = cmd_zalloc(nids * id_size);
		memcpy(*out_ids, ids, nids * id_size);
		*out_nids = nids;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
cmd_parse_uid_by_name(const struct silofs_substr *name, uid_t *out_uid)
{
	char buf[NAME_MAX + 1] = "";

	if (name->len >= sizeof(buf)) {
		cmd_die_by(name, "illegal user name");
	}
	substr_copyto(name, buf, sizeof(buf) - 1);
	cmd_resolve_uid_by_name(buf, out_uid);
}

static void
cmd_parse_gid_by_name(const struct silofs_substr *name, gid_t *out_gid)
{
	char buf[NAME_MAX + 1] = "";

	if (name->len >= sizeof(buf)) {
		cmd_die_by(name, "illegal group name");
	}
	substr_copyto(name, buf, sizeof(buf) - 1);
	cmd_resolve_gid_by_name(buf, out_gid);
}

static void cmd_parse_user(const struct silofs_substr *name,
                           const struct silofs_substr *suid,
                           struct silofs_id *out_id)
{
	cmd_parse_uid_by_name(name, &out_id->id.u.uid);
	cmd_parse_uid_by_value(suid, &out_id->id.u.suid);
	out_id->id_type = SILOFS_IDTYPE_UID;
}

static void cmd_parse_group(const struct silofs_substr *name,
                            const struct silofs_substr *sgid,
                            struct silofs_id *out_id)
{
	cmd_parse_gid_by_name(name, &out_id->id.g.gid);
	cmd_parse_gid_by_value(sgid, &out_id->id.g.sgid);
	out_id->id_type = SILOFS_IDTYPE_GID;
}

static void cmd_parse_id(const struct silofs_substr *name,
                         const struct silofs_substr *xxid,
                         enum silofs_idtype id_type,
                         struct silofs_id *out_id)
{
	if (id_type == SILOFS_IDTYPE_UID) {
		cmd_parse_user(name, xxid, out_id);
	} else if (id_type == SILOFS_IDTYPE_GID) {
		cmd_parse_group(name, xxid, out_id);
	}
}

static void cmd_parse_id_data(const struct silofs_substr *line,
                              enum silofs_idtype id_type,
                              struct silofs_id **ids, size_t *nids)
{
	struct silofs_substr_pair ssp;
	struct silofs_substr name;
	struct silofs_substr xxid;
	struct silofs_id id = { .id_type = SILOFS_IDTYPE_NONE };

	substr_split_by(line, '=', &ssp);
	substr_strip_ws(&ssp.first, &name);
	substr_strip_ws(&ssp.second, &xxid);

	if (substr_isempty(&name) || substr_isempty(&xxid)) {
		cmd_die_by(line, "missing id mapping");
	}
	cmd_parse_id(&name, &xxid, id_type, &id);
	cmd_append_id1(ids, nids, &id);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_append_conf_line(char **conf, const char *line)
{
	const size_t line_len = strlen(line);
	const size_t conf_len = *conf ? strlen(*conf) : 0;
	char *conf_next = NULL;

	conf_next = cmd_zalloc(conf_len + line_len + 1);
	if (*conf != NULL) {
		memcpy(conf_next, *conf, conf_len);
		cmd_pstrfree(conf);
	}
	memcpy(conf_next + conf_len, line, line_len);
	*conf = conf_next;
}

static void cmd_append_newline(char **conf)
{
	cmd_append_conf_line(conf, "\n");
}

static void cmd_append_section(const char *name, char **conf)
{
	char line[256] = "";

	snprintf(line, sizeof(line) - 1, "[%s]\n", name);
	cmd_append_conf_line(conf, line);
}

static void cmd_append_uuid_conf(const struct silofs_uuid *uuid, char **conf)
{
	char line[256] = "";
	char ustr[64] = "";
	uuid_t uu;

	SILOFS_STATICASSERT_EQ(sizeof(uu), sizeof(uuid->uu));

	memcpy(uu, uuid->uu, sizeof(uu));
	uuid_unparse(uu, ustr);
	snprintf(line, sizeof(line) - 1, "uuid = %s\n", ustr);
	cmd_append_conf_line(conf, line);
}

static void cmd_append_id_conf(const char *name, uint32_t id, char **conf)
{
	char line[512] = "";

	snprintf(line, sizeof(line) - 1, "%s = %u\n", name, id);
	cmd_append_conf_line(conf, line);
}

static void cmd_append_user_conf(const struct silofs_id *id, char **conf)
{
	char name[NAME_MAX + 1] = "";

	cmd_resolve_uid_to_name(id->id.u.uid, name, sizeof(name));
	cmd_append_id_conf(name, id->id.u.suid, conf);
}

static void cmd_append_group_conf(const struct silofs_id *id, char **conf)
{
	char name[NAME_MAX + 1] = "";

	cmd_resolve_gid_to_name(id->id.g.gid, name, sizeof(name));
	cmd_append_id_conf(name, id->id.g.sgid, conf);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool cmd_isascii_conf(const char *conf, size_t size)
{
	struct silofs_substr ss;

	substr_initn(&ss, conf, size);
	return substr_isascii(&ss);
}

static void cmd_read_conf(const char *path, char **out_conf)
{
	struct stat st;
	size_t size;
	char *conf = NULL;
	int fd = -1;
	int err;

	err = silofs_sys_stat(path, &st);
	if (err) {
		silofs_die(err, "stat failure: %s", path);
	}
	if (!S_ISREG(st.st_mode)) {
		silofs_die(0, "not a regular file: %s", path);
	}
	if (st.st_size >= SILOFS_MEGA) {
		silofs_die(-EFBIG, "illegal config file: %s", path);
	}
	err = silofs_sys_open(path, O_RDONLY, 0, &fd);
	if (err) {
		silofs_die(err, "can not open config file: %s", path);
	}
	size = (size_t)st.st_size;
	conf = cmd_zalloc(size + 1);
	err = silofs_sys_readn(fd, conf, size);
	if (err) {
		silofs_die(err, "failed to read config file %s", path);
	}
	silofs_sys_close(fd);

	if (!cmd_isascii_conf(conf, size)) {
		silofs_die(0, "non-ascii character in: %s", path);
	}
	*out_conf = conf;
}

static void cmd_write_conf(const char *path, const char *conf)
{
	const size_t len = conf ? strlen(conf) : 0;
	const mode_t mode = S_IRUSR | S_IWUSR;
	int fd = -1;
	int err;

	silofs_sys_chmod(path, mode);
	err = silofs_sys_open(path, O_CREAT | O_RDWR | O_TRUNC, mode, &fd);
	if (err) {
		silofs_die(err, "failed to create: %s", path);
	}
	err = silofs_sys_writen(fd, conf, len);
	if (err) {
		silofs_die(err, "failed to write: %s", path);
	}
	silofs_sys_closefd(&fd);
}
