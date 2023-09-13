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
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include "cmd.h"

#define CONF_SEC_IGNORE      (0x00)
#define CONF_SEC_FS          (0x01)
#define CONF_SEC_USERS       (0x02)
#define CONF_SEC_GROUPS      (0x04)


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
	struct passwd pwd = { .pw_uid = (uid_t)(-1) };
	struct passwd *pw = NULL;
	char *buf = NULL;
	size_t bsz;
	int err;

	bsz = cmd_getxx_bsz();
	buf = cmd_zalloc(bsz);
	err = getpwnam_r(name, &pwd, buf, bsz, &pw);
	if (err) {
		cmd_dief(err, "failed to resolve user name: %s", name);
	}
	if (pw == NULL) {
		cmd_dief(0, "unknown user name: %s", name);
	}
	*out_uid = pw->pw_uid;
	cmd_zfree(buf, bsz);
}

static void cmd_resolve_gid_by_name(const char *name, gid_t *out_gid)
{
	struct group grp = { .gr_gid = (gid_t)(-1) };
	struct group *gr = NULL;
	char *buf = NULL;
	size_t bsz;
	int err;

	bsz = cmd_getxx_bsz();
	buf = cmd_zalloc(bsz);
	err = getgrnam_r(name, &grp, buf, bsz, &gr);
	if (err) {
		cmd_dief(err, "failed to resolve group name: %s", name);
	}
	if (gr == NULL) {
		cmd_dief(0, "unknown group name: %s", name);
	}
	*out_gid = gr->gr_gid;
	cmd_zfree(buf, bsz);
}

static void cmd_resolve_uid_to_name(uid_t uid, char *name, size_t nsz)
{
	struct passwd pwd = { .pw_uid = (uid_t)(-1) };
	struct passwd *pw = NULL;
	char *buf = NULL;
	size_t bsz;
	size_t len;
	int err;

	bsz = cmd_getxx_bsz();
	buf = cmd_zalloc(bsz);
	err = getpwuid_r(uid, &pwd, buf, bsz, &pw);
	if (err) {
		cmd_dief(err, "failed to resolve uid: %u", uid);
	}
	if ((pw == NULL) || (pw->pw_name == NULL)) {
		cmd_dief(0, "unknown uid: %u", uid);
	}
	len = strlen(pw->pw_name);
	if (!len || (len >= nsz)) {
		cmd_dief(-ENAMETOOLONG, "bad user name: %s", pw->pw_name);
	}
	strncpy(name, pw->pw_name, nsz);
	cmd_zfree(buf, bsz);
}

static void cmd_resolve_gid_to_name(gid_t gid, char *name, size_t nsz)
{
	struct group grp = { .gr_gid = (gid_t)(-1) };
	struct group *gr = NULL;
	char *buf = NULL;
	size_t bsz;
	size_t len;
	int err;

	bsz = cmd_getxx_bsz();
	buf = cmd_zalloc(bsz);
	err = getgrgid_r(gid, &grp, buf, bsz, &gr);
	if (err) {
		cmd_dief(err, "failed to resolve gid: %u", gid);
	}
	if ((gr == NULL) || (gr->gr_name == NULL)) {
		cmd_dief(0, "unknown gid: %u", gid);
	}
	len = strlen(gr->gr_name);
	if (!len || (len >= nsz)) {
		cmd_dief(-ENAMETOOLONG, "bad group name: %s", gr->gr_name);
	}
	strncpy(name, gr->gr_name, nsz);
	cmd_zfree(buf, bsz);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_uids *cmd_malloc_uids(size_t nuids)
{
	struct silofs_uids *uids;

	uids = cmd_zalloc(nuids * sizeof(uids[0]));
	return uids;
}

static void cmd_free_uids(struct silofs_uids *uids, size_t nuids)
{
	cmd_zfree(uids, nuids * sizeof(uids[0]));
}

static void cmd_pfree_uids(struct silofs_uids **puids, size_t *pnuids)
{
	if (*puids && *pnuids) {
		cmd_free_uids(*puids, *pnuids);
		*puids = NULL;
		*pnuids = 0;
	}
}

static void cmd_copy_uids(struct silofs_uids *uids_dst,
                          const struct silofs_uids *uids_src, size_t nuids)
{
	if (uids_src && nuids) {
		memcpy(uids_dst, uids_src, nuids * sizeof(uids_dst[0]));
	}
}

static void
cmd_extend_uids(struct silofs_uids **puids, size_t *pnuids, size_t cnt)
{
	struct silofs_uids *uids = NULL;
	size_t nuids = *pnuids + cnt;

	uids = cmd_malloc_uids(nuids);
	cmd_copy_uids(uids, *puids, *pnuids);
	cmd_pfree_uids(puids, pnuids);
	*puids = uids;
	*pnuids = nuids;
}

static void cmd_append_uids1(struct silofs_uids **puids, size_t *pnuids,
                             const struct silofs_uids *uids)
{
	cmd_extend_uids(puids, pnuids, 1);
	cmd_copy_uids(&(*puids)[*pnuids - 1], uids, 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_gids *cmd_malloc_gids(size_t ngids)
{
	struct silofs_gids *gids;

	gids = cmd_zalloc(ngids * sizeof(gids[0]));
	return gids;
}

static void cmd_free_gids(struct silofs_gids *gids, size_t ngids)
{
	cmd_zfree(gids, ngids * sizeof(gids[0]));
}

static void cmd_pfree_gids(struct silofs_gids **pgids, size_t *pngids)
{
	if (*pgids && *pngids) {
		cmd_free_gids(*pgids, *pngids);
		*pgids = NULL;
		*pngids = 0;
	}
}

static void cmd_copy_gids(struct silofs_gids *gids_dst,
                          const struct silofs_gids *gids_src, size_t ngids)
{
	if (gids_src && ngids) {
		memcpy(gids_dst, gids_src, ngids * sizeof(gids_dst[0]));
	}
}

static void
cmd_extend_gids(struct silofs_gids **pgids, size_t *pngids, size_t cnt)
{
	struct silofs_gids *gids = NULL;
	size_t ngids = *pngids + cnt;

	gids = cmd_malloc_gids(ngids);
	cmd_copy_gids(gids, *pgids, *pngids);
	cmd_pfree_gids(pgids, pngids);
	*pgids = gids;
	*pngids = ngids;
}

static void cmd_append_gids1(struct silofs_gids **pgids, size_t *pngids,
                             const struct silofs_gids *gids)
{
	cmd_extend_gids(pgids, pngids, 1);
	cmd_copy_gids(&(*pgids)[*pngids - 1], gids, 1);
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

static void cmd_parse_uids(const struct silofs_substr *name,
                           const struct silofs_substr *suid,
                           struct silofs_uids *out_uids)
{
	cmd_parse_uid_by_name(name, &out_uids->fs_uid);
	cmd_parse_uid_by_value(suid, &out_uids->host_uid);
}

static void cmd_parse_gids(const struct silofs_substr *name,
                           const struct silofs_substr *sgid,
                           struct silofs_gids *out_gids)
{
	cmd_parse_gid_by_name(name, &out_gids->host_gid);
	cmd_parse_gid_by_value(sgid, &out_gids->fs_gid);
}

static void cmd_parse_uid_cfg(const struct silofs_substr *line,
                              struct silofs_uids **uids, size_t *nuids)
{
	struct silofs_substr_pair ssp;
	struct silofs_substr name;
	struct silofs_substr suid;
	struct silofs_uids uid;

	substr_split_by(line, '=', &ssp);
	substr_strip_ws(&ssp.first, &name);
	substr_strip_ws(&ssp.second, &suid);

	if (substr_isempty(&name) || substr_isempty(&suid)) {
		cmd_die_by(line, "missing user mapping");
	}
	cmd_parse_uids(&name, &suid, &uid);
	cmd_append_uids1(uids, nuids, &uid);
}

static void cmd_parse_gid_cfg(const struct silofs_substr *line,
                              struct silofs_gids **gids, size_t *ngids)
{
	struct silofs_substr_pair ssp;
	struct silofs_substr name;
	struct silofs_substr sgid;
	struct silofs_gids gid;

	substr_split_by(line, '=', &ssp);
	substr_strip_ws(&ssp.first, &name);
	substr_strip_ws(&ssp.second, &sgid);

	if (substr_isempty(&name) || substr_isempty(&sgid)) {
		cmd_die_by(line, "missing group mapping");
	}
	cmd_parse_gids(&name, &sgid, &gid);
	cmd_append_gids1(gids, ngids, &gid);
}

static void cmd_parse_uuid_cfg(const struct silofs_substr *line,
                               struct silofs_uuid *uuid)
{
	char ustr[40] = "";
	struct silofs_substr_pair ssp;
	struct silofs_substr name;
	struct silofs_substr suuid;
	uuid_t uu;
	int err;

	SILOFS_STATICASSERT_EQ(sizeof(uu), sizeof(uuid->uu));

	substr_split_by(line, '=', &ssp);
	substr_strip_ws(&ssp.first, &name);
	substr_strip_ws(&ssp.second, &suuid);

	if (substr_isempty(&name) || substr_isempty(&suuid)) {
		cmd_die_by(line, "missing uuid mapping");
	}
	if (!substr_isequal(&name, "uuid")) {
		cmd_die_by(line, "illegal uuid mapping");
	}

	substr_copyto(&suuid, ustr, sizeof(ustr));
	err = uuid_parse(ustr, uu);
	if (err) {
		cmd_die_by(line, "illegal uuid value");
	}
	memcpy(&uuid->uu, uu, sizeof(uuid->uu));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_append_cfgline(char **pcfg_curr, const char *line)
{
	const size_t line_len = strlen(line);
	const size_t conf_len = *pcfg_curr ? strlen(*pcfg_curr) : 0;
	char *pcfg_next = NULL;

	pcfg_next = cmd_zalloc(conf_len + line_len + 1);
	if (*pcfg_curr != NULL) {
		memcpy(pcfg_next, *pcfg_curr, conf_len);
		cmd_pstrfree(pcfg_curr);
	}
	memcpy(pcfg_next + conf_len, line, line_len);
	*pcfg_curr = pcfg_next;
}

static void cmd_append_newline(char **pcfg)
{
	cmd_append_cfgline(pcfg, "\n");
}

static void cmd_append_section(const char *name, char **pcfg)
{
	char line[256] = "";

	snprintf(line, sizeof(line) - 1, "[%s]\n", name);
	cmd_append_cfgline(pcfg, line);
}

static void cmd_append_uuid(const char *name,
                            const struct silofs_uuid *uuid, char **conf)
{
	char line[512] = "";
	char ustr[40] = "";
	uuid_t uu;

	SILOFS_STATICASSERT_EQ(sizeof(uu), sizeof(uuid->uu));

	memcpy(uu, uuid->uu, sizeof(uu));
	uuid_unparse(uu, ustr);
	ustr[36] = '\n';
	snprintf(line, sizeof(line) - 1, "%s = %s\n", name, ustr);
	cmd_append_cfgline(conf, line);
}

static void cmd_append_id(const char *name, uint32_t id, char **conf)
{
	char line[512] = "";

	snprintf(line, sizeof(line) - 1, "%s = %u\n", name, id);
	cmd_append_cfgline(conf, line);
}

static void
cmd_append_user(const struct silofs_uids *uid, char **conf)
{
	char name[NAME_MAX + 1] = "";

	cmd_resolve_uid_to_name(uid->host_uid, name, sizeof(name));
	cmd_append_id(name, uid->fs_uid, conf);
}

static void
cmd_append_group(const struct silofs_gids *gid, char **conf)
{
	char name[NAME_MAX + 1] = "";

	cmd_resolve_gid_to_name(gid->fs_gid, name, sizeof(name));
	cmd_append_id(name, gid->host_gid, conf);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool cmd_isascii_cfg(const char *cfg, size_t size)
{
	struct silofs_substr scfg;

	substr_initn(&scfg, cfg, size);
	return substr_isascii(&scfg);
}

static void cmd_read_iconf_file(const char *path, char **out_cfg)
{
	struct stat st;
	size_t size;
	char *cfg = NULL;
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
	cfg = cmd_zalloc(size + 1);
	err = silofs_sys_readn(fd, cfg, size);
	if (err) {
		silofs_die(err, "failed to read config file %s", path);
	}
	silofs_sys_close(fd);

	if (!cmd_isascii_cfg(cfg, size)) {
		silofs_die(0, "non-ascii character in: %s", path);
	}
	*out_cfg = cfg;
}

static void cmd_write_iconf_file(const char *path, const char *cfg)
{
	const size_t len = cfg ? strlen(cfg) : 0;
	const mode_t mode = S_IRUSR | S_IWUSR;
	int fd = -1;
	int err;

	silofs_sys_chmod(path, mode);
	err = silofs_sys_open(path, O_CREAT | O_RDWR | O_TRUNC, mode, &fd);
	if (err) {
		silofs_die(err, "failed to create: %s", path);
	}
	err = silofs_sys_writen(fd, cfg, len);
	if (err) {
		silofs_die(err, "failed to write: %s", path);
	}
	silofs_sys_closefd(&fd);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void cmd_iconf_parse_uuid_cfg(struct silofs_iconf *iconf,
                                     const struct silofs_substr *line)
{
	cmd_parse_uuid_cfg(line, &iconf->uuid);
}

static void cmd_iconf_parse_uid_cfg(struct silofs_iconf *iconf,
                                    const struct silofs_substr *line)
{
	cmd_parse_uid_cfg(line, &iconf->ids.uids, &iconf->ids.nuids);
}

static void cmd_iconf_parse_gid_cfg(struct silofs_iconf *iconf,
                                    const struct silofs_substr *line)
{
	cmd_parse_gid_cfg(line, &iconf->ids.gids, &iconf->ids.ngids);
}

static void cmd_iconf_parse_line(struct silofs_iconf *iconf, int sec_state,
                                 const struct silofs_substr *line)
{
	if (sec_state & CONF_SEC_FS) {
		cmd_iconf_parse_uuid_cfg(iconf, line);
	} else if (sec_state & CONF_SEC_USERS) {
		cmd_iconf_parse_uid_cfg(iconf, line);
	} else if (sec_state & CONF_SEC_GROUPS) {
		cmd_iconf_parse_gid_cfg(iconf, line);
	} else if (sec_state != CONF_SEC_IGNORE) {
		cmd_die_by(line, "illegal ids-map config");
	}
}

static int cmd_parse_sec_state(const struct silofs_substr *line)
{
	struct silofs_substr ss;
	int ret = CONF_SEC_IGNORE;

	substr_strip_ws(line, &ss);
	if (substr_starts_with(&ss, '[') && substr_ends_with(&ss, ']')) {
		substr_strip_any(&ss, "[]", &ss);
		substr_strip_ws(&ss, &ss);
		if (substr_isequal(&ss, "fs")) {
			ret = CONF_SEC_FS;
		} else if (substr_isequal(&ss, "users")) {
			ret = CONF_SEC_USERS;
		} else if (substr_isequal(&ss, "groups")) {
			ret = CONF_SEC_GROUPS;
		}
	}
	return ret;
}

static void cmd_iconf_parse_data(struct silofs_iconf *iconf,
                                 const struct silofs_substr *data)
{
	struct silofs_substr_pair pair;
	struct silofs_substr_pair pair2;
	struct silofs_substr *line = &pair.first;
	struct silofs_substr *tail = &pair.second;
	struct silofs_substr sline;
	int sec_state = CONF_SEC_IGNORE;
	int sec_snext = CONF_SEC_IGNORE;

	substr_split_by_nl(data, &pair);
	while (!substr_isempty(line) || !substr_isempty(tail)) {
		substr_split_by(line, '#', &pair2);
		substr_strip_ws(&pair2.first, &sline);

		sec_snext = cmd_parse_sec_state(&sline);
		if (sec_snext && (sec_snext != sec_state)) {
			sec_state = sec_snext;
		} else if (!substr_isempty(&sline)) {
			cmd_iconf_parse_line(iconf, sec_state, &sline);
		}
		substr_split_by_nl(tail, &pair);
	}
}

static void cmd_iconf_parse(struct silofs_iconf *iconf, const char *cfg)
{
	struct silofs_substr data;

	substr_init(&data, cfg);
	cmd_iconf_parse_data(iconf, &data);
}

static void
cmd_iconf_unparse(const struct silofs_iconf *iconf, char **pcfg)
{
	cmd_append_section("fs", pcfg);
	cmd_append_uuid("uuid", &iconf->uuid, pcfg);

	cmd_append_section("users", pcfg);
	for (size_t i = 0; i < iconf->ids.nuids; ++i) {
		cmd_append_user(&iconf->ids.uids[i], pcfg);
	}
	cmd_append_newline(pcfg);

	cmd_append_section("groups", pcfg);
	for (size_t j = 0; j < iconf->ids.ngids; ++j) {
		cmd_append_group(&iconf->ids.gids[j], pcfg);
	}
	cmd_append_newline(pcfg);
}

static void cmd_iconf_append_uids1(struct silofs_iconf *iconf,
                                   const struct silofs_uids *uids)
{
	cmd_append_uids1(&iconf->ids.uids, &iconf->ids.nuids, uids);
}

static void cmd_iconf_append_gids1(struct silofs_iconf *iconf,
                                   const struct silofs_gids *gids)
{
	cmd_append_gids1(&iconf->ids.gids, &iconf->ids.ngids, gids);
}

static bool cmd_iconf_has_host_gid(const struct silofs_iconf *iconf, gid_t gid)
{
	const struct silofs_ids *ids = &iconf->ids;

	for (size_t i = 0; i < ids->ngids; ++i) {
		if (ids->gids[i].host_gid == gid) {
			return true;
		}
	}
	return false;
}

static void cmd_iconf_add_supgr(struct silofs_iconf *iconf, const char *user)
{
	struct silofs_gids gids;
	gid_t groups[64] = { (gid_t)(-1) };
	gid_t gid = (gid_t)(-1);
	int ngroups = (int)SILOFS_ARRAY_SIZE(groups);
	int ret;

	ret = getgrouplist(user, gid, groups, &ngroups);
	if (ret < 0) {
		cmd_dief(errno, "getgrouplist failure: ret=%d", ret);
	}
	for (int i = 0; i < ngroups; ++i) {
		gid = groups[i];
		if (gid == (gid_t)(-1)) {
			continue;
		}
		if (cmd_iconf_has_host_gid(iconf, gid)) {
			continue;
		}
		gids.host_gid = gids.fs_gid = gid;
		cmd_iconf_append_gids1(iconf, &gids);
	}
}

void cmd_iconf_add_user(struct silofs_iconf *iconf,
                        const char *user, bool with_sup_groups)
{
	struct silofs_uids uids;
	struct silofs_gids gids;
	uid_t uid = (uid_t)(-1);
	gid_t gid = (gid_t)(-1);

	cmd_resolve_uidgid(user, &uid, &gid);
	uids.host_uid = uids.fs_uid = uid;
	cmd_iconf_append_uids1(iconf, &uids);
	gids.host_gid = gids.fs_gid = gid;
	cmd_iconf_append_gids1(iconf, &gids);
	if (with_sup_groups) {
		cmd_iconf_add_supgr(iconf, user);
	}
}

void cmd_iconf_init(struct silofs_iconf *iconf)
{
	memset(iconf, 0, sizeof(*iconf));
	silofs_uuid_generate(&iconf->uuid);
	iconf->ids.nuids = 0;
	iconf->ids.ngids = 0;
}

void cmd_iconf_assign(struct silofs_iconf *iconf,
                      const struct silofs_iconf *other)
{
	cmd_iconf_init(iconf);
	silofs_namebuf_assign(&iconf->name, &other->name);
	silofs_uuid_assign(&iconf->uuid, &other->uuid);
	for (size_t i = 0; i < other->ids.nuids; ++i) {
		cmd_iconf_append_uids1(iconf, &other->ids.uids[i]);
	}
	for (size_t j = 0; j < other->ids.ngids; ++j) {
		cmd_iconf_append_gids1(iconf, &other->ids.gids[j]);
	}
}

void cmd_iconf_reset(struct silofs_iconf *iconf)
{
	cmd_pfree_uids(&iconf->ids.uids, &iconf->ids.nuids);
	cmd_pfree_gids(&iconf->ids.gids, &iconf->ids.ngids);
}

static void
cmd_iconf_load_from(struct silofs_iconf *iconf, const char *path)
{
	char *cfg = NULL;

	cmd_read_iconf_file(path, &cfg);
	cmd_iconf_parse(iconf, cfg);
	cmd_pstrfree(&cfg);
}

static void
cmd_iconf_save_to(const struct silofs_iconf *iconf, const char *path)
{
	char *cfg = NULL;

	cmd_iconf_unparse(iconf, &cfg);
	cmd_write_iconf_file(path, cfg);
	cmd_pstrfree(&cfg);
}

static char *
cmd_iconf_pathname(const struct silofs_iconf *iconf, const char *repodir)
{
	char *path = NULL;

	cmd_join_path(repodir, iconf->name.name, &path);
	return path;
}

void cmd_iconf_load(struct silofs_iconf *iconf, const char *repodir)
{
	char *path;

	path = cmd_iconf_pathname(iconf, repodir);
	cmd_iconf_reset(iconf);
	cmd_iconf_load_from(iconf, path);
	cmd_pstrfree(&path);
}

void cmd_iconf_save(const struct silofs_iconf *iconf,
                    const char *repodir)
{
	char *path;

	path = cmd_iconf_pathname(iconf, repodir);
	cmd_iconf_save_to(iconf, path);
	cmd_pstrfree(&path);
}

void cmd_iconf_unlink(const struct silofs_iconf *iconf, const char *repodir)
{
	char *path = NULL;

	path = cmd_iconf_pathname(iconf, repodir);
	silofs_sys_unlink(path);
	cmd_pstrfree(&path);
	(void)iconf;
}

void cmd_iconf_setname(struct silofs_iconf *iconf, const char *name)
{
	struct silofs_namestr nstr;

	silofs_namestr_init(&nstr, name);
	silofs_namebuf_assign_str(&iconf->name, &nstr);
}

void cmd_iconf_setuuid(struct silofs_iconf *iconf,
                       const struct silofs_uuid *uuid)
{
	silofs_uuid_assign(&iconf->uuid, uuid);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int cmd_try_getlogin(char **out_name)
{
	char name[LOGIN_NAME_MAX + 1] = "";
	int err;

	err = getlogin_r(name, sizeof(name) - 1);
	if (err) {
		return err;
	}
	if (!strlen(name)) {
		return -ENOENT;
	}
	*out_name = cmd_strdup(name);
	return 0;
}

char *cmd_getpwuid(uid_t uid)
{
	char name[NAME_MAX + 1] = "";

	cmd_resolve_uid_to_name(uid, name, sizeof(name) - 1);
	return cmd_strdup(name);
}

char *cmd_getusername(void)
{
	char *name = NULL;
	int err;

	err = cmd_try_getlogin(&name);
	if (err) {
		name = cmd_getpwuid(geteuid());
	}
	return name;
}

void cmd_resolve_uidgid(const char *name, uid_t *out_uid, gid_t *out_gid)
{
	struct passwd pwd = { .pw_uid = (uid_t)(-1) };
	struct passwd *pw = NULL;
	char *buf = NULL;
	size_t bsz;
	int err;

	bsz = cmd_getxx_bsz();
	buf = cmd_zalloc(bsz);
	err = getpwnam_r(name, &pwd, buf, bsz, &pw);
	if (err) {
		cmd_dief(err, "getpwnam failed: %s", name);
	}
	if (pw == NULL) {
		cmd_dief(0, "unknown user name: %s", name);
	}
	*out_uid = pw->pw_uid;
	*out_gid = pw->pw_gid;
	cmd_zfree(buf, bsz);
}

