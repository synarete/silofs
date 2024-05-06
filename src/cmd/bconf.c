/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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

static void cmd_parse_simple_string(const struct silofs_substr *in,
                                    struct silofs_substr *out)
{
	struct silofs_substr ss;
	const char dq[] = "\"";

	substr_strip_ws(in, &ss);
	if (ss.len < 2) {
		cmd_dief(0, "illegal string: '%.*s'", ss.len, ss.str);
	}
	if (!silofs_substr_starts_with(&ss, dq[0]) ||
	    !silofs_substr_ends_with(&ss, dq[0])) {
		cmd_dief(0, "illegal string: '%.*s'", ss.len, ss.str);
	}
	substr_strip_any(&ss, dq, out);
	if ((out->len + 2) != ss.len) {
		cmd_dief(0, "illegal string: '%.*s'", ss.len, ss.str);
	}
}

static void cmd_parse_uuid_cfg(const struct silofs_substr *line,
                               struct silofs_uuid *uuid)
{
	struct silofs_substr_pair ssp;
	struct silofs_substr name;
	struct silofs_substr suuid;
	int err;

	substr_split_by(line, '=', &ssp);
	substr_strip_ws(&ssp.first, &name);
	cmd_parse_simple_string(&ssp.second, &suuid);

	if (substr_isempty(&name) || substr_isempty(&suuid)) {
		cmd_die_by(line, "missing uuid value");
	}
	if (!substr_isequal(&name, "uuid")) {
		cmd_die_by(line, "missing 'uuid' key");
	}
	err = silofs_uuid_parse2(uuid, &suuid);
	if (err) {
		cmd_die_by(line, "illegal uuid value");
	}
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
	struct silofs_strbuf sbuf;
	char line[512] = "";

	silofs_strbuf_reset(&sbuf);
	silofs_uuid_unparse(uuid, &sbuf);
	snprintf(line, sizeof(line) - 1, "%s = \"%s\"\n", name, sbuf.str);
	cmd_append_cfgline(conf, line);
}

static void cmd_append_hash(const char *name,
                            const struct silofs_hash256 *hash, char **conf)
{
	struct silofs_strbuf sbuf;
	char line[512] = "";

	silofs_hash256_to_base64(hash, &sbuf);
	snprintf(line, sizeof(line) - 1, "%s = \"%s\"\n", name, sbuf.str);
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

static char *
cmd_read_bconf_file(const char *repodir, const char *name)
{
	struct stat st = { .st_mode = 0 };
	size_t size = 0;
	char *cfg = NULL;
	int dfd = -1;
	int fd = -1;
	int err;

	err = silofs_sys_stat(repodir, &st);
	if (err) {
		silofs_die(err, "stat failure: %s", repodir);
	}
	if (!S_ISDIR(st.st_mode)) {
		silofs_die(0, "not a directory: %s", repodir);
	}
	err = silofs_sys_open(repodir, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		silofs_die(err, "opendir error: %s", repodir);
	}
	err = silofs_sys_fstatat(dfd, name, &st, 0);
	if (err) {
		silofs_die(err, "stat failure: %s", name);
	}
	if (!S_ISREG(st.st_mode)) {
		silofs_die(0, "not a regular file: %s", name);
	}
	size = (size_t)st.st_size;
	if (size >= SILOFS_MEGA) {
		silofs_die(-EFBIG, "illegal boot-config file: %s", name);
	}
	err = silofs_sys_openat(dfd, name, O_RDONLY, 0, &fd);
	if (err) {
		silofs_die(err, "failed to open boot-config: %s", name);
	}
	silofs_sys_closefd(&dfd);

	cfg = cmd_zalloc(size + 1);
	err = silofs_sys_readn(fd, cfg, size);
	if (err) {
		silofs_die(err, "failed to read boot-config: %s", name);
	}
	silofs_sys_close(fd);

	if (!cmd_isascii_cfg(cfg, size)) {
		silofs_die(0, "non-ascii character in: %s", repodir);
	}
	return cfg;
}

static void
cmd_write_bconf_file(const char *repodir, const char *name, const char *cfg)
{
	const size_t len = cfg ? strlen(cfg) : 0;
	const mode_t mode = S_IRUSR | S_IWUSR;
	int dfd = -1;
	int fd = -1;
	int err;

	err = silofs_sys_open(repodir, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		silofs_die(err, "opendir error: %s", repodir);
	}
	silofs_sys_fchmodat(dfd, name, mode, 0);

	err = silofs_sys_openat(dfd, name, O_CREAT | O_RDWR | O_TRUNC,
	                        mode, &fd);
	if (err) {
		silofs_die(err, "failed to create boot-config: %s", name);
	}
	silofs_sys_closefd(&dfd);

	err = silofs_sys_writen(fd, cfg, len);
	if (err) {
		silofs_die(err, "failed to write boot-config: %s", name);
	}
	silofs_sys_closefd(&fd);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

enum cmd_conf_sec {
	CMD_CONF_SEC_NIL,
	CMD_CONF_SEC_FS,
	CMD_CONF_SEC_USERS,
	CMD_CONF_SEC_GROUPS,
};

static const char *s_cmd_conf_sec_name[] = {
	[CMD_CONF_SEC_NIL] = "",
	[CMD_CONF_SEC_FS] = "fs",
	[CMD_CONF_SEC_USERS] = "users",
	[CMD_CONF_SEC_GROUPS] = "groups",
};

static const char *cmd_conf_sec_to_name(enum cmd_conf_sec sec)
{
	const char *sec_name = "";

	if (sec < SILOFS_ARRAY_SIZE(s_cmd_conf_sec_name)) {
		sec_name = s_cmd_conf_sec_name[sec];
	}
	return sec_name;
}

static enum cmd_conf_sec cmd_conf_sec_by_name(const struct silofs_substr *ss)
{
	const char *sec_name;

	for (int i = 0; i < (int)SILOFS_ARRAY_SIZE(s_cmd_conf_sec_name); ++i) {
		sec_name = s_cmd_conf_sec_name[i];
		if (substr_isequal(ss, sec_name)) {
			return (enum cmd_conf_sec)i;
		}
	}
	return CMD_CONF_SEC_NIL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool cmd_bconf_has_pack_id(const struct silofs_fs_bconf *bconf)
{
	return !silofs_hash256_isnil(&bconf->pack_id);
}

static void cmd_bconf_parse_fsid_cfg(struct silofs_fs_bconf *bconf,
                                     const struct silofs_substr *line)
{
	cmd_parse_uuid_cfg(line, &bconf->fs_uuid);
}

static void cmd_bconf_parse_users_cfg(struct silofs_fs_bconf *bconf,
                                      const struct silofs_substr *line)
{
	cmd_parse_uid_cfg(line, &bconf->users_ids.uids,
	                  &bconf->users_ids.nuids);
}

static void cmd_bconf_parse_groups_cfg(struct silofs_fs_bconf *bconf,
                                       const struct silofs_substr *line)
{
	cmd_parse_gid_cfg(line, &bconf->groups_ids.gids,
	                  &bconf->groups_ids.ngids);
}

static void cmd_bconf_parse_line(struct silofs_fs_bconf *bconf,
                                 enum cmd_conf_sec sec_state,
                                 const struct silofs_substr *line)
{
	switch (sec_state) {
	case CMD_CONF_SEC_NIL:
		break;
	case CMD_CONF_SEC_FS:
		cmd_bconf_parse_fsid_cfg(bconf, line);
		break;
	case CMD_CONF_SEC_USERS:
		cmd_bconf_parse_users_cfg(bconf, line);
		break;
	case CMD_CONF_SEC_GROUPS:
		cmd_bconf_parse_groups_cfg(bconf, line);
		break;
	default:
		cmd_die_by(line, "illegal boot-config");
		break;
	}
}

static enum cmd_conf_sec cmd_parse_sec_state(const struct silofs_substr *line)
{
	struct silofs_substr ss;
	enum cmd_conf_sec sec = CMD_CONF_SEC_NIL;

	substr_strip_ws(line, &ss);
	if (substr_starts_with(&ss, '[') && substr_ends_with(&ss, ']')) {
		substr_strip_any(&ss, "[]", &ss);
		substr_strip_ws(&ss, &ss);
		sec = cmd_conf_sec_by_name(&ss);
	}
	return sec;
}

static void cmd_bconf_parse_data(struct silofs_fs_bconf *bconf,
                                 const struct silofs_substr *data)
{
	struct silofs_substr_pair pair;
	struct silofs_substr_pair pair2;
	struct silofs_substr *line = &pair.first;
	struct silofs_substr *tail = &pair.second;
	struct silofs_substr sline;
	enum cmd_conf_sec sec_curr = CMD_CONF_SEC_NIL;
	enum cmd_conf_sec sec_next = CMD_CONF_SEC_NIL;

	substr_split_by_nl(data, &pair);
	while (!substr_isempty(line) || !substr_isempty(tail)) {
		substr_split_by(line, '#', &pair2);
		substr_strip_ws(&pair2.first, &sline);

		sec_next = cmd_parse_sec_state(&sline);
		if ((sec_next != CMD_CONF_SEC_NIL) &&
		    (sec_next != sec_curr)) {
			sec_curr = sec_next;
		} else if (!substr_isempty(&sline)) {
			cmd_bconf_parse_line(bconf, sec_curr, &sline);
		}
		substr_split_by_nl(tail, &pair);
	}
}

static void cmd_bconf_parse(struct silofs_fs_bconf *bconf, const char *cfg)
{
	struct silofs_substr data;

	substr_init(&data, cfg);
	cmd_bconf_parse_data(bconf, &data);
}

static char *cmd_bconf_unparse(const struct silofs_fs_bconf *bconf)
{
	const char *sec_name = NULL;
	char *cfg = NULL;

	sec_name = cmd_conf_sec_to_name(CMD_CONF_SEC_FS);
	cmd_append_section(sec_name, &cfg);
	cmd_append_uuid("uuid", &bconf->fs_uuid, &cfg);
	if (cmd_bconf_has_pack_id(bconf)) {
		cmd_append_hash("pack", &bconf->pack_id, &cfg);
	}
	cmd_append_newline(&cfg);

	sec_name = cmd_conf_sec_to_name(CMD_CONF_SEC_USERS);
	cmd_append_section(sec_name, &cfg);
	for (size_t i = 0; i < bconf->users_ids.nuids; ++i) {
		cmd_append_user(&bconf->users_ids.uids[i], &cfg);
	}
	cmd_append_newline(&cfg);

	sec_name = cmd_conf_sec_to_name(CMD_CONF_SEC_GROUPS);
	cmd_append_section(sec_name, &cfg);
	for (size_t j = 0; j < bconf->groups_ids.ngids; ++j) {
		cmd_append_group(&bconf->groups_ids.gids[j], &cfg);
	}
	cmd_append_newline(&cfg);
	return cfg;
}

static void cmd_bconf_append_user_id(struct silofs_fs_bconf *bconf,
                                     const struct silofs_uids *uids)
{
	cmd_append_uids1(&bconf->users_ids.uids,
	                 &bconf->users_ids.nuids, uids);
}

static void cmd_bconf_append_group_id(struct silofs_fs_bconf *bconf,
                                      const struct silofs_gids *gids)
{
	cmd_append_gids1(&bconf->groups_ids.gids,
	                 &bconf->groups_ids.ngids, gids);
}

static bool
cmd_bconf_has_host_gid(const struct silofs_fs_bconf *bconf, gid_t gid)
{
	for (size_t i = 0; i < bconf->groups_ids.ngids; ++i) {
		if (bconf->groups_ids.gids[i].host_gid == gid) {
			return true;
		}
	}
	return false;
}

static void cmd_bconf_add_supgr(struct silofs_fs_bconf *bconf,
                                const char *user)
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
		if (cmd_bconf_has_host_gid(bconf, gid)) {
			continue;
		}
		gids.host_gid = gids.fs_gid = gid;
		cmd_bconf_append_group_id(bconf, &gids);
	}
}

void cmd_bconf_add_user(struct silofs_fs_bconf *bconf,
                        const char *user, bool with_sup_groups)
{
	struct silofs_uids uids;
	struct silofs_gids gids;
	uid_t uid = (uid_t)(-1);
	gid_t gid = (gid_t)(-1);

	cmd_resolve_uidgid(user, &uid, &gid);
	uids.host_uid = uids.fs_uid = uid;
	cmd_bconf_append_user_id(bconf, &uids);
	gids.host_gid = gids.fs_gid = gid;
	cmd_bconf_append_group_id(bconf, &gids);
	if (with_sup_groups) {
		cmd_bconf_add_supgr(bconf, user);
	}
}

void cmd_bconf_init(struct silofs_fs_bconf *bconf)
{
	silofs_memzero(bconf, sizeof(*bconf));
	silofs_uuid_generate(&bconf->fs_uuid);
	bconf->users_ids.uids = NULL;
	bconf->users_ids.nuids = 0;
	bconf->groups_ids.gids = NULL;
	bconf->groups_ids.ngids = 0;
}

void cmd_bconf_set_fsid(struct silofs_fs_bconf *bconf,
                        const struct silofs_uuid *uuid)
{
	silofs_uuid_assign(&bconf->fs_uuid, uuid);
}

static void cmd_bconf_set_name2(struct silofs_fs_bconf *bconf,
                                const struct silofs_strbuf *name)
{
	silofs_strbuf_assign(&bconf->name, name);
}

void cmd_bconf_assign(struct silofs_fs_bconf *bconf,
                      const struct silofs_fs_bconf *other)
{
	cmd_bconf_init(bconf);
	cmd_bconf_set_name2(bconf, &other->name);
	cmd_bconf_set_fsid(bconf, &other->fs_uuid);
	for (size_t i = 0; i < other->users_ids.nuids; ++i) {
		cmd_bconf_append_user_id(bconf, &other->users_ids.uids[i]);
	}
	for (size_t j = 0; j < other->groups_ids.ngids; ++j) {
		cmd_bconf_append_group_id(bconf, &other->groups_ids.gids[j]);
	}
}

void cmd_bconf_reset_ids(struct silofs_fs_bconf *bconf)
{
	cmd_pfree_uids(&bconf->users_ids.uids, &bconf->users_ids.nuids);
	cmd_pfree_gids(&bconf->groups_ids.gids, &bconf->groups_ids.ngids);
}

void cmd_bconf_load(struct silofs_fs_bconf *bconf, const char *basedir)
{
	char *cfg = NULL;

	cmd_bconf_reset_ids(bconf);
	cfg = cmd_read_bconf_file(basedir, bconf->name.str);
	cmd_bconf_parse(bconf, cfg);
	cmd_pstrfree(&cfg);
}

void cmd_bconf_save(const struct silofs_fs_bconf *bconf, const char *basedir)
{
	char *cfg = NULL;

	cfg = cmd_bconf_unparse(bconf);
	cmd_write_bconf_file(basedir, bconf->name.str, cfg);
	cmd_pstrfree(&cfg);
}

void cmd_bconf_unlink(const struct silofs_fs_bconf *bconf, const char *basedir)
{
	char *path = NULL;

	cmd_join_path(basedir, bconf->name.str, &path);
	silofs_sys_unlink(path);
	cmd_pstrfree(&path);
}

void cmd_bconf_set_name(struct silofs_fs_bconf *bconf, const char *name)
{
	struct silofs_namestr nstr;
	int err;

	err = silofs_make_namestr(&nstr, name);
	if (err) {
		cmd_dief(err, "illegal name: %s", name);
	}
	silofs_strbuf_setup(&bconf->name, &nstr.s);
}

void cmd_bconf_set_lvid_by(struct silofs_fs_bconf *bconf,
                           const struct silofs_lvid *lvid)
{
	cmd_bconf_set_fsid(bconf, &lvid->uuid);
}

void cmd_bconf_get_lvid(const struct silofs_fs_bconf *bconf,
                        struct silofs_lvid *out_lvid)
{
	silofs_lvid_by_uuid(out_lvid, &bconf->fs_uuid);
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

