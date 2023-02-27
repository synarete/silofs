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
#include <termios.h>
#include <ctype.h>
#include "cmd.h"

static void write_stdout(const char *msg)
{
	size_t nwr;
	int fd_out = STDOUT_FILENO;

	silofs_sys_write(fd_out, msg, strlen(msg), &nwr);
	silofs_sys_fsync(fd_out);
}

static void write_newline(void)
{
	write_stdout("\n");
}

static void check_password_char(int ch)
{
	if (!isascii(ch)) {
		cmd_dief(-EINVAL, "non ASCII char in password");
	}
	if (iscntrl(ch)) {
		cmd_dief(-EINVAL, "control char in password");
	}
	if (isspace(ch)) {
		cmd_dief(-EINVAL, "space char in password");
	}
	if (!isprint(ch)) {
		cmd_dief(-EINVAL, "non printable char in password");
	}
	if (!isalnum(ch) && !ispunct(ch)) {
		cmd_dief(-EINVAL, "illegal char in password");
	}
}

static int isskip(int ch)
{
	return !ch || isspace(ch);
}

static void parse_password(char *buf, size_t bsz)
{
	size_t len = bsz;
	const char *str = buf;

	while (len && isskip(*str)) {
		str++;
		len--;
	}
	while (len && isskip(str[len - 1])) {
		len--;
	}
	if (len == 0) {
		cmd_dief(-EINVAL, "zero length password");
	}
	if ((len > SILOFS_PASSWORD_MAX) || (len >= bsz)) {
		cmd_dief(-EINVAL, "password too long");
	}
	for (size_t i = 0; i < len; ++i) {
		check_password_char(str[i]);
	}
	memmove(buf, str, len);
	buf[len] = '\0';
}

static void
read_password_buf_from_file(int fd, void *buf, size_t bsz, size_t *out_len)
{
	int err;
	struct stat st;

	err = silofs_sys_fstat(fd, &st);
	if (err) {
		cmd_dief(err, "fstat failed");
	}
	if (!st.st_size || (st.st_size > (loff_t)bsz)) {
		cmd_dief(-EFBIG, "illegal password file size");
	}
	err = silofs_sys_pread(fd, buf, (size_t)st.st_size, 0, out_len);
	if (err) {
		cmd_dief(err, "pread password file");
	}
}

static void
read_password_buf_from_tty(int fd, void *buf, size_t bsz, size_t *out_len)
{
	int err;
	int read_err;
	char *pass;
	struct termios tr_old;
	struct termios tr_new;

	err = tcgetattr(fd, &tr_old);
	if (err) {
		cmd_dief(errno, "tcgetattr fd=%d", fd);
	}
	memcpy(&tr_new, &tr_old, sizeof(tr_new));
	tr_new.c_lflag &= ~((tcflag_t)ECHO);
	tr_new.c_lflag |= ICANON;
	tr_new.c_lflag |= ISIG;
	tr_new.c_cc[VMIN] = 1;
	tr_new.c_cc[VTIME] = 0;
	err = tcsetattr(fd, TCSANOW, &tr_new);
	if (err) {
		cmd_dief(errno, "tcsetattr fd=%d", fd);
	}

	read_err = silofs_sys_read(fd, buf, bsz, out_len);
	write_newline();

	err = tcsetattr(fd, TCSANOW, &tr_old);
	if (err) {
		cmd_dief(errno, "tcsetattr fd=%d", fd);
	}

	err = read_err;
	if (err) {
		cmd_dief(err, "read password error");
	}
	if (*out_len == 0) {
		cmd_dief(-EINVAL, "read zero-length password");
	}
	pass = buf;
	if (pass[*out_len - 1] != '\n') {
		cmd_dief(-EINVAL, "password too long");
	}
}

static void read_password_buf(int fd, void *buf, size_t bsz, size_t *out_len)
{
	if (isatty(fd)) {
		read_password_buf_from_tty(fd, buf, bsz, out_len);
	} else {
		read_password_buf_from_file(fd, buf, bsz, out_len);
	}
}

static int open_password_file(const char *path)
{
	int err;
	int fd = -1;

	if (path == NULL) {
		return STDIN_FILENO;
	}
	err = silofs_sys_access(path, R_OK);
	if (err) {
		cmd_dief(err, "no read access to password file %s", path);
	}
	err = silofs_sys_open(path, O_RDONLY, 0, &fd);
	if (err) {
		cmd_dief(err, "can not open password file %s", path);
	}
	return fd;
}

static void close_password_file(int fd, const char *path)
{
	int err;

	if (path != NULL) {
		err = silofs_sys_close(fd);
		if (err) {
			cmd_dief(err, "close failed: %s", path);
		}
	}
}

static char *getpass_from_file(const char *path)
{
	int fd;
	size_t len = 0;
	char buf[1024] = "";

	fd = open_password_file(path);
	read_password_buf(fd, buf, sizeof(buf), &len);
	parse_password(buf, len);
	close_password_file(fd, path);
	return cmd_strdup(buf);
}

static char *silofs_do_getpass(const char *path, bool repeat)
{
	char *pass = NULL;
	char *pass2 = NULL;

	if (path) {
		return getpass_from_file(path);
	}
	write_stdout("enter password: ");
	pass = getpass_from_file(NULL);
	if (!repeat) {
		return pass;
	}
	write_stdout("re-enter password: ");
	pass2 = getpass_from_file(NULL);
	if (strcmp(pass, pass2) != 0) {
		cmd_delpass(&pass);
		cmd_delpass(&pass2);
		cmd_dief(0, "password not equal");
	}
	cmd_delpass(&pass2);
	return pass;
}

void cmd_getpass(const char *path, char **out_pass)
{
	*out_pass = silofs_do_getpass(path, false);
}

void cmd_getpass2(const char *path, char **out_pass)
{
	*out_pass = silofs_do_getpass(path, true);
}

void cmd_delpass(char **pass)
{
	if (pass && *pass) {
		silofs_memffff(*pass, strlen(*pass));
		cmd_pstrfree(pass);
	}
}

