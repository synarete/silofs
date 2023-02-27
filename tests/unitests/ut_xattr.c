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
#include "unitests.h"


struct silofs_kv_sizes {
	size_t name_len;
	size_t value_size;
};


static struct ut_keyval *
kv_new(struct ut_env *ute, size_t nlen, size_t size)
{
	struct ut_keyval *kv;

	kv = ut_malloc(ute, sizeof(*kv));
	kv->name = ut_randstr(ute, nlen);
	kv->value = ut_randstr(ute, size);
	kv->size = size;

	return kv;
}

static struct ut_kvl *kvl_new(struct ut_env *ute, size_t limit)
{
	struct ut_kvl *kvl;
	const size_t list_sz = limit * sizeof(struct ut_keyval *);

	kvl = ut_malloc(ute, sizeof(*kvl));
	kvl->ute = ute;
	kvl->list = ut_zalloc(ute, list_sz);
	kvl->limit = limit;
	kvl->count = 0;
	return kvl;
}

static void kvl_append(struct ut_kvl *kvl, size_t nlen, size_t value_sz)
{
	ut_expect_lt(kvl->count, kvl->limit);

	kvl->list[kvl->count++] = kv_new(kvl->ute, nlen, value_sz);
}

static void kvl_appendn(struct ut_kvl *kvl,
                        const struct silofs_kv_sizes *arr, size_t arr_len)
{
	for (size_t i = 0; i < arr_len; ++i) {
		kvl_append(kvl, arr[i].name_len, arr[i].value_size);
	}
}

static void kvl_populate(struct ut_kvl *kvl,
                         size_t name_len, size_t value_sz)
{
	for (size_t i = kvl->count; i < kvl->limit; ++i) {
		kvl_append(kvl, name_len, value_sz);
	}
}

static void kvl_populate_max(struct ut_kvl *kvl)
{
	const size_t name_len = UT_NAME_MAX;
	const size_t value_sz = SILOFS_XATTR_VALUE_MAX;

	for (size_t i = kvl->count; i < kvl->limit; ++i) {
		kvl_append(kvl, name_len, value_sz);
	}
}

static void kvl_swap(struct ut_kvl *kvl, size_t i, size_t j)
{
	struct ut_keyval *kv;

	kv = kvl->list[i];
	kvl->list[i] = kvl->list[j];
	kvl->list[j] = kv;
}

static void kvl_reverse(struct ut_kvl *kvl)
{
	const size_t cnt = kvl->count / 2;

	for (size_t i = 0, j = kvl->count - 1; i < cnt; ++i, --j) {
		kvl_swap(kvl, i, j);
	}
}

static void kvl_random_shuffle(struct ut_kvl *kvl)
{
	size_t pos[32];
	const size_t npos = UT_ARRAY_SIZE(pos);
	struct ut_env *ute = kvl->ute;

	for (size_t i = 0, j = npos; i < kvl->count / 2; ++i, ++j) {
		if (j >= npos) {
			ut_randfill(ute, pos, sizeof(pos));
			j = 0;
		}
		kvl_swap(kvl, i, pos[j] % kvl->count);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_xattr_simple_(struct ut_env *ute,
                             size_t name_len, size_t value_size)
{
	ino_t ino = 0;
	ino_t dino = 0;
	const char *name = UT_NAME;
	struct ut_kvl *kvl = NULL;

	kvl = kvl_new(ute, 1);
	kvl_populate(kvl, name_len, value_size);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	for (size_t i = 0; i < kvl->count; ++i) {
		ut_setxattr_create(ute, ino, kvl->list[i]);
	}
	for (size_t i = 0; i < kvl->count; ++i) {
		ut_getxattr_value(ute, ino, kvl->list[i]);
	}
	ut_listxattr_ok(ute, ino, kvl);
	for (size_t i = 0; i < kvl->count; ++i) {
		ut_removexattr_ok(ute, ino, kvl->list[i]);
	}
	for (size_t i = 0; i < kvl->count; ++i) {
		ut_getxattr_nodata(ute, ino, kvl->list[i]);
	}
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_xattr_simple(struct ut_env *ute)
{
	ut_xattr_simple_(ute, 1, 1);
	ut_xattr_simple_(ute, SILOFS_NAME_MAX, 1);
	ut_xattr_simple_(ute, 1, SILOFS_XATTR_VALUE_MAX);
	ut_xattr_simple_(ute, SILOFS_NAME_MAX, SILOFS_XATTR_VALUE_MAX);
}

static void ut_xattr_any_value(struct ut_env *ute)
{
	for (size_t i = 1; i <= SILOFS_XATTR_VALUE_MAX; ++i) {
		ut_xattr_simple_(ute, SILOFS_NAME_MAX, i);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_xattr_short_names(struct ut_env *ute)
{
	ino_t ino = 0;
	ino_t dino = 0;
	const char *name = UT_NAME;
	struct ut_kvl *kvl = NULL;

	kvl = kvl_new(ute, 16);
	kvl_populate(kvl, 4, 32);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	for (size_t i = 0; i < kvl->count; ++i) {
		ut_setxattr_create(ute, ino, kvl->list[i]);
	}
	for (size_t i = 0; i < kvl->count; ++i) {
		ut_getxattr_value(ute, ino, kvl->list[i]);
	}
	ut_listxattr_ok(ute, ino, kvl);
	for (size_t i = 0; i < kvl->count; ++i) {
		ut_removexattr_ok(ute, ino, kvl->list[i]);
	}
	for (size_t i = 0; i < kvl->count; ++i) {
		ut_getxattr_nodata(ute, ino, kvl->list[i]);
	}
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_xattr_long_names(struct ut_env *ute)
{
	ino_t ino = 0;
	const ino_t root_ino = UT_ROOT_INO;
	const char *name = UT_NAME;
	struct ut_kvl *kvl = NULL;

	kvl = kvl_new(ute, 4);
	kvl_populate(kvl, UT_NAME_MAX, SILOFS_XATTR_VALUE_MAX);

	ut_create_file(ute, root_ino, name, &ino);
	ut_setxattr_all(ute, ino, kvl);
	ut_listxattr_ok(ute, ino, kvl);
	kvl_reverse(kvl);
	ut_listxattr_ok(ute, ino, kvl);
	ut_removexattr_all(ute, ino, kvl);
	ut_remove_file(ute, root_ino, name, ino);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fill_short_kv(struct ut_env *ute,
                          struct ut_keyval *kv, size_t idx)
{
	const char *str;

	str = ut_strfmt(ute, (idx & 1) ? "%lx" : "%032lx", idx);
	kv->name = str;
	kv->value = str;
	kv->size = strlen(str);
}

static void ut_xattr_shorts_(struct ut_env *ute, size_t cnt)
{
	ino_t ino = 0;
	const char *dname = UT_NAME;
	struct ut_keyval kv = { .size = 0 };

	ut_mkdir_at_root(ute, dname, &ino);
	for (size_t i = 0; i < cnt; ++i) {
		fill_short_kv(ute, &kv, i);
		ut_setxattr_create(ute, ino, &kv);
	}
	for (size_t i = 0; i < cnt; i += 2) {
		fill_short_kv(ute, &kv, i);
		ut_removexattr_ok(ute, ino, &kv);
	}
	for (size_t i = 1; i < cnt; i += 2) {
		fill_short_kv(ute, &kv, i);
		ut_removexattr_ok(ute, ino, &kv);
		fill_short_kv(ute, &kv, ~i);
		ut_setxattr_create(ute, ino, &kv);
		fill_short_kv(ute, &kv, ~(i - 1));
		ut_setxattr_create(ute, ino, &kv);
	}
	for (size_t i = 0; i < cnt; ++i) {
		fill_short_kv(ute, &kv, ~i);
		ut_removexattr_ok(ute, ino, &kv);
	}
	ut_rmdir_at_root(ute, dname);
}

static void ut_xattr_shorts(struct ut_env *ute)
{
	ut_xattr_shorts_(ute, 10);
	ut_xattr_shorts_(ute, 100);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fill_novalue_kv(struct ut_env *ute,
                            struct ut_keyval *kv, size_t idx)
{
	size_t len = 0;
	char *str = NULL;

	str = ut_strfmt(ute, "%lx-%0255lx", idx, idx);
	len = strlen(str);
	if ((idx > 7) && (idx < len)) {
		str[idx] = '\0';
	} else if (len > UT_NAME_MAX) {
		str[UT_NAME_MAX] = '\0';
	}
	kv->name = str;
	kv->value = NULL;
	kv->size = 0;
}

static void ut_xattr_no_value_(struct ut_env *ute, size_t cnt)
{
	ino_t ino = 0;
	const char *dname = UT_NAME;
	struct ut_keyval kv = { .size = 0 };

	ut_mkdir_at_root(ute, dname, &ino);
	for (size_t i = 0; i < cnt; ++i) {
		fill_novalue_kv(ute, &kv, i);
		ut_setxattr_create(ute, ino, &kv);
	}
	for (size_t i = 0; i < cnt; i += 2) {
		fill_novalue_kv(ute, &kv, i);
		ut_removexattr_ok(ute, ino, &kv);
	}
	for (size_t i = 1; i < cnt; i += 2) {
		fill_novalue_kv(ute, &kv, i);
		ut_removexattr_ok(ute, ino, &kv);
		fill_novalue_kv(ute, &kv, ~i);
		ut_setxattr_create(ute, ino, &kv);
		fill_novalue_kv(ute, &kv, ~(i - 1));
		ut_setxattr_create(ute, ino, &kv);
	}
	for (size_t i = 0; i < cnt; ++i) {
		fill_novalue_kv(ute, &kv, ~i);
		ut_removexattr_ok(ute, ino, &kv);
	}
	ut_rmdir_at_root(ute, dname);
}

static void ut_xattr_no_value(struct ut_env *ute)
{
	ut_xattr_no_value_(ute, 40);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_xattr_multi(struct ut_env *ute)
{
	ino_t ino = 0;
	ino_t dino = 0;
	const char *dname = UT_NAME;
	const char *fname = UT_NAME;
	struct ut_kvl *kvl = NULL;
	const struct silofs_kv_sizes kv_sizes_arr[] = {
		{ 1, 1 },
		{ UT_NAME_MAX / 2, 2 },
		{ 2, SILOFS_XATTR_VALUE_MAX / 2 },
		{ UT_NAME_MAX / 16, 16 },
		{ 32, SILOFS_XATTR_VALUE_MAX / 32 },
		{ UT_NAME_MAX, 128 },
		{ 64, SILOFS_XATTR_VALUE_MAX },
	};
	const size_t nkv_sizes = UT_ARRAY_SIZE(kv_sizes_arr);

	ut_mkdir_at_root(ute, dname, &dino);
	ut_create_only(ute, dino, fname, &ino);

	for (size_t i = 0; i < 4; ++i) {
		kvl = kvl_new(ute, nkv_sizes);
		kvl_appendn(kvl, kv_sizes_arr, nkv_sizes);

		ut_setxattr_all(ute, dino, kvl);
		ut_listxattr_ok(ute, dino, kvl);
		ut_setxattr_all(ute, ino, kvl);
		ut_listxattr_ok(ute, ino, kvl);
		kvl_reverse(kvl);
		ut_listxattr_ok(ute, dino, kvl);
		ut_listxattr_ok(ute, ino, kvl);
		ut_removexattr_all(ute, ino, kvl);
		ut_drop_caches_fully(ute);
		kvl_random_shuffle(kvl);
		ut_setxattr_all(ute, ino, kvl);
		ut_listxattr_ok(ute, ino, kvl);
		ut_listxattr_ok(ute, dino, kvl);
		kvl_random_shuffle(kvl);
		ut_listxattr_ok(ute, ino, kvl);
		ut_removexattr_all(ute, ino, kvl);
		ut_removexattr_all(ute, dino, kvl);
	}
	ut_unlink_ok(ute, dino, fname);
	ut_rmdir_at_root(ute, dname);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_xattr_lookup_random(struct ut_env *ute)
{
	ino_t ino = 0;
	ino_t dino = 0;
	const ino_t root_ino = UT_ROOT_INO;
	const char *dname = UT_NAME;
	const char *xname = NULL;
	struct ut_kvl *kvl = kvl_new(ute, 4);

	kvl_populate_max(kvl);
	ut_mkdir_oki(ute, root_ino, dname, &dino);
	for (size_t i = 0; i < kvl->count; ++i) {
		xname = kvl->list[i]->name;
		ut_create_file(ute, dino, xname, &ino);
		ut_setxattr_all(ute, ino, kvl);
		ut_listxattr_ok(ute, ino, kvl);
	}
	for (size_t i = 0; i < kvl->count; ++i) {
		xname = kvl->list[i]->name;
		ut_lookup_ino(ute, dino, xname, &ino);
		ut_listxattr_ok(ute, ino, kvl);
	}
	kvl_random_shuffle(kvl);
	for (size_t i = 0; i < kvl->count; i += 3) {
		xname = kvl->list[i]->name;
		ut_lookup_ino(ute, dino, xname, &ino);
		ut_removexattr_all(ute, ino, kvl);
	}
	kvl_random_shuffle(kvl);
	for (size_t i = 0; i < kvl->count; ++i) {
		xname = kvl->list[i]->name;
		ut_lookup_ino(ute, dino, xname, &ino);
		ut_remove_file(ute, dino, xname, ino);
	}
	ut_rmdir_ok(ute, root_ino, dname);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_xattr_replace(struct ut_env *ute)
{
	ino_t ino = 0;
	ino_t dino = 0;
	const ino_t root_ino = UT_ROOT_INO;
	const char *dname = UT_NAME;
	const char *fname = UT_NAME;
	struct ut_kvl *kvl = kvl_new(ute, 5);

	kvl_populate(kvl, UT_NAME_MAX / 2, SILOFS_XATTR_VALUE_MAX / 2);

	ut_mkdir_oki(ute, root_ino, dname, &dino);
	ut_create_file(ute, dino, fname, &ino);
	for (size_t i = 0; i < kvl->count; ++i) {
		ut_setxattr_create(ute, ino, kvl->list[i]);
	}
	for (size_t i = 0; i < kvl->count; ++i) {
		kvl->list[i]->size = SILOFS_XATTR_VALUE_MAX / 3;
		ut_setxattr_replace(ute, ino, kvl->list[i]);
	}
	for (size_t i = 0; i < kvl->count; ++i) {
		kvl->list[i]->size = SILOFS_XATTR_VALUE_MAX / 4;
		ut_setxattr_rereplace(ute, ino, kvl->list[i]);
	}
	for (size_t i = 0; i < kvl->count; ++i) {
		ut_removexattr_ok(ute, ino, kvl->list[i]);
	}
	ut_remove_file(ute, dino, fname, ino);
	ut_rmdir_ok(ute, root_ino, dname);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_xattr_replace_multi(struct ut_env *ute)
{
	ino_t ino = 0;
	ino_t dino = 0;
	size_t value_size = 0;
	const ino_t root_ino = UT_ROOT_INO;
	const char *dname = UT_NAME;
	const char *fname = UT_NAME;
	struct ut_kvl *kvl = kvl_new(ute, 3);

	value_size = SILOFS_XATTR_VALUE_MAX;
	kvl_populate(kvl, UT_NAME_MAX / 2, value_size);

	ut_mkdir_oki(ute, root_ino, dname, &dino);
	ut_create_file(ute, dino, fname, &ino);
	for (size_t i = 0; i < kvl->count; ++i) {
		ut_setxattr_create(ute, ino, kvl->list[i]);
	}
	for (size_t i = 0; i < kvl->count; ++i) {
		for (size_t j = value_size; j > 2; --j) {
			kvl->list[i]->size = j - 1;
			ut_setxattr_replace(ute, ino, kvl->list[i]);
			kvl->list[i]->size = j - 2;
			ut_setxattr_rereplace(ute, ino,
			                      kvl->list[i]);
		}
	}
	for (size_t i = 0; i < kvl->count; ++i) {
		ut_removexattr_ok(ute, ino, kvl->list[i]);
	}
	ut_remove_file(ute, dino, fname, ino);
	ut_rmdir_ok(ute, root_ino, dname);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_xattr_with_io_(struct ut_env *ute, loff_t base_off,
                              size_t name_len, size_t value_size)
{
	ino_t ino = 0;
	ino_t dino = 0;
	loff_t off = -1;
	const char *name = UT_NAME;
	const struct ut_keyval *kv = NULL;
	struct ut_kvl *kvl = kvl_new(ute, 3);

	kvl_populate(kvl, name_len, value_size);
	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	for (size_t i = 0; i < kvl->count; ++i) {
		kv = kvl->list[i];
		ut_setxattr_create(ute, ino, kv);
		off = base_off + (long)(i * value_size);
		ut_write_ok(ute, ino, kv->value, kv->size, off);
	}
	for (size_t i = 0; i < kvl->count; ++i) {
		kv = kvl->list[i];
		ut_getxattr_value(ute, ino, kv);
		off = base_off + (long)(i * value_size);
		ut_read_verify(ute, ino, kv->value, kv->size, off);
	}
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_xattr_with_io(struct ut_env *ute)
{
	ut_xattr_with_io_(ute, 0, SILOFS_NAME_MAX, UT_KILO / 4);
	ut_xattr_with_io_(ute, UT_KILO, SILOFS_NAME_MAX / 2, UT_KILO / 2);
	ut_xattr_with_io_(ute, UT_MEGA, SILOFS_NAME_MAX / 4, UT_KILO);
	ut_xattr_with_io_(ute, UT_TERA, SILOFS_NAME_MAX / 8, 2 * UT_KILO);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST1(ut_xattr_simple),
	UT_DEFTEST(ut_xattr_any_value),
	UT_DEFTEST(ut_xattr_short_names),
	UT_DEFTEST(ut_xattr_long_names),
	UT_DEFTEST(ut_xattr_shorts),
	UT_DEFTEST(ut_xattr_no_value),
	UT_DEFTEST(ut_xattr_multi),
	UT_DEFTEST(ut_xattr_lookup_random),
	UT_DEFTEST(ut_xattr_replace),
	UT_DEFTEST(ut_xattr_replace_multi),
	UT_DEFTEST(ut_xattr_with_io),
};

const struct ut_testdefs ut_tdefs_xattr = UT_MKTESTS(ut_local_tests);

