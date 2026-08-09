/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include "utests.h"

#define ZMAGIC 0xA334CDE661L

struct ut_zrecord {
	struct silofs_avl_node avl_node;
	struct ut_env *ute;
	long key;
	long magic;
};

static struct ut_zrecord *avl_node_to_zrecord(const struct silofs_avl_node *an)
{
	const struct ut_zrecord *zr;

	ut_expect_not_null(an);
	zr = ut_container_of(an, struct ut_zrecord, avl_node);
	ut_expect_eq(zr->magic, ZMAGIC);

	return silofs_unconst(zr);
}

static const void *zrecord_getkey(const struct silofs_avl_node *an)
{
	const struct ut_zrecord *zr = avl_node_to_zrecord(an);

	return &zr->key;
}

static long zrecord_keycmp(const void *x, const void *y)
{
	const long znum_x = *((const long *)x);
	const long znum_y = *((const long *)y);

	return (znum_y > znum_x) - (znum_y < znum_x);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct ut_zrecord *zrecord_new(struct ut_env *ute, long num)
{
	struct ut_zrecord *zr;

	zr        = ut_malloc(ute, sizeof(*zr));
	zr->ute   = ute;
	zr->key   = num;
	zr->magic = ZMAGIC;
	silofs_avl_node_init(&zr->avl_node);

	return zr;
}

static struct silofs_avl_node *avl_node_of(struct ut_zrecord *zr)
{
	return &zr->avl_node;
}

static struct silofs_avl_node *new_node(struct ut_env *ute, long num)
{
	struct ut_zrecord *zr = zrecord_new(ute, num);

	return avl_node_of(zr);
}

static void check_node(const struct silofs_avl_node *x, long num)
{
	const struct ut_zrecord *zr = avl_node_to_zrecord(x);

	ut_expect_eq(zr->magic, ZMAGIC);
	ut_expect_eq(zr->key, num);
}

static void check_node_ge(const struct silofs_avl_node *x, long num)
{
	const struct ut_zrecord *zr = avl_node_to_zrecord(x);

	ut_expect_eq(zr->magic, ZMAGIC);
	ut_expect_ge(zr->key, num);
}

static void check_node_gt(const struct silofs_avl_node *x, long num)
{
	const struct ut_zrecord *zr = avl_node_to_zrecord(x);

	ut_expect_eq(zr->magic, ZMAGIC);
	ut_expect_gt(zr->key, num);
}

static void verify_node(struct silofs_avl_node *x, void *p)
{
	const struct ut_zrecord *zr = avl_node_to_zrecord(x);

	ut_expect_eq(zr->magic, ZMAGIC);
	ut_expect_null(p);
}

static const struct silofs_avl_node_functor node_functor = {
	.fn  = verify_node,
	.ctx = nullptr,
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool avl_isempty(const struct silofs_avl *avl)
{
	return silofs_avl_isempty(avl);
}

static struct silofs_avl *avl_new(struct ut_env *ute)
{
	struct silofs_avl *avl;

	avl = ut_malloc(ute, sizeof(*avl));
	silofs_avl_init(avl, zrecord_getkey, zrecord_keycmp, ute);
	ut_expect(avl_isempty(avl));
	return avl;
}

static void avl_done(struct silofs_avl *avl)
{
	ut_expect_eq(avl->size, 0);
	silofs_avl_fini(avl);
}

static struct ut_env *avl_ute(const struct silofs_avl *avl)
{
	return avl->userp;
}

static void
avl_insert_unique_(struct silofs_avl *avl, struct silofs_avl_node *an)
{
	int ret;

	ret = silofs_avl_insert_unique(avl, an);
	ut_expect_ok(ret);
	ret = silofs_avl_insert_unique(avl, an);
	ut_expect_err(ret, -1);
}

static void avl_insert_unique(struct silofs_avl *avl, long key)
{
	avl_insert_unique_(avl, new_node(avl_ute(avl), key));
}

static void avl_insert_replace(struct silofs_avl *avl, long key)
{
	struct silofs_avl_node *an;
	struct silofs_avl_node *an2;

	an = silofs_avl_find(avl, &key);
	check_node(an, key);

	an2 = silofs_avl_insert_replace(avl, new_node(avl_ute(avl), key));
	ut_expect_eq(an, an2);
}

static void avl_find_exists(const struct silofs_avl *avl, long key)
{
	const struct ut_zrecord *zr;
	const struct silofs_avl_node *an;

	an = silofs_avl_find(avl, &key);
	ut_expect_not_null(an);

	zr = avl_node_to_zrecord(an);
	ut_expect_eq(zr->key, key);
}

static void avl_find_non_exists(const struct silofs_avl *avl, long key)
{
	const struct silofs_avl_node *an;

	an = silofs_avl_find(avl, &key);
	ut_expect_null(an);
}

static void avl_find_unique(const struct silofs_avl *avl, long key)
{
	size_t cnt;
	const struct silofs_avl_node *an;

	an = silofs_avl_find_first(avl, &key);
	check_node(an, key);

	cnt = silofs_avl_count(avl, &key);
	ut_expect_eq(cnt, 1);
}

static void avl_remove_exists(struct silofs_avl *avl, long key)
{
	struct silofs_avl_node *an;

	an = silofs_avl_find(avl, &key);
	check_node(an, key);

	silofs_avl_remove(avl, an);

	an = silofs_avl_find(avl, &key);
	ut_expect_null(an);
}

static void avl_remove_range(struct silofs_avl *avl, long key1, long key2)
{
	struct silofs_avl_node *first      = nullptr;
	const struct silofs_avl_node *last = nullptr;

	silofs_assert_le(key1, key2);

	first = silofs_avl_lower_bound(avl, &key1);
	if (first != nullptr) {
		check_node_ge(first, key1);
	} else {
		first = silofs_avl_begin(avl);
	}
	last = silofs_avl_upper_bound(avl, &key2);
	if (last != nullptr) {
		check_node_gt(last, key2);
	} else {
		last = silofs_avl_end(avl);
	}
	ut_expect_not_null(first);
	ut_expect_not_null(last);
	silofs_avl_remove_range(avl, first, last, &node_functor);
}

static size_t avl_size(const struct silofs_avl *avl)
{
	return silofs_avl_size(avl);
}

static struct silofs_avl_node *avl_begin(const struct silofs_avl *avl)
{
	return silofs_avl_begin(avl);
}

static const struct silofs_avl_node *avl_end(const struct silofs_avl *avl)
{
	return silofs_avl_end(avl);
}

static struct silofs_avl_node *
avl_next(const struct silofs_avl *avl, const struct silofs_avl_node *x)
{
	return silofs_avl_next(avl, x);
}

static struct silofs_avl_node *
avl_prev(const struct silofs_avl *avl, const struct silofs_avl_node *x)
{
	return silofs_avl_prev(avl, x);
}

static long avl_min_key(const struct silofs_avl *avl)
{
	const struct ut_zrecord *zr;
	const struct silofs_avl_node *beg;

	ut_expect(avl->size > 0);

	beg = avl_begin(avl);
	ut_expect(beg != avl_end(avl));
	zr = avl_node_to_zrecord(beg);

	return zr->key;
}

static void
avl_iterate_range(const struct silofs_avl *avl, struct silofs_avl_node *beg,
		  const struct silofs_avl_node *end, size_t expected_cnt,
		  long key_beg, long step)
{
	size_t cnt;
	long key                    = key_beg;
	struct silofs_avl_node *itr = beg;

	cnt = 0;
	while (itr != end) {
		check_node(itr, key);

		key += step;
		cnt++;
		itr = avl_next(avl, itr);
	}
	ut_expect_eq(cnt, expected_cnt);

	while (itr != beg) {
		key -= step;
		cnt--;
		itr = avl_prev(avl, itr);
		check_node(itr, key);
	}
	ut_expect_eq(cnt, 0);
}

static void
avl_iterate_all(const struct silofs_avl *avl, long key_beg, long step)
{
	avl_iterate_range(avl, avl_begin(avl), avl_end(avl), avl_size(avl),
			  key_beg, step);
}

static void avl_iterate_seq(const struct silofs_avl *avl)
{
	avl_iterate_all(avl, avl_min_key(avl), 1);
}

static void avl_verify_integrity(const struct silofs_avl *avl)
{
	const struct silofs_avl_node *itr = avl_begin(avl);
	const struct silofs_avl_node *end = avl_end(avl);
	size_t size, cnt = 0;

	size = avl_size(avl);
	while (itr != end) {
		avl_node_to_zrecord(itr); /* verify node is valid */
		itr = avl_next(avl, itr);
		cnt++;
	}
	ut_expect_eq(cnt, size);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_avl_simple_(struct ut_env *ute, size_t cnt, long key_base, long step)
{
	struct silofs_avl *avl;
	long key;

	avl = avl_new(ute);
	key = key_base;
	for (size_t i = 0; i < cnt; ++i) {
		avl_insert_unique(avl, key);
		avl_iterate_all(avl, key_base, step);
		avl_find_unique(avl, key);
		key += step;
	}
	key = key_base;
	for (size_t i = 0; i < cnt; ++i) {
		avl_insert_replace(avl, key);
		key += step;
	}
	key = key_base;
	for (size_t i = 0; i < cnt; ++i) {
		avl_find_exists(avl, key);
		key += step;
	}
	key = key_base;
	for (size_t i = 0; i < cnt; ++i) {
		avl_find_unique(avl, key);
		avl_remove_exists(avl, key);
		key += step;
	}
	avl_done(avl);
}

static void ut_avl_simple(struct ut_env *ute)
{
	ut_avl_simple_(ute, 1, 0, 1);
	ut_avl_simple_(ute, 10, 0, 1);
	ut_avl_simple_(ute, 1111, 111, 11);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
ut_avl_mixed_(struct ut_env *ute, size_t cnt, long key_base, long step)
{
	struct silofs_avl *avl;
	long key;

	avl = avl_new(ute);
	key = key_base;
	for (size_t i = 0; i < cnt; ++i) {
		avl_insert_unique(avl, key);
		key += (2 * step);
	}
	key = key_base;
	for (size_t i = 0; i < cnt; ++i) {
		avl_remove_exists(avl, key);
		key += step;
		avl_insert_unique(avl, key);
		key += step;
	}
	key = key_base;
	for (size_t i = 0; i < cnt; ++i) {
		key += step;
		avl_remove_exists(avl, key);
		key += step;
		avl_find_non_exists(avl, key);
	}
	avl_done(avl);
}

static void ut_avl_mixed(struct ut_env *ute)
{
	ut_avl_mixed_(ute, 8, 1, 2);
	ut_avl_mixed_(ute, 1111, 111, 11);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
avl_populate_keys(struct silofs_avl *avl, const long *keys, size_t cnt)
{
	size_t size;

	for (size_t i = 0; i < cnt; ++i) {
		avl_insert_unique(avl, keys[i]);
	}
	size = avl_size(avl);
	ut_expect_eq(size, cnt);
	avl_verify_integrity(avl);
}

static long *random_keys(struct ut_env *ute, size_t cnt, long base)
{
	return ut_randseq(ute, cnt, base);
}

static void ut_avl_random_(struct ut_env *ute, size_t cnt)
{
	constexpr long base = 100000;
	struct silofs_avl *avl;
	const long *keys;
	long key;

	keys = random_keys(ute, cnt, base);
	avl  = avl_new(ute);
	avl_populate_keys(avl, keys, cnt);

	for (size_t i = 0; i < cnt; ++i) {
		key = base + (long)i;
		avl_find_exists(avl, key);
	}
	avl_iterate_seq(avl);

	for (size_t i = 0; i < cnt; i += 2) {
		key = keys[i];
		avl_remove_exists(avl, key);
	}
	for (size_t i = 1; i < cnt; i += 2) {
		key = keys[i];
		avl_remove_exists(avl, key);
	}
	avl_done(avl);
}

static void ut_avl_random(struct ut_env *ute)
{
	ut_avl_random_(ute, 10);
	ut_avl_random_(ute, 1000);
	ut_avl_random_(ute, 100000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_avl_remove_range_(struct ut_env *ute, size_t cnt)
{
	struct silofs_avl *avl;
	const long key_last = (long)cnt - 1;
	const long *keys;
	long key1, key2;
	size_t size;

	avl  = avl_new(ute);
	keys = random_keys(ute, cnt, 0);
	avl_populate_keys(avl, keys, cnt);

	size = avl_size(avl);
	ut_expect_eq(size, cnt);

	key1 = 1;
	key2 = 1;
	avl_remove_range(avl, key1, key2);
	size = avl_size(avl);
	ut_expect_eq(size, cnt - 1);

	key1 = 1;
	key2 = 3;
	avl_remove_range(avl, key1, key2);
	size = avl_size(avl);
	ut_expect_eq(size, cnt - 3);

	key1 = (long)cnt / 3;
	key2 = 2 * key1;
	avl_remove_range(avl, key1, key2);

	key1 = key2 + 1;
	key2 = key_last - 1;
	avl_remove_range(avl, key1, key2);

	key1 = 1;
	key2 = 3;
	avl_remove_range(avl, key1, key2);

	key1 = 0;
	key2 = key_last + 1;
	avl_remove_range(avl, key1, key2);
	avl_done(avl);
}

static void ut_avl_remove_range(struct ut_env *ute)
{
	ut_avl_remove_range_(ute, 10);
	ut_avl_remove_range_(ute, 10000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_avl_delete_rebalance(struct ut_env *ute)
{
	constexpr long keys[] = { 50, 25, 75, 10, 30, 60, 80, 5, 15, 27 };
	struct silofs_avl *avl;

	/*
	 * Tree structure with 10 nodes for rebalancing tests during deletion.
	 *
	 * This tests various deletion scenarios including:
	 * - Leaf node deletions
	 * - Internal node deletions requiring rebalancing
	 * - Left-heavy and right-heavy subtree rebalancing
	 */
	avl = avl_new(ute);
	avl_populate_keys(avl, keys, UT_ARRAY_SIZE(keys));

	/* Delete leaf nodes */
	avl_remove_exists(avl, 5);
	avl_verify_integrity(avl);

	avl_remove_exists(avl, 15);
	avl_verify_integrity(avl);

	/* Delete internal node */
	avl_remove_exists(avl, 10);
	avl_verify_integrity(avl);

	avl_remove_exists(avl, 27);
	avl_verify_integrity(avl);

	avl_remove_exists(avl, 30);
	avl_verify_integrity(avl);

	/* Verify remaining nodes */
	avl_find_exists(avl, 25);
	avl_find_exists(avl, 50);
	avl_find_exists(avl, 60);
	avl_find_exists(avl, 75);
	avl_find_exists(avl, 80);

	/* Clean up remaining nodes */
	avl_remove_exists(avl, 25);
	avl_remove_exists(avl, 60);
	avl_remove_exists(avl, 80);
	avl_remove_exists(avl, 75);
	avl_remove_exists(avl, 50);

	ut_expect_eq(avl_size(avl), 0);
	avl_done(avl);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_avl_delete_balanced_(struct ut_env *ute, size_t height)
{
	const size_t cnt = (1UL << height) - 1; /* 2^height - 1 nodes */
	struct silofs_avl *avl;
	const long *keys;

	keys = ut_randseq(ute, cnt, 1000);
	avl  = avl_new(ute);
	avl_populate_keys(avl, keys, cnt);

	for (size_t i = 0; i < cnt; ++i) {
		avl_remove_exists(avl, keys[i]);
		avl_verify_integrity(avl);
	}

	ut_expect_eq(avl_size(avl), 0);
	avl_done(avl);
}

static void ut_avl_delete_balanced(struct ut_env *ute)
{
	ut_avl_delete_balanced_(ute, 4); /* 15 nodes */
	ut_avl_delete_balanced_(ute, 5); /* 31 nodes */
	ut_avl_delete_balanced_(ute, 6); /* 63 nodes */
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_avl_delete_cascade(struct ut_env *ute)
{
	struct silofs_avl *avl = avl_new(ute);

	/* Build a left-heavy tree that will require right rotation at root
	 * when we delete from the right side:
	 *        4
	 *       / \
	 *      2   5
	 *     / \
	 *    1   3
	 */
	avl_insert_unique(avl, 4);
	avl_insert_unique(avl, 2);
	avl_insert_unique(avl, 5);
	avl_insert_unique(avl, 1);
	avl_insert_unique(avl, 3);

	avl_remove_exists(avl, 5);
	avl_verify_integrity(avl);
	avl_find_exists(avl, 1);
	avl_find_exists(avl, 2);
	avl_find_exists(avl, 3);
	avl_find_exists(avl, 4);

	avl_remove_exists(avl, 1);
	avl_remove_exists(avl, 2);
	avl_remove_exists(avl, 3);
	avl_remove_exists(avl, 4);

	avl_done(avl);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_avl_alternating_(struct ut_env *ute, size_t cnt)
{
	struct silofs_avl *avl;
	long key;

	avl = avl_new(ute);
	for (size_t i = 0; i < cnt; ++i) {
		avl_insert_unique(avl, (long)i);
	}
	ut_expect_eq(avl_size(avl), cnt);

	/* alternating delete and insert pattern */
	for (size_t i = 0; i < cnt / 2; ++i) {
		key = (long)(cnt / 2 + i);
		avl_remove_exists(avl, key);

		key = (long)(cnt + i);
		avl_insert_unique(avl, key);

		avl_verify_integrity(avl);
	}

	for (size_t i = 0; i < cnt; ++i) {
		key = (long)i;
		if (i >= cnt / 2) {
			key = (long)(cnt / 2 + i);
		}
		if (silofs_avl_find(avl, &key) != nullptr) {
			avl_remove_exists(avl, key);
		}
	}

	avl_done(avl);
}

static void ut_avl_alternating(struct ut_env *ute)
{
	ut_avl_alternating_(ute, 20);
	ut_avl_alternating_(ute, 200);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_avl_zigzag_delete(struct ut_env *ute)
{
	constexpr long keys[] = {
		50, 25, 75, 10, 30, 60, 80, 5, 15, 27, 35, 55, 65, 77, 85, 3,
	};
	struct silofs_avl *avl;

	/*
	 * Zigzag deletion test with 16 nodes.
	 * Tests various rotation patterns during deletion:
	 * - Left-left rotations
	 * - Right-right rotations
	 * - Left-right (zigzag) rotations
	 * - Right-left (zigzag) rotations
	 */
	avl = avl_new(ute);
	avl_populate_keys(avl, keys, UT_ARRAY_SIZE(keys));

	/* Left-left rotation */
	avl_remove_exists(avl, 3);
	avl_verify_integrity(avl);

	avl_remove_exists(avl, 5);
	avl_verify_integrity(avl);

	/* Right-right rotation */
	avl_remove_exists(avl, 85);
	avl_verify_integrity(avl);

	avl_remove_exists(avl, 77);
	avl_verify_integrity(avl);

	/* Left-right (zigzag) rotation */
	avl_remove_exists(avl, 35);
	avl_verify_integrity(avl);

	avl_remove_exists(avl, 27);
	avl_verify_integrity(avl);

	/* Right-left (zigzag) rotation */
	avl_remove_exists(avl, 55);
	avl_verify_integrity(avl);

	avl_remove_exists(avl, 65);
	avl_verify_integrity(avl);

	/* Verify remaining nodes exist */
	avl_find_exists(avl, 10);
	avl_find_exists(avl, 15);
	avl_find_exists(avl, 25);
	avl_find_exists(avl, 30);
	avl_find_exists(avl, 50);
	avl_find_exists(avl, 60);
	avl_find_exists(avl, 75);
	avl_find_exists(avl, 80);

	/* Clean up remaining nodes */
	avl_remove_exists(avl, 10);
	avl_remove_exists(avl, 15);
	avl_remove_exists(avl, 25);
	avl_remove_exists(avl, 30);
	avl_remove_exists(avl, 50);
	avl_remove_exists(avl, 60);
	avl_remove_exists(avl, 75);
	avl_remove_exists(avl, 80);

	ut_expect_eq(avl_size(avl), 0);
	avl_done(avl);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_avl_root_replace(struct ut_env *ute)
{
	constexpr long keys[] = { 50, 25, 75, 10, 30, 60, 80, 5, 15, 27 };
	struct silofs_avl *avl;

	/*
	 * Root replacement test with 10 nodes.
	 * Tests root deletions and replacements to ensure
	 * the tree maintains balance and integrity after each root change.
	 * This exercises the successor/predecessor selection logic
	 * and verifies proper parent-child relationship updates.
	 */
	avl = avl_new(ute);
	avl_populate_keys(avl, keys, UT_ARRAY_SIZE(keys));

	/* First root deletion - 50 should be replaced */
	avl_remove_exists(avl, 50);
	avl_verify_integrity(avl);

	/* Verify tree structure after first root replacement */
	avl_find_exists(avl, 25);
	avl_find_exists(avl, 60); /* new root should be 60 (successor of 50) */
	avl_find_exists(avl, 75);

	/* Second root deletion */
	avl_remove_exists(avl, 60);
	avl_verify_integrity(avl);

	/* Delete more nodes */
	avl_remove_exists(avl, 5);
	avl_verify_integrity(avl);

	avl_remove_exists(avl, 15);
	avl_verify_integrity(avl);

	avl_remove_exists(avl, 10);
	avl_verify_integrity(avl);

	avl_remove_exists(avl, 27);
	avl_verify_integrity(avl);

	/* Clean up remaining nodes */
	avl_remove_exists(avl, 25);
	avl_remove_exists(avl, 30);
	avl_remove_exists(avl, 75);
	avl_remove_exists(avl, 80);

	ut_expect_eq(avl_size(avl), 0);
	avl_done(avl);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_avl_bounds(struct ut_env *ute)
{
	struct silofs_avl *avl;
	struct silofs_avl_node *node;
	const long keys[] = { 10, 20, 30, 40, 50, 60, 70, 80, 90, 100 };

	avl = avl_new(ute);
	avl_populate_keys(avl, keys, UT_ARRAY_SIZE(keys));

	/* Test lower_bound - finds first element >= key */
	node = silofs_avl_lower_bound(avl, &(long){ 25 });
	check_node(node, 30);

	node = silofs_avl_lower_bound(avl, &(long){ 30 });
	check_node(node, 30);

	node = silofs_avl_lower_bound(avl, &(long){ 5 });
	check_node(node, 10);

	node = silofs_avl_lower_bound(avl, &(long){ 95 });
	check_node(node, 100);

	node = silofs_avl_lower_bound(avl, &(long){ 105 });
	ut_expect_null(node);

	/* Test upper_bound - finds first element > key */
	node = silofs_avl_upper_bound(avl, &(long){ 25 });
	check_node(node, 30);

	node = silofs_avl_upper_bound(avl, &(long){ 30 });
	check_node(node, 40);

	node = silofs_avl_upper_bound(avl, &(long){ 5 });
	check_node(node, 10);

	node = silofs_avl_upper_bound(avl, &(long){ 90 });
	check_node(node, 100);

	node = silofs_avl_upper_bound(avl, &(long){ 100 });
	ut_expect_null(node);

	/* Clean up */
	for (size_t i = 0; i < UT_ARRAY_SIZE(keys); ++i) {
		avl_remove_exists(avl, keys[i]);
	}
	avl_done(avl);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_avl_empty_operations(struct ut_env *ute)
{
	constexpr long keys[] = {
		10, 20, 30, 40, 50, 60, 70, 80, 90, 100,
	};
	struct silofs_avl *avl;
	struct silofs_avl_node *an;
	const struct silofs_avl_node *end;
	size_t size;

	avl = avl_new(ute);

	ut_expect(avl_isempty(avl));
	size = avl_size(avl);
	ut_expect_eq(size, 0);

	for (size_t i = 0; i < UT_ARRAY_SIZE(keys); ++i) {
		an = silofs_avl_find(avl, &keys[i]);
		ut_expect_null(an);

		an = silofs_avl_find_first(avl, &keys[i]);
		ut_expect_null(an);

		an = silofs_avl_lower_bound(avl, &keys[i]);
		ut_expect_null(an);

		an = silofs_avl_upper_bound(avl, &keys[i]);
		ut_expect_null(an);

		ut_expect_eq(silofs_avl_count(avl, &keys[i]), 0);
	}

	an  = avl_begin(avl);
	end = avl_end(avl);
	ut_expect_eq(an, end);

	avl_populate_keys(avl, keys, UT_ARRAY_SIZE(keys));
	ut_expect_eq(avl_size(avl), UT_ARRAY_SIZE(keys));

	for (size_t i = 0; i < UT_ARRAY_SIZE(keys); ++i) {
		avl_remove_exists(avl, keys[i]);
	}
	size = avl_size(avl);
	ut_expect_eq(size, 0);

	avl_done(avl);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_avl_single_node_(struct ut_env *ute, size_t cnt)
{
	struct silofs_avl *avl;
	struct silofs_avl_node *an, *nxt;
	const struct silofs_avl_node *end;
	const long *keys;
	size_t size;

	keys = random_keys(ute, cnt, 0);
	avl  = avl_new(ute);
	for (size_t i = 0; i < cnt; ++i) {
		avl_insert_unique(avl, keys[i]);
		size = avl_size(avl);
		ut_expect_eq(size, 1);

		avl_find_exists(avl, keys[i]);
		avl_find_unique(avl, keys[i]);

		an = avl_begin(avl);
		check_node(an, keys[i]);
		nxt = avl_next(avl, an);
		end = avl_end(avl);
		ut_expect_eq(nxt, end);

		an = silofs_avl_lower_bound(avl, &keys[i]);
		check_node(an, keys[i]);

		an = silofs_avl_upper_bound(avl, &keys[i]);
		ut_expect_null(an);

		avl_remove_exists(avl, keys[i]);
		size = avl_size(avl);
		ut_expect_eq(size, 0);
	}
	avl_done(avl);
}

static void ut_avl_single_node(struct ut_env *ute)
{
	ut_avl_single_node_(ute, 100);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_avl_sequential_insert_(struct ut_env *ute, size_t cnt)
{
	struct silofs_avl *avl = avl_new(ute);

	for (size_t i = 0; i < cnt; ++i) {
		avl_insert_unique(avl, (long)i);
		avl_verify_integrity(avl);
	}
	for (size_t i = 0; i < cnt; ++i) {
		avl_find_exists(avl, (long)i);
	}
	for (size_t i = cnt; i > 0; --i) {
		avl_remove_exists(avl, (long)(i - 1));
		avl_verify_integrity(avl);
	}
	avl_done(avl);
}

static void ut_avl_sequential_insert(struct ut_env *ute)
{
	ut_avl_sequential_insert_(ute, 100);
	ut_avl_sequential_insert_(ute, 1000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_avl_reverse_sequential_insert_(struct ut_env *ute, size_t cnt)
{
	struct silofs_avl *avl = avl_new(ute);

	for (size_t i = cnt; i > 0; --i) {
		avl_insert_unique(avl, (long)(i - 1));
		avl_verify_integrity(avl);
	}
	for (size_t i = 0; i < cnt; ++i) {
		avl_find_exists(avl, (long)i);
	}
	for (size_t i = 0; i < cnt; ++i) {
		avl_remove_exists(avl, (long)i);
		avl_verify_integrity(avl);
	}
	avl_done(avl);
}

static void ut_avl_reverse_sequential_insert(struct ut_env *ute)
{
	ut_avl_reverse_sequential_insert_(ute, 100);
	ut_avl_reverse_sequential_insert_(ute, 1000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_avl_insert_replace_pattern(struct ut_env *ute)
{
	constexpr long keys[] = {
		50, 25, 75, 10, 30, 60, 80, 5, 15, 27,
	};
	struct silofs_avl_node *an_old, *an_new, *an_ret;
	struct silofs_avl *avl;
	size_t size;

	avl = avl_new(ute);
	avl_populate_keys(avl, keys, UT_ARRAY_SIZE(keys));

	for (size_t i = 0; i < UT_ARRAY_SIZE(keys); ++i) {
		an_old = silofs_avl_find(avl, &keys[i]);
		ut_expect_not_null(an_old);

		an_new = new_node(ute, keys[i]);
		an_ret = silofs_avl_insert_replace(avl, an_new);
		ut_expect_eq(an_old, an_ret);

		avl_verify_integrity(avl);
		size = avl_size(avl);
		ut_expect_eq(size, UT_ARRAY_SIZE(keys));
	}
	for (size_t round = 0; round < 3; ++round) {
		for (size_t i = 0; i < UT_ARRAY_SIZE(keys); ++i) {
			an_old = silofs_avl_find(avl, &keys[i]);
			an_new = new_node(ute, keys[i]);
			an_ret = silofs_avl_insert_replace(avl, an_new);
			ut_expect_eq(an_old, an_ret);
		}
		avl_verify_integrity(avl);
	}
	for (size_t i = 0; i < UT_ARRAY_SIZE(keys); ++i) {
		avl_remove_exists(avl, keys[i]);
	}
	size = avl_size(avl);
	ut_expect_eq(size, 0);
	avl_done(avl);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_avl_iteration_forward_backward(struct ut_env *ute)
{
	const long keys[] = {
		50, 25, 75, 10, 30, 60, 80, 5, 15, 27,
	};
	const long keys_sorted[] = {
		5, 10, 15, 25, 27, 30, 50, 60, 75, 80,
	};
	const struct silofs_avl_node *an;
	struct silofs_avl *avl;
	size_t idx;

	avl = avl_new(ute);
	avl_populate_keys(avl, keys, UT_ARRAY_SIZE(keys));

	idx = 0;
	an = avl_begin(avl);
	while (an != avl_end(avl)) {
		ut_expect_lt(idx, UT_ARRAY_SIZE(keys_sorted));
		if (idx >= UT_ARRAY_SIZE(keys_sorted)) {
			break; /* make clang-scan happy */
		}
		check_node(an, keys_sorted[idx]);
		an = avl_next(avl, an);
		idx++;
	}
	ut_expect_eq(idx, UT_ARRAY_SIZE(keys_sorted));

	/* backward iteration from end */
	an = avl_end(avl);
	while (an != avl_begin(avl)) {
		ut_expect_gt(idx, 0);
		if (idx == 0) {
			break; /* make clang-scan happy */
		}
		idx--;
		an = avl_prev(avl, an);
		check_node(an, keys_sorted[idx]);
	}
	ut_expect_eq(idx, 0);

	/* partial forward iteration */
	idx = 0;
	an  = avl_begin(avl);
	for (size_t i = 0; i < 7 && an != avl_end(avl); ++i) {
		ut_expect_lt(idx, UT_ARRAY_SIZE(keys_sorted));
		if (idx >= UT_ARRAY_SIZE(keys_sorted)) {
			break; /* make clang-scan happy */
		}
		check_node(an, keys_sorted[idx]);
		an = avl_next(avl, an);
		idx++;
	}

	/* partial backward iteration */
	for (size_t i = 0; i < 7 && an != avl_begin(avl); ++i) {
		ut_expect_gt(idx, 0);
		idx -= 1;
		an   = avl_prev(avl, an);
		if (idx < UT_ARRAY_SIZE(keys_sorted)) {
			/* make clang-scan happy */
			check_node(an, keys_sorted[idx]);
		}
	}

	/* cleanup */
	for (size_t i = 0; i < UT_ARRAY_SIZE(keys); ++i) {
		avl_remove_exists(avl, keys[i]);
	}
	avl_done(avl);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_avl_stress_rotations_(struct ut_env *ute, size_t cnt)
{
	struct silofs_avl *avl;
	const long *keys;
	size_t size;

	keys = ut_randseq(ute, cnt, 10000);
	avl  = avl_new(ute);
	avl_populate_keys(avl, keys, cnt);

	avl_verify_integrity(avl);

	/* remove every third element */
	for (size_t i = 0; i < cnt; i += 3) {
		avl_remove_exists(avl, keys[i]);
		avl_verify_integrity(avl);
	}

	/* remove every second remaining element */
	for (size_t i = 1; i < cnt; i += 3) {
		avl_remove_exists(avl, keys[i]);
		avl_verify_integrity(avl);
	}

	/* remove remaining elements */
	for (size_t i = 2; i < cnt; i += 3) {
		avl_remove_exists(avl, keys[i]);
		avl_verify_integrity(avl);
	}

	size = avl_size(avl);
	ut_expect_eq(size, 0);
	avl_done(avl);
}

static void ut_avl_stress_rotations(struct ut_env *ute)
{
	ut_avl_stress_rotations_(ute, 100);
	ut_avl_stress_rotations_(ute, 1000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_avl_min_max_operations(struct ut_env *ute)
{
	constexpr long keys[]   = { 50, 25, 75, 10, 30, 60, 80, 5, 15, 27 };
	constexpr long sorted[] = { 5, 10, 15, 25, 27, 30, 50, 60, 75, 80 };
	struct silofs_avl_node *an;
	struct silofs_avl *avl;

	avl = avl_new(ute);
	avl_populate_keys(avl, keys, UT_ARRAY_SIZE(keys));

	/* test minimum (leftmost) */
	an = avl_begin(avl);
	check_node(an, sorted[0]);

	/* remove minimum and check new minimum */
	avl_remove_exists(avl, sorted[0]);
	an = avl_begin(avl);
	check_node(an, sorted[1]);

	avl_remove_exists(avl, sorted[1]);
	an = avl_begin(avl);
	check_node(an, sorted[2]);

	/* test that we can iterate to maximum */
	while (avl_next(avl, an) != avl_end(avl)) {
		an = avl_next(avl, an);
	}
	check_node(an, sorted[UT_ARRAY_SIZE(sorted) - 1]); /* maximum */

	/* remove maximum and verify */
	avl_remove_exists(avl, sorted[UT_ARRAY_SIZE(sorted) - 1]);
	an = avl_begin(avl);
	while (avl_next(avl, an) != avl_end(avl)) {
		an = avl_next(avl, an);
	}
	check_node(an, sorted[UT_ARRAY_SIZE(sorted) - 2]); /* new maximum */

	avl_remove_exists(avl, sorted[UT_ARRAY_SIZE(sorted) - 2]);
	an = avl_begin(avl);
	while (avl_next(avl, an) != avl_end(avl)) {
		an = avl_next(avl, an);
	}
	check_node(an, sorted[UT_ARRAY_SIZE(sorted) - 3]); /* new maximum */

	/* clean up remaining nodes */
	for (size_t i = 2; i < UT_ARRAY_SIZE(sorted) - 2; ++i) {
		avl_remove_exists(avl, sorted[i]);
	}

	avl_done(avl);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST1(ut_avl_simple),
	UT_DEFTEST1(ut_avl_mixed),
	UT_DEFTEST(ut_avl_random),
	UT_DEFTEST(ut_avl_remove_range),
	UT_DEFTEST(ut_avl_delete_rebalance),
	UT_DEFTEST(ut_avl_delete_balanced),
	UT_DEFTEST(ut_avl_delete_cascade),
	UT_DEFTEST(ut_avl_alternating),
	UT_DEFTEST(ut_avl_zigzag_delete),
	UT_DEFTEST(ut_avl_root_replace),
	UT_DEFTEST(ut_avl_bounds),
	UT_DEFTEST(ut_avl_empty_operations),
	UT_DEFTEST(ut_avl_single_node),
	UT_DEFTEST(ut_avl_sequential_insert),
	UT_DEFTEST(ut_avl_reverse_sequential_insert),
	UT_DEFTEST(ut_avl_insert_replace_pattern),
	UT_DEFTEST(ut_avl_iteration_forward_backward),
	UT_DEFTEST(ut_avl_stress_rotations),
	UT_DEFTEST(ut_avl_min_max_operations),
};

const struct ut_testdefs ut_tdefs_avl = UT_MKTESTS(ut_local_tests);
