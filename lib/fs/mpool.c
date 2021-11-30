/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/fs/mpool.h>
#include <silofs/fs/private.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>


#define MPC_MAGIC               0xA119CE6D2BL
#define MT_MAGIC                0x1DD8223104L
#define MPC_SIZE                SILOFS_BK_SIZE
#define MPC_TAIL_SIZE           (64)
#define MOBJ_SIZE_MIN \
	(sizeof(struct silofs_mobj_head) + sizeof(struct silofs_mobj_tail))
#define NMH_IN_MPC \
	((MPC_SIZE - MPC_TAIL_SIZE) / MOBJ_SIZE_MIN)


struct silofs_mobj_head {
	struct silofs_list_head lh;
} silofs_aligned16;


struct silofs_mobj_tail {
	struct silofs_mpool_chnk *mpc;
	long magic;
} silofs_aligned16;


struct silofs_mpc_tail {
	long   magic;
	size_t nused;
	int8_t pad[48];
} silofs_aligned64;

union silofs_mpc_objs {
	uint8_t d[MPC_SIZE - MPC_TAIL_SIZE];
	struct silofs_mobj_head mh[NMH_IN_MPC];
};

struct silofs_mpool_chnk {
	union silofs_mpc_objs  objs;
	struct silofs_mpc_tail tail;
};


static void mpool_init_alloc_if(struct silofs_mpool *mpool);
static void mpool_fini_alloc_if(struct silofs_mpool *mpool);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void mpc_init(struct silofs_mpool_chnk *mpc)
{
	mpc->tail.nused = 0;
	mpc->tail.magic = MPC_MAGIC;
}

static void mpc_fini(struct silofs_mpool_chnk *mpc)
{
	silofs_assert_eq(mpc->tail.nused, 0);
	mpc->tail.nused = ~0UL;
	mpc->tail.magic = ~MPC_MAGIC;
}

static void mpc_inc_nused(struct silofs_mpool_chnk *mpc)
{
	silofs_assert_eq(mpc->tail.magic, MPC_MAGIC);
	mpc->tail.nused++;
}

static void mpc_dec_nused(struct silofs_mpool_chnk *mpc)
{
	silofs_assert_eq(mpc->tail.magic, MPC_MAGIC);
	silofs_assert_gt(mpc->tail.nused, 0);
	mpc->tail.nused--;
}

static bool mpc_is_unused(const struct silofs_mpool_chnk *mpc)
{
	return (mpc->tail.nused == 0);
}

static struct silofs_mobj_head *mpc_beg(struct silofs_mpool_chnk *mpc)
{
	return mpc->objs.mh;
}

static const struct silofs_mobj_head *
mpc_end(const struct silofs_mpool_chnk *mpc)
{
	return mpc->objs.mh + ARRAY_SIZE(mpc->objs.mh);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t mpq_obj_size_nheads(size_t obj_size)
{
	const struct silofs_mobj_head *mh = NULL;

	return (obj_size + sizeof(*mh) - 1) / sizeof(*mh);
}

static size_t mpq_obj_nheads(const struct silofs_mpoolq *mpq)
{
	return mpq_obj_size_nheads(mpq->mpq_obj_size);
}

static size_t mpq_obj_nheads_full(const struct silofs_mpoolq *mpq)
{
	STATICASSERT_EQ(sizeof(struct silofs_mobj_head),
	                sizeof(struct silofs_mobj_tail));

	return mpq_obj_nheads(mpq) + 1;
}

static void mpq_init(struct silofs_mpoolq *mpq,
                     struct silofs_qalloc *qal, size_t obj_size)
{
	listq_init(&mpq->mpq_fls);
	mpq->mpq_qal = qal;
	mpq->mpq_obj_size = obj_size;
}

static void mpq_fini(struct silofs_mpoolq *mpq)
{
	listq_fini(&mpq->mpq_fls);
	mpq->mpq_qal = NULL;
	mpq->mpq_obj_size = 0;
}

static struct silofs_mpool_chnk *mpq_new_mpc(struct silofs_mpoolq *mpq)
{
	struct silofs_mpool_chnk *mpc;

	STATICASSERT_EQ(sizeof(mpc->tail), MPC_TAIL_SIZE);
	STATICASSERT_LE(sizeof(*mpc), MPC_SIZE);

	mpc = silofs_qalloc_malloc(mpq->mpq_qal, sizeof(*mpc));
	if (mpc != NULL) {
		mpc_init(mpc);
	}
	return mpc;
}

static void mpq_del_mpc(struct silofs_mpoolq *mpq,
                        struct silofs_mpool_chnk *mpc)
{
	mpc_fini(mpc);
	silofs_qalloc_free(mpq->mpq_qal, mpc, sizeof(*mpc));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_mobj_head *lh_to_mh(struct silofs_list_head *lh)
{
	struct silofs_mobj_head *mh;

	mh = container_of(lh, struct silofs_mobj_head, lh);
	return mh;
}

static struct silofs_list_head *mh_to_lh(struct silofs_mobj_head *mh)
{
	return &mh->lh;
}

static struct silofs_mobj_tail *
mpq_tail_of(const struct silofs_mpoolq *mpq, struct silofs_mobj_head *mh)
{
	void *tail;
	const size_t nheads = mpq_obj_nheads(mpq);

	tail = mh + nheads;
	return tail;
}

static struct silofs_mpool_chnk *
mpq_mh_to_mpc(const struct silofs_mpoolq *mpq, struct silofs_mobj_head *mh)
{
	struct silofs_mpool_chnk *mpc;
	struct silofs_mobj_tail *mt = mpq_tail_of(mpq, mh);

	mpc = mt->mpc;
	silofs_assert_not_null(mpc);
	silofs_assert_eq(mt->magic, MT_MAGIC);
	silofs_assert_eq(mpc->tail.magic, MPC_MAGIC);
	silofs_assert_le(mpc->tail.nused, ARRAY_SIZE(mpc->objs.mh));

	return mpc;
}

static struct silofs_mobj_head *mpq_pop_obj(struct silofs_mpoolq *mpq)
{
	struct silofs_list_head *lh;
	struct silofs_mobj_head *mh = NULL;

	lh = listq_pop_front(&mpq->mpq_fls);
	if (lh != NULL) {
		mh = lh_to_mh(lh);
	}
	return mh;
}

static void mpq_push_obj(struct silofs_mpoolq *mpq,
                         struct silofs_mobj_head *mh)
{
	listq_push_back(&mpq->mpq_fls, mh_to_lh(mh));
}

static void mpq_remove_obj(struct silofs_mpoolq *mpq,
                           struct silofs_mobj_head *mh)
{
	listq_remove(&mpq->mpq_fls, mh_to_lh(mh));
}

static void mpq_add_bfree_chnk(struct silofs_mpoolq *mpq,
                               struct silofs_mpool_chnk *mpc)
{
	size_t step;
	struct silofs_mobj_tail *mt = NULL;
	struct silofs_mobj_head *mh = mpc_beg(mpc);
	const struct silofs_mobj_head *end = mpc_end(mpc);

	step = mpq_obj_nheads_full(mpq);
	while (mh < end) {
		mt = mpq_tail_of(mpq, mh);
		mt->mpc = mpc;
		mt->magic = MT_MAGIC;
		mpq_push_obj(mpq, mh);
		mh += step;
	}
}

static void mpq_remove_bfree_chnk(struct silofs_mpoolq *mpq,
                                  struct silofs_mpool_chnk *mpc)
{
	size_t step;
	struct silofs_mobj_tail *mt = NULL;
	struct silofs_mobj_head *mh = mpc_beg(mpc);
	const struct silofs_mobj_head *end = mpc_end(mpc);

	step = mpq_obj_nheads_full(mpq);
	while (mh < end) {
		mt = mpq_tail_of(mpq, mh);
		mpq_remove_obj(mpq, mh);
		mt->mpc = NULL;
		mh += step;
	}
}

static int mpq_more_bfree(struct silofs_mpoolq *mpq)
{
	struct silofs_mpool_chnk *mpc;

	mpc = mpq_new_mpc(mpq);
	if (mpc == NULL) {
		return -ENOMEM;
	}
	mpq_add_bfree_chnk(mpq, mpc);
	return 0;
}

static void mpq_less_bfree(struct silofs_mpoolq *mpq,
                           struct silofs_mpool_chnk *mpc)
{
	mpq_remove_bfree_chnk(mpq, mpc);
	mpq_del_mpc(mpq, mpc);
}


static struct silofs_mobj_head *mpq_alloc_obj(struct silofs_mpoolq *mpq)
{
	struct silofs_mobj_head *mh;
	struct silofs_mpool_chnk *mpc;

	mh = mpq_pop_obj(mpq);
	if (mh != NULL) {
		mpc = mpq_mh_to_mpc(mpq, mh);
		mpc_inc_nused(mpc);
	}
	return mh;
}

static void mpq_free_obj(struct silofs_mpoolq *mpq,
                         struct silofs_mobj_head *mh)
{
	struct silofs_mpool_chnk *mpc = mpq_mh_to_mpc(mpq, mh);

	mpc_dec_nused(mpc);
	mpq_push_obj(mpq, mh);

	if (mpc_is_unused(mpc)) {
		mpq_less_bfree(mpq, mpc);
	}
}


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int cmp_size(const void *p1, const void *p2)
{
	const size_t *sz1 = p1;
	const size_t *sz2 = p2;

	return (int)(*sz1) - (int)(*sz2);
}

void silofs_mpool_init(struct silofs_mpool *mp, struct silofs_qalloc *qal)
{
	size_t slot = 0;
	size_t prv_size = 0;
	size_t obj_size[] = {
		sizeof(struct silofs_ubk_info),
		sizeof(struct silofs_vbk_info),
		sizeof(struct silofs_spnode_info),
		sizeof(struct silofs_spleaf_info),
		sizeof(struct silofs_itnode_info),
		sizeof(struct silofs_inode_info),
		sizeof(struct silofs_xanode_info),
		sizeof(struct silofs_symval_info),
		sizeof(struct silofs_dnode_info),
		sizeof(struct silofs_finode_info),
		sizeof(struct silofs_fileaf_info),
	};

	STATICASSERT_EQ(ARRAY_SIZE(mp->mpq), ARRAY_SIZE(obj_size));

	qsort(obj_size, ARRAY_SIZE(obj_size), sizeof(obj_size[0]), cmp_size);

	silofs_memzero(mp->mpq, sizeof(mp->mpq));
	for (size_t i = 0; i < ARRAY_SIZE(obj_size); ++i) {
		if (obj_size[i] > prv_size) {
			mpq_init(&mp->mpq[slot++], qal, obj_size[i]);
			prv_size = obj_size[i];
		}
	}
	mpool_init_alloc_if(mp);
	mp->mp_qal = qal;
	mp->mp_nbytes_alloc = 0;
}

void silofs_mpool_fini(struct silofs_mpool *mp)
{
	struct silofs_mpoolq *mpq = NULL;

	for (size_t i = 0; i < ARRAY_SIZE(mp->mpq); ++i) {
		mpq = &mp->mpq[i];
		if (mpq->mpq_obj_size > 0) {
			mpq_fini(mpq);
		}
	}
	mpool_fini_alloc_if(mp);
	mp->mp_qal = NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_mpoolq *
mpool_mpq_of(struct silofs_mpool *mp, size_t obj_size)
{
	struct silofs_mpoolq *mpq;

	for (size_t i = 0; i < ARRAY_SIZE(mp->mpq); ++i) {
		mpq = &mp->mpq[i];
		if (!mpq->mpq_obj_size || (mpq->mpq_obj_size > obj_size)) {
			break; /* sub-queues are sorted by object-size */
		}
		if (mpq->mpq_obj_size == obj_size) {
			return mpq;
		}
	}
	return NULL;
}

static void *mpool_malloc_obj(struct silofs_mpool *mp, size_t sz)
{
	void *obj;
	struct silofs_mpoolq *mpq;

	mpq = mpool_mpq_of(mp, sz);
	if (mpq == NULL) {
		return NULL;
	}
	obj = mpq_alloc_obj(mpq);
	if (obj != NULL) {
		return obj;
	}
	if (mpq_more_bfree(mpq) != 0) {
		return NULL;
	}
	obj = mpq_alloc_obj(mpq);
	if (obj == NULL) {
		return NULL;
	}
	return obj;
}

static void mpool_free_obj(struct silofs_mpool *mpool, void *obj, size_t sz)
{
	struct silofs_mpoolq *mpq;

	mpq = mpool_mpq_of(mpool, sz);
	if (mpq != NULL) {
		mpq_free_obj(mpq, obj);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_mpool *aif_to_mpool(const struct silofs_alloc_if *aif)
{
	const struct silofs_mpool *mpool;

	mpool = silofs_container_of2(aif, struct silofs_mpool, mp_alif);
	return silofs_unconst(mpool);
}

static void *mpool_malloc(struct silofs_alloc_if *alif, size_t nbytes)
{
	void *ptr;
	struct silofs_mpoolq *mpq;
	struct silofs_mpool *mpool = aif_to_mpool(alif);

	mpq = mpool_mpq_of(mpool, nbytes);
	if (mpq != NULL) {
		ptr = mpool_malloc_obj(mpool, nbytes);
	} else {
		ptr = silofs_qalloc_malloc(mpool->mp_qal, nbytes);
	}
	if (ptr != NULL) {
		mpool->mp_nbytes_alloc += nbytes;
	}
	return ptr;
}

static void mpool_free(struct silofs_alloc_if *alif, void *ptr, size_t nbytes)
{
	struct silofs_mpoolq *mpq;
	struct silofs_mpool *mpool = aif_to_mpool(alif);

	silofs_assert_ge(mpool->mp_nbytes_alloc, nbytes);

	mpq = mpool_mpq_of(mpool, nbytes);
	if (mpq != NULL) {
		mpool_free_obj(mpool, ptr, nbytes);
	} else {
		silofs_qalloc_free(mpool->mp_qal, ptr, nbytes);
	}
	mpool->mp_nbytes_alloc -= nbytes;
}

static void mpool_stat(const struct silofs_alloc_if *alif,
                       struct silofs_alloc_stat *out_stat)
{
	const struct silofs_mpool *mpool = aif_to_mpool(alif);

	silofs_qalloc_stat(mpool->mp_qal, out_stat);
}

static int mpool_resolve(const struct silofs_alloc_if *alif,
                         void *ptr, size_t len, struct silofs_fiovec *fiov)
{
	const struct silofs_mpool *mpool = aif_to_mpool(alif);

	return silofs_qalloc_resolve(mpool->mp_qal, ptr, len, fiov);
}

static void mpool_init_alloc_if(struct silofs_mpool *mpool)
{
	mpool->mp_alif.malloc_fn = mpool_malloc;
	mpool->mp_alif.free_fn = mpool_free;
	mpool->mp_alif.stat_fn = mpool_stat;
	mpool->mp_alif.resolve_fn = mpool_resolve;
}

static void mpool_fini_alloc_if(struct silofs_mpool *mpool)
{
	mpool->mp_alif.malloc_fn = NULL;
	mpool->mp_alif.free_fn = NULL;
	mpool->mp_alif.stat_fn = NULL;
	mpool->mp_alif.resolve_fn = NULL;
}

