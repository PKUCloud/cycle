#ifndef __RR_HASH_H
#define __RR_HASH_H

#include <linux/record_replay.h>
#include <linux/types.h>
#include <asm/logger.h>

/* Number of bits of the hash key. Too large will make kmalloc fail */
#define RR_HASH_BITS	18
#define RR_HASH_SIZE	(1UL << RR_HASH_BITS)
#define RR_HASH_MASK	0x3FFFFUL

static void rr_init_hash(struct hlist_head **phash)
{
	int i;
	struct hlist_head *temp = kmalloc(sizeof(*temp) * RR_HASH_SIZE,
					  GFP_KERNEL);
	if (unlikely(!temp)) {
		RR_ERR("error: fail to kmalloc for hash table for size=%lu",
		       RR_HASH_SIZE * sizeof(*temp));
		return;
	}

	for (i = 0; i < RR_HASH_SIZE; ++i) {
		INIT_HLIST_HEAD(&temp[i]);
	}

	*phash = temp;
	RR_DLOG(INIT, "hash_table initialized");
}

/* Not responsible for clearing nodes here */
static void rr_clear_hash(struct hlist_head **phash)
{
	RR_ASSERT(phash);
	if (*phash) {
		kfree(*phash);
		*phash = NULL;
		RR_DLOG(INIT, "hash_table clear");
	}
}

static inline u32 rr_hashfn(u64 val)
{
	return val & RR_HASH_MASK;
}

static inline void rr_hash_insert(struct hlist_head *hash,
				  struct rr_gfn_state *gfnsta)
{
	u32 hashkey = rr_hashfn(gfnsta->gfn);

	RR_ASSERT(hashkey < RR_HASH_SIZE);
	hlist_add_head(&gfnsta->hlink, &hash[hashkey]);
}

static inline struct rr_gfn_state *rr_hash_find(struct hlist_head *hash,
						u64 gfn)
{
	u32 hashkey = rr_hashfn(gfn);
	struct hlist_head *phead;
	struct rr_gfn_state *gfnsta;

	RR_ASSERT(hashkey < RR_HASH_SIZE);
	phead = &hash[hashkey];
	hlist_for_each_entry(gfnsta, phead, hlink) {
		if (gfnsta->gfn == gfn) {
			return gfnsta;
		}
	}
	return NULL;
}

#endif

