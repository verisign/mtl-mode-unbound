/*
 * services/cache/ladder.c - MTL ladder caching functions.
 * 
 *  
 *  Copyright (c) 2024, VeriSign, Inc.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted (subject to the limitations in the disclaimer
 *  below) provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *    * Neither the name of the copyright holder nor the names of its
 *      contributors may be used to endorse or promote products derived from this
 *      software without specific prior written permission.
 *
 *  NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY
 *  THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 *  CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 *  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
*/

/**
 * \file
 *
 * This file contains the ladder cache.
 */
#include "config.h"
#include "services/cache/ladder.h"
#include "sldns/rrdef.h"
#include "util/storage/slabhash.h"
#include "util/config_file.h"
#include "util/data/packed_rrset.h"
#include "util/data/msgreply.h"
#include "util/data/msgparse.h"
#include "util/data/dname.h"
#include "util/regional.h"
#include "util/alloc.h"
#include "util/net_help.h"
#include "util/storage/lookup3.h"
#include "validator/val_secalgo.h"

#include <mtllib/mtl.h>
#include <time.h>

/**
 * Create ladder cache
 * @param cfg: config settings or NULL for defaults.
 * @return: pointer to the cache that was created or NULL if the
 *         cache could not be created.
 */
struct ladder_cache *ladder_cache_create(struct config_file *cfg)
{
	if (cfg == NULL)
	{
		return NULL;
	}

	size_t slabs = (cfg ? cfg->ladder_cache_slabs : HASH_DEFAULT_SLABS);
	size_t startarray = HASH_DEFAULT_STARTARRAY;
	size_t maxmem = (cfg ? cfg->ladder_cache_size : HASH_DEFAULT_MAXMEM);

	struct ladder_cache *l = (struct ladder_cache *)slabhash_create(slabs,
											 startarray,
											 maxmem,
											 ladder_cache_sizefunc,
											 ladder_cache_compare,
											 ladder_cache_key_free,
											 ladder_cache_data_free,
											 NULL);
	return l;
}

/**
 * Delete the ladder cache record
 * @param r: rrset cache to delete.
 */
void ladder_cache_delete(struct ladder_cache *l)
{
	if (l)
	{
		slabhash_delete(&l->table);
	}
}

/**
 * Adjust settings of the cache to settings from the config file.
 * May purge the cache. May recreate the cache.
 * There may be no threading or use by other threads.
 * @param l: ladder cache to adjust (like realloc).
 * @param cfg: config settings or NULL for defaults.
 * @return pointer to the cache or NULL if the cache could not be created.
 */
struct ladder_cache *ladder_cache_adjust(struct ladder_cache *l,
										 struct config_file *cfg)
{
	if (cfg == NULL)
	{
		return NULL;
	}

	if (!l || !cfg ||
		!slabhash_is_size(&l->table, cfg->ladder_cache_size, cfg->ladder_cache_slabs))
	{
		ladder_cache_delete(l);
		l = ladder_cache_create(cfg);
	}
	return l;
}

/**
 * Update or insert a ladder in the ladder cache for future use.
 * Will lookup the ladder to see if it is in the cache and then
 * perform an update if necessary.
 *
 * @param l: the ladder cache.
 * @param ref: reference ladder pointer
 * @return: true if the passed reference is updated,
 *          false if it is unchanged.
 */
int ladder_cache_update(struct ladder_cache *l, LADDER *ref)
{
	uint8_t new_record = 0;
	LADDER *cache_ladder = NULL;
	struct ladder_cache_key *key = NULL;

	if ((ref == NULL) || (l == NULL))
	{
		return 0;
	}

	// Ladders are stored by SID
	hashvalue_type h = hashlittle(ref->sid.id, ref->sid.length, 0xaa);

	struct lruhash_entry *e;
	/* looks up item with a readlock - no editing! */
	if ((e = slabhash_lookup(&l->table, h, &ref->sid, 0)) != 0)
	{
		// For each ladder in the e->data, do the ladder compare
		cache_ladder = e->data;
		if (ladder_cache_is_ladder_equal(ref, cache_ladder))
		{
			ladder_cache_touch(l, cache_ladder, e);
			lock_rw_unlock(&e->lock);
			return 2;
		}
	}

	// Add the ladder to the cache, or create it if e is NULL
	if (e == NULL)
	{
		key = calloc(1, sizeof(struct ladder_cache_key));
		if(key == NULL) {
			return 2;
		}
		lock_rw_init(&key->entry.lock);
		key->entry.hash = h;
		key->entry.key = key;
		key->entry.data = NULL;

		key->sid.length = ref->sid.length;
		memcpy(key->sid.id, ref->sid.id, ref->sid.length);

		lock_rw_wrlock(&key->entry.lock);
		e = &key->entry;
		new_record = 1;
	}
	else
	{
		key = e->key;
	}

	if (key->entry.data != NULL)
	{
		mtl_ladder_free(key->entry.data);
		key->entry.data = NULL;
	}

	LADDER *new_rec = (LADDER *)calloc(1, sizeof(LADDER));
	if(new_rec == NULL) {
		return 2;
	}
	memcpy(new_rec, ref, sizeof(LADDER));
	size_t rung_size = sizeof(RUNG) * ref->rung_count;
	new_rec->rungs = (RUNG *)calloc(1, rung_size);
	memcpy(new_rec->rungs, ref->rungs, rung_size);

	key->entry.data = new_rec;

	lock_rw_unlock(&key->entry.lock);

	if (new_record)
	{
		slabhash_insert(&l->table, key->entry.hash, &key->entry, new_rec, NULL);
	}
	else
	{
		ladder_cache_touch(l, e->data, e);
	}
	return 1;
}

/**
 * Check to see if the ladder is currently in the ladder cache.
 * Note: This function checks the ladder IDs and all rungs match. Thus
 *       updated ladders with different rungs will reutrh false.
 *
 * @param l: the ladder cache.
 * @param ref: reference ladder pointer
 * @return: true if the ladder is in cache, false if it is not.
 */
int ladder_cache_ladder_exists(struct ladder_cache *l, LADDER *ref)
{
	if ((ref == NULL) || (l == NULL))
	{
		return 0;
	}

	// Ladders are stored by SID
	hashvalue_type h = hashlittle(ref->sid.id, ref->sid.length, 0xaa);

	struct lruhash_entry *e;
	/* looks up item with a readlock - no editing! */
	if ((e = slabhash_lookup(&l->table, h, &ref->sid, 0)) != 0)
	{
		LADDER *cache_ladder = e->data;
		if (ladder_cache_is_ladder_equal(ref, cache_ladder))
		{
			lock_rw_unlock(&e->lock);
			return 1;
		}
		lock_rw_unlock(&e->lock);
	}
	return 0;
}

/**
 * Given a ladder cache and an auth path, look for a cached rung that can
 * verify the given auth path.
 *
 * @param l: the ladder cache.
 * @param path: MTL authentication path
 * @return: RUNG pointer if it exists, or NULL if not
 */
RUNG *
ladder_cache_find_rung(struct ladder_cache *l, AUTHPATH *path)
{
	LADDER *cache_ladder = NULL;
	RUNG *tmp_rung = NULL;
	struct lruhash_entry *e = NULL;

	if ((path == NULL) || (l == NULL))
	{
		return NULL;
	}

	// Ladders are stored by SID
	hashvalue_type h = hashlittle(path->sid.id, path->sid.length, 0xaa);

	/* looks up item with a readlock - no editing! */
	if ((e = slabhash_lookup(&l->table, h, &path->sid, 0)) != 0)
	{
		cache_ladder = (LADDER *)e->data;

		// Find the best containing ladder
		tmp_rung = mtl_rung(path, cache_ladder);
		if (tmp_rung != NULL)
		{
			ladder_cache_touch(l, cache_ladder, e);
		}
		lock_rw_unlock(&e->lock);
	}
	return tmp_rung;
}

/**
 * Clear the ladder cache entries
 *
 * @param l: the ladder cache.
 * @return: None
 */
void ladder_cache_clear(struct ladder_cache *l)
{
	if (l)
		slabhash_clear(&l->table);
}

/**
 * Update the LRU access for a given ladder reference
 *
 * @param l: the ladder cache.
 * @param ref: reference ladder pointer
 * @param e: Pointer to the entry in the LRU cache.
 * @return: none
 */
void ladder_cache_touch(struct ladder_cache *l, LADDER *ref,
						struct lruhash_entry *e)
{
	hashvalue_type h = hashlittle(ref->sid.id, ref->sid.length, 0xaa);

	struct lruhash *table = slabhash_gettable(&l->table, h);
	/*
	 * This leads to locking problems, deadlocks, if the caller is
	 * holding any other rrset lock.
	 * Because a lookup through the hashtable does:
	 *	tablelock -> entrylock  (for that entry caller holds)
	 * And this would do
	 *	entrylock(already held) -> tablelock
	 * And if two threads do this, it results in deadlock.
	 * So, the caller must not hold entrylock.
	 */
	lock_quick_lock(&table->lock);
	lock_rw_rdlock(&e->lock);
	if (e->hash == h)
	{
		lru_touch(table, e);
	}
	lock_rw_unlock(&e->lock);
	lock_quick_unlock(&table->lock);
}

/**
 * Function that calculates the size of the record in the cache
 *
 * @param key: pointer to the cache key record
 * @param data: pointer to the cache data record
 * @return: returns the size of the cache record
 */
size_t
ladder_cache_sizefunc(void *key, void *data)
{
	if ((key == NULL) || (data == NULL))
	{
		return 0;
	}

	// The memory size of a ladder is the lruhash entry
	size_t cache_entry_size = sizeof(struct ladder_cache_key);

	// Plus the expiration and Ladder records
	cache_entry_size += sizeof(LADDER);

	// Plus the rung data
	LADDER *ladder = (LADDER *)data;
	cache_entry_size += ladder->rung_count * sizeof(RUNG);

	// Plus the size of the memory locks
	cache_entry_size += lock_get_mem(&key->entry.lock);

	return cache_entry_size;
}

/**
 * Function that compares two cache keys to see if they are equal
 *
 * @param k1: pointer to the first cache key record
 * @param k2: pointer to the second cache key record
 * @return: 0 if equal, -1 if k1 is after k2, and 1 if k1 is before k2
 */
int ladder_cache_compare(void *k1, void *k2)
{
	struct ladder_cache_key *ladder_cache_1 = (struct ladder_cache_key *)k1;
	struct ladder_cache_key *ladder_cache_2 = (struct ladder_cache_key *)k2;
	SERIESID *key1 = &ladder_cache_1->sid;
	SERIESID *key2 = &ladder_cache_2->sid;

	if (key1 == NULL)
	{
		return -1;
	}
	if (key2 == NULL)
	{
		return 1;
	}

	if (key1->length < key2->length)
	{
		return -1;
	}
	if (key1->length > key2->length)
	{
		return 1;
	}

	for (uint16_t i = 0; i < key1->length; i++)
	{
		if (key1->id[i] < key2->id[i])
		{
			return -1;
		}
		if (key1->id[i] > key2->id[i])
		{
			return 1;
		}
	}
	return 0;
}

/**
 * Function that frees a ladder cache key object
 *
 * @param key: pointer to the cache key record
 * @param userdata: optional user data parameter
 * @return: None.
 */
void ladder_cache_key_free(void *key, void *ATTR_UNUSED(userdata))
{
	struct ladder_cache_key *tmp_key = NULL;

	if(key != NULL) {
		tmp_key = (struct ladder_cache_key*)key;
		lock_rw_destroy(&tmp_key->entry.lock);
		free(tmp_key);
	}
}

/**
 * Function that frees a ladder cache data object
 *
 * @param data: pointer to the cached record data block
 * @param userdata: optional user data parameter
 * @return: None.
 */
void ladder_cache_data_free(void *data, void *ATTR_UNUSED(userdata))
{
	if (data != NULL)
	{
		mtl_ladder_free((LADDER *)data);
	}
}

/**
 * Compare two ladders and signals if they are the same
 * @param ladder_one: Pointer to the first ladder.
 * @param ladder_two: Pointer to the second ladder
 * @return 1 if they match and 0 if not
 */
uint8_t
ladder_cache_is_ladder_equal(LADDER *ladder_one, LADDER *ladder_two)
{
	uint8_t rung_match = 1;

	if ((ladder_one == NULL) || (ladder_two == NULL))
	{
		return 0;
	}

	if ((ladder_two->flags == ladder_one->flags) &&
		(ladder_two->rung_count == ladder_one->rung_count) &&
		(ladder_two->sid.length == ladder_one->sid.length) &&
		(memcmp(ladder_two->sid.id, ladder_one->sid.id,
				ladder_two->sid.length) == 0))
	{
		for (uint16_t r = 0; r < ladder_two->rung_count; r++)
		{
			RUNG *cache_rung = ladder_two->rungs;
			RUNG *src_rung = ladder_one->rungs;
			if ((cache_rung[r].left_index != src_rung[r].left_index) ||
				(cache_rung[r].right_index != src_rung[r].right_index) ||
				(cache_rung[r].hash_length != src_rung[r].hash_length) ||
				(memcmp(cache_rung[r].hash, src_rung[r].hash,
						cache_rung[r].hash_length) != 0))
			{
				rung_match = 0;
			}
		}
	}
	else
	{
		rung_match = 0;
	}

	return rung_match;
}