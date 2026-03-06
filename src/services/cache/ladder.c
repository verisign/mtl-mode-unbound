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
#include <mtllib/mtllib_buffer.h>
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
 * Get the SID from the specific ladder buffer
 *
 * @param ladder_buff: reference ladder buffer pointer
 * @param hash_size: length in bytes of the hash (aka security parameter)
 * @param sid: pointer to the Series ID structure allocated for the SID
 * @return: 0 on success or 1 on failure
 */
int ladder_buffer_get_sid(MTLLIB_BUFFER* ladder_buff, size_t hash_size, SERIESID* sid)
{
	uint8_t* data_ptr = NULL;

	if((ladder_buff == NULL) || (hash_size == 0) || (sid == NULL)  || (ladder_buff->buffer_position < (hash_size * 2) + 4)) {
		return 1;
	}

	sid->length = hash_size * 2;
	data_ptr = ladder_buff->buffer_data;
	memcpy(&sid->id[0], &data_ptr[2], hash_size * 2);
	return 0;
}


/**
 * Update or insert a ladder in the ladder cache for future use.
 * Will lookup the ladder to see if it is in the cache and then
 * perform an update if necessary.
 *
 * @param l: the ladder cache.
 * @param ladder_buff: reference ladder buffer pointer
 * @param hash_size: length in bytes of the hash (aka security parameter)
 * @return: true if the passed reference is updated,
 *          false if it is unchanged.
 */
int ladder_cache_update(struct ladder_cache *l, MTLLIB_BUFFER* ladder_buff, size_t hash_size)
{
	uint8_t new_record = 0;
	MTLLIB_BUFFER *cache_ladder = NULL;
	struct ladder_cache_key *key = NULL;
	SERIESID sid;

	if ((ladder_buff == NULL) || (l == NULL) || (ladder_buff->buffer_position == 0) || 
	    (hash_size == 0))
	{
		return 0;
	}

	if(ladder_buffer_get_sid(ladder_buff, hash_size, &sid)) {
		return 0;
	}

	// Ladders are stored by SID
	hashvalue_type h = hashlittle(sid.id, sid.length, 0xaa);

	struct lruhash_entry *e;
	/* looks up item with a readlock - no editing! */
	if ((e = slabhash_lookup(&l->table, h, &sid, 0)) != 0)
	{
		// For each ladder in the e->data, do the ladder compare
		cache_ladder = (MTLLIB_BUFFER*)e->data;
		if (ladder_cache_is_ladder_equal(ladder_buff, cache_ladder))
		{
			ladder_cache_touch(l, cache_ladder, e, hash_size);
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

		key->sid.length = sid.length;
		memcpy(key->sid.id, sid.id, sid.length);

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
		mtllib_buffer_free(key->entry.data);
		key->entry.data = NULL;
	}

	MTLLIB_BUFFER* new_rec = NULL;	
	if (mtllib_buffer_initialize(&new_rec, ladder_buff->buffer_position, NULL) != MTLLIB_OK) {
		return 2;
    }

	memcpy(new_rec->buffer_data, ladder_buff->buffer_data, ladder_buff->buffer_position);
	new_rec->buffer_position = ladder_buff->buffer_position;
	key->entry.data = new_rec;
	lock_rw_unlock(&key->entry.lock);

	if (new_record)
	{
		slabhash_insert(&l->table, key->entry.hash, &key->entry, new_rec, NULL);
	}
	else
	{
		ladder_cache_touch(l, new_rec, e, hash_size);
	}
	return 1;
}

/**
 * Check to see if the ladder is currently in the ladder cache.
 * Note: This function checks the ladder IDs and all rungs match. Thus
 *       updated ladders with different rungs will reutrh false.
 *
 * @param l: the ladder cache.
 * @param ref: reference ladder buffer pointer
 * @param hash_size: length in bytes of the hash (aka security parameter)
 * @return: true if the ladder is in cache, false if it is not.
 */
int ladder_cache_ladder_exists(struct ladder_cache *l, MTLLIB_BUFFER *ref, size_t hash_size)
{
	SERIESID sid;

	if ((ref == NULL) || (l == NULL) || (hash_size == 0))
	{
		return 0;
	}

	if(ladder_buffer_get_sid(ref, hash_size, &sid)) {
		return 0;
	}

	// Ladders are stored by SID
	hashvalue_type h = hashlittle(sid.id, sid.length, 0xaa);

	struct lruhash_entry *e;
	/* looks up item with a readlock - no editing! */
	e = slabhash_lookup(&l->table, h, &sid, 0);
	if(e != NULL) 
	// if ((e = slabhash_lookup(&l->table, h, &sid, 0)) != 0)
	{
		MTLLIB_BUFFER *cache_ladder = (MTLLIB_BUFFER*)e->data;
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
 * Given a ladder cache and a series ID, get the cached ladder
 *
 * @param l: the ladder cache
 * @param sid: MTL series identifier
 * @param hash_size: length in bytes of the hash (aka security parameter) 
 * @return: MTLLIB_BUFFER pointer or NULL if no ladder
 */
MTLLIB_BUFFER* 
ladder_cache_find_ladder(struct ladder_cache *l, SERIESID* sid, size_t hash_size)
{
	MTLLIB_BUFFER *cache_ladder = NULL;
	struct lruhash_entry *e = NULL;

	if ((sid == NULL) || (l == NULL))
	{
		return NULL;
	}

	// Ladders are stored by SID
	hashvalue_type h = hashlittle(sid->id, sid->length, 0xaa);

	/* looks up item with a readlock - no editing! */
	if ((e = slabhash_lookup(&l->table, h, sid, 0)) != 0)
	{
		cache_ladder = (MTLLIB_BUFFER *)e->data;
		ladder_cache_touch(l, cache_ladder, e, hash_size);
		lock_rw_unlock(&e->lock);		
	}
	return cache_ladder;
}

/**
 * Clear the ladder cache entries
 *
 * @param l: the ladder cache.
 * @return: None
 */
void ladder_cache_clear(struct ladder_cache *l)
{
	if (l) {
		slabhash_clear(&l->table);
	}
}

/**
 * Update the LRU access for a given ladder reference
 *
 * @param l: the ladder cache.
 * @param ref: reference ladder buffer pointer
 * @param e: Pointer to the entry in the LRU cache.
 * @return: 0 on success or 1 on failure
 */
int ladder_cache_touch(struct ladder_cache *l, MTLLIB_BUFFER *ref,
						struct lruhash_entry *e, size_t hash_size)
{
	SERIESID sid;

	if ((ref == NULL) || (l == NULL) || (e == NULL))
	{
		return 1;
	}

	if(ladder_buffer_get_sid(ref, hash_size, &sid)) {
		return 1;
	}

	hashvalue_type h = hashlittle(sid.id, sid.length, 0xaa);

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

	return 0;
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
	cache_entry_size += sizeof(MTLLIB_BUFFER);

	// Plus the rung data
	MTLLIB_BUFFER *ladder = (MTLLIB_BUFFER *)data;
	cache_entry_size += ladder->buffer_position;

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
	mtllib_buffer_free((MTLLIB_BUFFER *)data);
	}
}

/**
 * Compare two ladders and signals if they are the same
 * @param ladder_one: Pointer to the first ladder.
 * @param ladder_two: Pointer to the second ladder
 * @return 1 if they match and 0 if not
 */
uint8_t
ladder_cache_is_ladder_equal(MTLLIB_BUFFER *ladder_one, MTLLIB_BUFFER *ladder_two)
{
	if ((ladder_one == NULL) || (ladder_two == NULL) ||
        (ladder_one->buffer_position > ladder_one->buffer_length) ||
        (ladder_two->buffer_position > ladder_two->buffer_length))
	{
		return 0;
	}

	if((ladder_one->buffer_type != ladder_two->buffer_type) ||
	   (ladder_one->buffer_position != ladder_two->buffer_position)) {
		return 0;
	}

	if(memcmp(ladder_one->buffer_data, ladder_two->buffer_data, ladder_one->buffer_position) == 0) {
		return 1;
	}

	return 0;
}