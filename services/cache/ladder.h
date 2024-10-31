/*
 * services/cache/ladder.h - MTL ladder caching functions/structures/constants.
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

#ifndef SERVICES_CACHE_LADDER_H
#define SERVICES_CACHE_LADDER_H

#include <mtllib/mtl.h>
#include <time.h>

#include "util/storage/lruhash.h"
#include "util/storage/slabhash.h"
#include "util/data/packed_rrset.h"

struct config_file;

/********************************************
 * Structures for the ladder caches
 ********************************************/
/**
 * The ladder cache structure.
 */
struct ladder_cache
{
	/** uses partitioned hash table */
	struct slabhash table;
};

/**
 * key for ip_ratelimit lookups, a source IP.
 */
struct ladder_cache_key {
	/** key value */
	SERIESID sid;
	/** lruhash key entry */
	struct lruhash_entry entry;
};

/********************************************
 * Ladder cache function prototypes
 ********************************************/
/**
 * Create ladder cache
 * @param cfg: config settings or NULL for defaults.
 * @return: pointer to the cache that was created or NULL if the
 *         cache could not be created.
 */
struct ladder_cache *ladder_cache_create(struct config_file *cfg);

/**
 * Delete the ladder cache record
 * @param r: rrset cache to delete.
 */
void ladder_cache_delete(struct ladder_cache *l);

/**
 * Adjust settings of the cache to settings from the config file.
 * May purge the cache. May recreate the cache.
 * There may be no threading or use by other threads.
 * @param l: ladder cache to adjust (like realloc).
 * @param cfg: config settings or NULL for defaults.
 * @return pointer to the cache or NULL if the cache could not be created.
 */
struct ladder_cache *ladder_cache_adjust(struct ladder_cache *l,
										 struct config_file *cfg);

/**
 * Update or insert a ladder in the ladder cache for future use.
 * Will lookup if the ladder is in the cache and perform an update if necessary.
 *
 * @param l: the ladder cache.
 * @param ref: reference ladder pointer
 * @return: true if the passed reference is updated, false if it is unchanged.
 */
int ladder_cache_update(struct ladder_cache *l, LADDER *ref);

/**
 * Check to see if the ladder is currently in the ladder cache.
 * Note: This function checks the ladder IDs and all rungs match. Thus
 *       updated ladders with different rungs will reutrh false.
 *
 * @param l: the ladder cache.
 * @param ref: reference ladder pointer
 * @return: true if the ladder is in cache, false if it is not.
 */
int ladder_cache_ladder_exists(struct ladder_cache *l, LADDER *ref);

/**
 * Given a ladder cache and an auth path, look for a cached rung that can
 * verify the given auth path.
 *
 * @param l: the ladder cache.
 * @param path: MTL authentication path
 * @return: RUNG pointer if it exists, or NULL if not
 */
RUNG *ladder_cache_find_rung(struct ladder_cache *l, AUTHPATH *path);

/**
 * Clear the ladder cache entries
 *
 * @param l: the ladder cache.
 * @return: None
 */
void ladder_cache_clear(struct ladder_cache *l);

/**
 * Update the LRU access for a given ladder reference
 *
 * @param l: the ladder cache.
 * @param ref: reference ladder pointer
 * @param e: Pointer to the entry in the LRU cache.
 * @return: none
 */
void ladder_cache_touch(struct ladder_cache *l, LADDER *ref, struct lruhash_entry *e);

/********************************************
 * Ladder cache utility functions
 ********************************************/
/**
 * Function that calculates the size of the record in the cache
 *
 * @param key: pointer to the cache key record
 * @param data: pointer to the cache data record
 * @return: returns the size of the cache record
 */
size_t ladder_cache_sizefunc(void *key, void *data);

/**
 * Function that compares two cache keys to see if they are equal
 *
 * @param k1: pointer to the first cache key record
 * @param k2: pointer to the second cache key record
 * @return: 0 if equal, -1 if k1 is after k2, and 1 if k1 is before k2
 */
int ladder_cache_compare(void *k1, void *k2);

/**
 * Function that frees a ladder cache object
 *
 * @param key: pointer to the cache key record
 * @param userdata: optional user data parameter
 * @return: None.
 */
void ladder_cache_key_free(void *key, void *userdata);

/**
 * Function that frees a ladder cache data object
 *
 * @param data: pointer to the cached record data block
 * @param userdata: optional user data parameter
 * @return: None.
 */
void ladder_cache_data_free(void *data, void *userdata);

/**
 * Compare two ladders and signal if they are the same
 * @param ladder_one: Pointer to the first ladder.
 * @param ladder_two: Pointer to the second ladder
 * @return 1 if they match and 0 if not
 */
uint8_t ladder_cache_is_ladder_equal(LADDER *ladder_one, LADDER *ladder_two);

#endif /* SERVICES_CACHE_LADDER_H */