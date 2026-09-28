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

/** Wrapper for SHAKE128(msg, 256)
* @param msg: message to be hashed
* @param msg_len: length (in bytes) of msg
* @param out: buffer to place output in (caller is responsible for checking that out is large enough to hold SIGTAG_LEN bytes)
* @return 0 on success, 1 on failure
*/
uint8_t ladder_cache_calc_sigtag(uint8_t *msg, size_t msg_len, uint8_t *out) {
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	const EVP_MD *alg = EVP_shake128();
	if ((ctx == NULL) || (alg == NULL)) {
		return 1;
	}
	if (EVP_DigestInit_ex(ctx, EVP_shake128(), NULL) != 1) {
		return 1;
	}
	if (EVP_DigestUpdate(ctx, msg, msg_len) != 1) {
		EVP_MD_CTX_destroy(ctx);
		return 1;
	}
	if (EVP_DigestFinalXOF(ctx, out, SIGTAG_LEN) != 1) {
		EVP_MD_CTX_destroy(ctx);
		return 1;
	}

	EVP_MD_CTX_destroy(ctx);
	return 0; 
	
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
 * Get the maximum covered index from the specific ladder buffer
 *
 * @param ladder_buff: reference ladder buffer pointer
 * @param hash_size: length in bytes of the hash (aka security parameter)
 * @param right_index: pointer to fill with the index value
 * @return: 0 on success or 1 on failure
 */
int ladder_buffer_get_right_index(MTLLIB_BUFFER* ladder_buff, size_t hash_size, MTL_INDEX *right_index)
{
	uint8_t* rungs_start = NULL;
	size_t header_len = 2 + (2*hash_size) + 2; // Flags | SID | Rung_Count
	uint16_t rung_count = 0;
	size_t rung_size = (2*MTL_INDEX_LEN) + hash_size; // Size of a single rung: left_index | right_index | hash

	if((ladder_buff == NULL) || (hash_size == 0) || (right_index == NULL)  || (mtllib_buffer_in_use(ladder_buff) < header_len)) {
		return 1;
	}
	*right_index = 0;

	rungs_start = mtllib_buffer_data_ptr(ladder_buff) + header_len;
	bytes_to_uint16(rungs_start - 2, &rung_count);
	if (rung_count == 0) {
		return 1;
	}
	if (mtllib_buffer_in_use(ladder_buff) < header_len + rung_count * ((2 * MTL_INDEX_LEN) + hash_size)) {
		return 1;
	}

	uint16_t i;
	MTL_INDEX rung_right_index; // right index of the current rung
	for (i = 0; i < rung_count; i++) {
		bytes_to_mtl_index(rungs_start + (i * rung_size) + MTL_INDEX_LEN, &rung_right_index);
		if (rung_right_index > *right_index) {
			*right_index = rung_right_index;
		}
	}
		
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
 * @param sigtag: tag associated with the ladder
 * @return: true if the passed reference is updated,
 *          false if it is unchanged.
 */
int ladder_cache_update(struct ladder_cache *l, MTLLIB_BUFFER* ladder_buff, size_t hash_size, uint8_t *sigtag, struct domain_name *signer_name)
{
	uint8_t new_record = 0;
	MTLLIB_BUFFER *cache_ladder = NULL;
	struct ladder_cache_key *key = NULL;
	struct ladder_cache_key lookup_key;

	if ((ladder_buff == NULL) || (l == NULL) || (ladder_buff->buffer_position == 0) || 
	    (hash_size == 0) || (sigtag == NULL) || (signer_name == NULL))
	{
		return 0;
	}

	memcpy(lookup_key.tag, sigtag, SIGTAG_LEN);
	lookup_key.signer_name.length = signer_name->length;
	memcpy(lookup_key.signer_name.labels, signer_name->labels, signer_name->length);

	// Compute hashtable hint
	hashvalue_type h = hashlittle(lookup_key.signer_name.labels, lookup_key.signer_name.length, 0xaa);

	struct lruhash_entry *e;
	/* looks up item with a readlock - no editing! */
	if ((e = slabhash_lookup(&l->table, h, &lookup_key, 0)) != 0)
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

		memcpy(key->tag, lookup_key.tag, SIGTAG_LEN);

		key->signer_name.length = lookup_key.signer_name.length;
		memcpy(key->signer_name.labels, lookup_key.signer_name.labels, lookup_key.signer_name.length);

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
 *       updated ladders with different rungs will return false.
 *
 * @param l: the ladder cache.
 * @param ref: reference ladder buffer pointer
 * @param sigtag: sigtag for the signed ladder containing the ladder
 * @param signer_name: name the the signer who signed this ladder
 * @return: true if the ladder is in cache, false if it is not.
 */
int ladder_cache_ladder_exists(struct ladder_cache *l, MTLLIB_BUFFER *ref, uint8_t *sigtag, struct domain_name *signer_name)
{
	struct ladder_cache_key cache_key;

	if ((ref == NULL) || (l == NULL) || (sigtag == NULL) || (signer_name == NULL))
	{
		return 0;
	}

	cache_key.signer_name.length = signer_name->length;
	memcpy(cache_key.signer_name.labels, signer_name->labels, signer_name->length);
	memcpy(cache_key.tag, sigtag, SIGTAG_LEN);


	// Compute hashtable hint
	hashvalue_type h = hashlittle(cache_key.signer_name.labels, cache_key.signer_name.length, 0xaa);

	struct lruhash_entry *e;
	/* looks up item with a readlock - no editing! */
	e = slabhash_lookup(&l->table, h, &cache_key, 0);
	if(e != NULL) 
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

/* args structure to pass into ladder_cache_check_compatible function pointer */
struct ladder_cache_sigtag_check_compatible_args {
	unsigned char *signature;
	size_t signature_len;
	size_t hash_size;
	struct domain_name *signer_name;
	MTLLIB_BUFFER *found_ladder;
};

/**
 * Function pointer for use in ladder_cache_find_ladder -- set found_ladder to a cached ladder if its compatible with the authpath of signature
 * @param sig: signature (full or condensed) to check compatibility against
 * @param sig_len: length in bytes of the signature
 * @param signer_name: signer name to match against
 * @param found_ladder: current best match, NULL if none found
 * @return: None
 */
static void ladder_cache_sigtag_check_compatible(struct lruhash_entry *e, void *args_ptr) {
	struct ladder_cache_sigtag_check_compatible_args *args = args_ptr;
	if (args->found_ladder != NULL) { // already found a ladder
		return;
	}

	struct ladder_cache_key *key = e->key;
	MTLLIB_BUFFER *ladder_buffer = e->data;

	// Check for matching signer_name
	if ((key->signer_name.length != args->signer_name->length) ||
		(memcmp(key->signer_name.labels, args->signer_name->labels, key->signer_name.length) != 0)) {
			return;
		}

	// Extract data structures from buffer
	LADDER *ladder = NULL;
	mtl_ladder_from_buffer(mtllib_buffer_data_ptr(ladder_buffer), mtllib_buffer_in_use(ladder_buffer), args->hash_size, &ladder);
	RANDOMIZER *r;
	AUTHPATH *authpath;
	mtl_auth_path_from_buffer(args->signature, args->signature_len, args->hash_size, &r, &authpath);

	// Are there any compatible rungs in the cached ladder?
	if(mtl_rung(authpath, ladder) != NULL) {
		args->found_ladder = ladder_buffer;
	}
}

/**
 * Given a ladder cache and a signature, get a cached ladder to compare against
 *
 * @param l: the ladder cache
 * @param sig: signature (full or condensed) to check compatibility against
 * @param sig_len: length in bytes of the signature
 * @return: MTLLIB_BUFFER pointer to a verified ladder compatible with the authpath of sig or NULL if no ladder
 */
MTLLIB_BUFFER* 
ladder_cache_find_ladder(struct ladder_cache *l, unsigned char *sig, size_t siglen, struct domain_name *signer_name)
{
	struct lruhash_entry *e = NULL;

	if ((sig == NULL) || (siglen == 0) || (l == NULL) || (signer_name == NULL))
	{
		return NULL;
	}

	// Compute hashtable hint
	hashvalue_type h = hashlittle(signer_name->labels, signer_name->length, 0xaa);
	struct lruhash *bin = slabhash_gettable(&l->table, h);


	// Gather SigTags from ladders in bin
	struct ladder_cache_sigtag_check_compatible_args args = {
		.signature = sig,
		.signature_len = siglen,
		.hash_size = 16, // TODO dynamically compute
		.signer_name = signer_name,
		.found_ladder = NULL,
	};

	lruhash_traverse(bin, 0, ladder_cache_sigtag_check_compatible, &args);
	return args.found_ladder;
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
	if ((ref == NULL) || (l == NULL) || (e == NULL) || (e->key) == NULL)
	{
		return 1;
	}

	struct ladder_cache_key *cache_key = e->key;
	if (cache_key == NULL) {
		return 1;
	}
	struct lruhash *table = slabhash_gettable(&l->table, e->hash);
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
	lru_touch(table, e);
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
	struct ladder_cache_key *key1 = (struct ladder_cache_key *)k1;
	struct ladder_cache_key *key2 = (struct ladder_cache_key *)k2;
	int x;

	// NULL is considered the last key, but is not equal to itself
	if (key1 == NULL)
	{
		return -1;
	}
	if (key2 == NULL)
	{
		return 1;
	}

	// Compare SigTags
	if( (x = memcmp(key1->tag, key2->tag, SIGTAG_LEN)) != 0 ) {
		return x < 0 ? -1 : 1;
	}

	// If SigTags match, check the signers' names using the same rules
	if (key1->signer_name.length != key2->signer_name.length)
	{
		return key1->signer_name.length < key2->signer_name.length ? -1 : 1;
	}
	if( (x = memcmp(key1->signer_name.labels, key2->signer_name.labels, key1->signer_name.length)) != 0 ) {
		return x < 0 ? -1 : 1;
	}

	// If neither SigTags nor Signer names mismatch, the keys are equal
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

	if(ladder_one->buffer_position != ladder_two->buffer_position) {
		return 0;
	}

	if(memcmp(ladder_one->buffer_data, ladder_two->buffer_data, ladder_one->buffer_position) == 0) {
		return 1;
	}

	return 0;
}


/* args structure to pass into ladder_cache_sigtag_add_matching function pointer */
struct ladder_cache_sigtag_add_matching_args {
	struct domain_name *signer_name;
	MTLLIB_BUFFER *option_data;
};

/**
 * Function pointer for use in ladder_cache_build_sigtag -- add tag for each matching entry found
 * @param signer_name: signer name to match against
 * @param option_data: buffer to append to
 * @return: None
 */
static void ladder_cache_sigtag_add_matching(struct lruhash_entry *e, void *args_ptr) {
	if ( (e == NULL) || (args_ptr == NULL) ) {
		return;
	}

	struct ladder_cache_sigtag_add_matching_args *args = args_ptr;
	if ( (args->signer_name == NULL) || (args->option_data == NULL) ) {
		return;
	}

	struct ladder_cache_key *key = e->key;
	MTLLIB_BUFFER *ladder_buffer = e->data;
	if ( (key == NULL) || (ladder_buffer == NULL) ) {
		return;
	}

#ifdef UNBOUND_DEBUG
	fprintf(stderr, "...searching for signer: ");
	for(int i=0; i<args->signer_name->length; i++) {
		fprintf(stderr, "%c", args->signer_name->labels[i]);
	}
	fprintf(stderr, "\n");
	fprintf(stderr, "...found cached signer : ");
	for(int i=0; i<key->signer_name.length; i++) {
		fprintf(stderr, "%c", key->signer_name.labels[i]);
	}
	fprintf(stderr, " ");
	for(int i=0; i<SIGTAG_LEN; i++) {
		fprintf(stderr, "%02x", key->tag[i]);
	}
	fprintf(stderr, "\n");
	fflush(stderr);
#endif

	// Compare search signer name to signer name of entry
	if (args->signer_name->length != key->signer_name.length) {
		return;
	}
	if (memcmp(args->signer_name->labels, key->signer_name.labels, args->signer_name->length) != 0) {
		return;
	}

	// Match found
	if (mtllib_buffer_available(args->option_data) < SIGTAG_LEN) {
		return;
	}
	mtllib_buffer_append(args->option_data, key->tag, SIGTAG_LEN);
	
	return;



}
/**
 * Construct SigTag OPTION-DATA
 * @param l: the ladder cache
 * @param signer_name: the signer_name for which to search the cache for associated ladders
 * @param option_data: buffer to fill with SigTags
 * @return: 0 on success, 1 on failure. If successful, option-length is in_use(option_data).
 *  If option_data is too small to hold all SigTags, the function will add as many as will fit;
 *  This scenario is still considered a success
 */
uint8_t
ladder_cache_build_sigtag(struct ladder_cache *l, struct domain_name *signer_name, MTLLIB_BUFFER *option_data) {
	if ((l == NULL) || (signer_name == NULL) || (option_data == NULL)) {
		return 1;
	}

	// Find appropriate bin in the hash table
	hashvalue_type h = hashlittle(signer_name->labels, signer_name->length, 0xaa);
	struct lruhash *bin = slabhash_gettable(&l->table, h);

	// Gather SigTags from ladders in bin
	struct ladder_cache_sigtag_add_matching_args args = {
		.signer_name = signer_name,
		.option_data = option_data,
	};

	lruhash_traverse(bin, 0, ladder_cache_sigtag_add_matching, &args);

	return 0;
}