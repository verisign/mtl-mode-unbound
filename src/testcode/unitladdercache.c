/*
 * testcode/unitladdercache.c - MTL ladder caching test.
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
 * This file contains unit test for MTL ladder caching
 */
#include "config.h"
#include "services/authzone.h"
#include "testcode/unitmain.h"
#include "util/alloc.h"
#include "util/regional.h"
#include "util/net_help.h"
#include "util/config_file.h"
#include "util/data/msgreply.h"
#include "services/cache/dns.h"
#include "services/cache/ladder.h"
#include "sldns/str2wire.h"
#include "sldns/wire2str.h"
#include "sldns/sbuffer.h"
#include "sldns/rrdef.h"
#include "sldns/keyraw.h"

#include "util/data/packed_rrset.h"
#include "validator/val_pqalgo.h"
#include "validator/val_secalgo.h"

#include <mtllib/mtl.h>
#include <time.h>

#include "util/storage/lookup3.h"
#include "util/storage/lruhash.h"
#include "util/storage/slabhash.h"
#include "util/data/packed_rrset.h"

#define TEST_MAX_QUERY_NUM 20
#define TEST_SID_LENGTH 8

uint32_t node_count;
struct config_file *ladder_cache_cfg;

/**
 * Static helper functions for the tests below
 */

static void
test_ladder_cache_count_record(struct lruhash_entry *e, void *ATTR_UNUSED(userdata))
{
    if (e != NULL)
    {
        node_count++;
    }
}

static uint32_t
test_ladder_cache_count_nodes(struct ladder_cache *l)
{
    node_count = 0;
    slabhash_traverse(&l->table, 0, test_ladder_cache_count_record, NULL);
    return node_count;
}

static MTLLIB_BUFFER *
test_ladder_cache_setup_ladder(uint8_t rung_count)
{
    LADDER *test_ladder;
    MTLLIB_BUFFER *mtl_ladder;
    uint8_t sid[] = {0xac,0x03,0x66,0x96,0x74,0x4b,0x7e,0x49,0x53,0xdb,0xe3,0xfc,0xcc,0x9f,0x41,0x1b,
                     0x33,0x3b,0x5c,0xb3,0xda,0x8e,0x26,0x51,0xda,0xc6,0x72,0x3d,0xb7,0xfc,0x8e,0xe9};
    size_t hash_size = 16;
    // Rung (0,3)
    uint8_t rung1_hash[] = {0xe4,0xb5,0x72,0xc1,0x7c,0xee,0x1c,0x78,0x16,0x07,0x3b,0xfe,0x06,0xc0,0x6b,0x9b};
    // Rung (4,5)
    uint8_t rung2_hash[] = {0x70,0x29,0x8f,0x74,0xbe,0xac,0x51,0x98,0xa2,0xbe,0x23,0x3d,0x5d,0xf6,0x63,0xd5};
    uint8_t* buffer_ptr = NULL;
    size_t buffer_ptr_len = 0;

    if (rung_count > 2)
    {
        return NULL;
    }

    // Setup a test ladder to verify the signature with
    test_ladder = calloc(1, sizeof(LADDER));
    if (test_ladder != NULL)
    {
        test_ladder->flags = 0;
        test_ladder->rung_count = rung_count;
        test_ladder->sid.length = hash_size * 2;
        memcpy(test_ladder->sid.id, sid, hash_size * 2);
        test_ladder->rungs = calloc(rung_count, sizeof(RUNG));
        if (rung_count >= 1)
        {
            test_ladder->rungs[0].left_index = 0;
            test_ladder->rungs[0].right_index = 3;
            test_ladder->rungs[0].hash_length = hash_size;
            memcpy(test_ladder->rungs[0].hash, &rung1_hash[0], hash_size);
        }
        if (rung_count >= 2)
        {
            test_ladder->rungs[1].left_index = 4;
            test_ladder->rungs[1].right_index = 5;
            test_ladder->rungs[1].hash_length = hash_size;
            memcpy(test_ladder->rungs[1].hash, &rung2_hash[0], hash_size);
        }
    }

    buffer_ptr_len = mtl_ladder_to_buffer(test_ladder, hash_size, &buffer_ptr);
    // Allocate an internal buffer (with 3rd parameter NULL) so buffer free does the cleanup
    if(mtllib_buffer_initialize(&mtl_ladder, buffer_ptr_len, NULL) != MTLLIB_OK) {
        fprintf(stderr, "  ERROR - Unable to allocate buffer\n");
        return NULL;
    }
    memset(mtl_ladder->buffer_data, 0, buffer_ptr_len);
    memcpy(mtl_ladder->buffer_data, buffer_ptr, buffer_ptr_len);
    mtl_ladder->buffer_position = buffer_ptr_len;
    free(buffer_ptr);

    return mtl_ladder;
}

/**
 * Test the ladder cache creates
 */
static void
test_ladder_cache_create_delete(void)
{
    struct ladder_cache *lc = NULL;

    // Test creating a new ladder cache
    lc = ladder_cache_create(ladder_cache_cfg);
    unit_assert(lc != NULL);
    unit_assert(test_ladder_cache_count_nodes(lc) == 0);

    ladder_cache_delete(lc);

    // test passing in bad parameters
    unit_assert(ladder_cache_create(NULL) == NULL);

    // Make sure delete of NULL does not crach
    ladder_cache_delete(NULL);
}

/**
 * Test the cache adjust/initialize function
 */
static void
test_ladder_cache_adjust(void)
{
    struct config_file *cfg = config_create();
    struct ladder_cache *lc = NULL;
    struct ladder_cache *tmp_lc = NULL;

    // Test creating a new ladder cache
    lc = ladder_cache_adjust(lc, cfg);
    unit_assert(lc != NULL);
    unit_assert(lc->table.size == 4);
    unit_assert(test_ladder_cache_count_nodes(lc) == 0);

    // Test updates to the ladder which require no changes
    tmp_lc = ladder_cache_adjust(lc, cfg);
    unit_assert(lc == tmp_lc);
    unit_assert(tmp_lc->table.size == 4);
    unit_assert(test_ladder_cache_count_nodes(lc) == 0);
    unit_assert(test_ladder_cache_count_nodes(tmp_lc) == 0);

    // Test updates to the ladder which require changes
    cfg->ladder_cache_slabs = 2;
    tmp_lc = ladder_cache_adjust(lc, cfg);

    unit_assert(tmp_lc->table.size == 2);
    unit_assert(test_ladder_cache_count_nodes(tmp_lc) == 0);
    cfg->ladder_cache_slabs = 4;

    // Test null parameters - First param NULL is tested above
    unit_assert(ladder_cache_adjust(tmp_lc, NULL) == NULL);

    ladder_cache_delete(tmp_lc);
    config_delete(cfg);
}

/**
 * Test the cache update and replace function
 */
static void
test_ladder_cache_update(void)
{
    struct ladder_cache *lc = NULL;
    MTLLIB_BUFFER *test_ladder1 = test_ladder_cache_setup_ladder(1);
    MTLLIB_BUFFER *test_ladder2 = test_ladder_cache_setup_ladder(2);
    MTLLIB_BUFFER *test_ladder3 = test_ladder_cache_setup_ladder(2);
    test_ladder3->buffer_data[6] = 0x44;
    size_t hash_size = 16;
    struct domain_name signer_name;
    char labels[] = {3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
    signer_name.length = sizeof(labels);
    memcpy(signer_name.labels, labels, signer_name.length);
    uint8_t i;
    uint8_t sigtags[TEST_MAX_QUERY_NUM][SIGTAG_LEN];
    for (i = 0; i < TEST_MAX_QUERY_NUM; i++) {
        memset(sigtags[i], i, SIGTAG_LEN);
    }

    // Initalize the cache
    lc = ladder_cache_adjust(lc, ladder_cache_cfg);
    unit_assert(lc != NULL);
    unit_assert(lc->table.size == 4);
    unit_assert(test_ladder_cache_count_nodes(lc) == 0);

    // Test adding a ladder to the cache
    unit_assert(ladder_cache_update(lc, test_ladder1, hash_size, sigtags[1], &signer_name) == 1);
    unit_assert(test_ladder_cache_count_nodes(lc) == 1);

    // Test adding a ladder to the cache a second time - should not change
    unit_assert(ladder_cache_update(lc, test_ladder1, hash_size, sigtags[1], &signer_name) == 2);
    unit_assert(test_ladder_cache_count_nodes(lc) == 1);
    mtllib_buffer_free(test_ladder1);

    // Test adding an updated version of the first node (should create a new entry)
    unit_assert(ladder_cache_update(lc, test_ladder2, hash_size, sigtags[2], &signer_name) == 1);
    unit_assert(test_ladder_cache_count_nodes(lc) == 2);
    mtllib_buffer_free(test_ladder2);   

    // Test adding a completely different node (should create a new entry)
    unit_assert(ladder_cache_update(lc, test_ladder3, hash_size, sigtags[3], &signer_name) == 1);
    unit_assert(test_ladder_cache_count_nodes(lc) == 3);

    // Test adding new signature on existing node (should create a new entry)
    unit_assert(ladder_cache_update(lc, test_ladder3, hash_size, sigtags[4], &signer_name) == 1);
    unit_assert(test_ladder_cache_count_nodes(lc) == 4);

    // Test with NULL parameters
    unit_assert(ladder_cache_update(NULL, test_ladder3, hash_size, sigtags[0], &signer_name) == 0);
    unit_assert(test_ladder_cache_count_nodes(lc) == 4);
    unit_assert(ladder_cache_update(lc, NULL, hash_size, sigtags[0], &signer_name) == 0);
    unit_assert(test_ladder_cache_count_nodes(lc) == 4);
    unit_assert(ladder_cache_update(lc, test_ladder3, 0, sigtags[0], &signer_name) == 0);
    unit_assert(test_ladder_cache_count_nodes(lc) == 4);
    unit_assert(ladder_cache_update(lc, test_ladder3, hash_size, NULL, &signer_name) == 0);
    unit_assert(test_ladder_cache_count_nodes(lc) == 4);
    unit_assert(ladder_cache_update(lc, test_ladder3, hash_size, sigtags[0], NULL) == 0);
    unit_assert(test_ladder_cache_count_nodes(lc) == 4);

    mtllib_buffer_free(test_ladder3);
    ladder_cache_delete(lc);
}

/**
 * Test the function that determines if a ladder is in cache
 */
static void
test_ladder_cache_ladder_exists(void)
{
    struct ladder_cache *lc = NULL;
    MTLLIB_BUFFER *test_ladder1 = test_ladder_cache_setup_ladder(1);
    MTLLIB_BUFFER *test_ladder2 = test_ladder_cache_setup_ladder(2);
    MTLLIB_BUFFER *test_ladder3 = test_ladder_cache_setup_ladder(2);
    test_ladder3->buffer_data[6] = 0x44;
    size_t hash_size = 16;
    struct domain_name signer_name;
    char labels[] = {3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
    signer_name.length = sizeof(labels);
    memcpy(signer_name.labels, labels, signer_name.length);
    struct domain_name signer_name2;
    char labels2[] = {3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'n', 'e', 't', 0};
    signer_name2.length = sizeof(labels2);
    memcpy(signer_name2.labels, labels2, signer_name2.length);
    uint8_t i;
    uint8_t sigtags[TEST_MAX_QUERY_NUM][SIGTAG_LEN];
    for (i = 0; i < TEST_MAX_QUERY_NUM; i++) {
        memset(sigtags[i], i, SIGTAG_LEN);
    }

    // Initalize the cache
    lc = ladder_cache_adjust(lc, ladder_cache_cfg);
    unit_assert(lc != NULL);
    unit_assert(lc->table.size == 4);
    unit_assert(test_ladder_cache_count_nodes(lc) == 0);

    // Add a test ladder to the cache
    unit_assert(ladder_cache_update(lc, test_ladder1, hash_size, sigtags[1], &signer_name) == 1);
    unit_assert(test_ladder_cache_count_nodes(lc) == 1);

    // Test with one ladder in cache
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder1, sigtags[1], &signer_name) == 1);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder2, sigtags[2], &signer_name) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder3, sigtags[3], &signer_name) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder1, sigtags[0], &signer_name) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder2, sigtags[0], &signer_name) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder3, sigtags[0], &signer_name) == 0);

    // Add a second ladder to the cache
    unit_assert(ladder_cache_update(lc, test_ladder3, hash_size, sigtags[3], &signer_name) == 1);
    unit_assert(test_ladder_cache_count_nodes(lc) == 2);

    // Test with two ladders in cache
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder1, sigtags[1], &signer_name) == 1);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder2, sigtags[2], &signer_name) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder3, sigtags[3], &signer_name) == 1);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder1, sigtags[0], &signer_name) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder2, sigtags[0], &signer_name) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder3, sigtags[0], &signer_name) == 0);
    
    // Test signer binding
    unit_assert(ladder_cache_update(lc, test_ladder2, hash_size, sigtags[2], &signer_name2) == 1);
    unit_assert(test_ladder_cache_count_nodes(lc) == 3);

    unit_assert(ladder_cache_ladder_exists(lc, test_ladder1, sigtags[1], &signer_name) == 1);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder2, sigtags[2], &signer_name) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder3, sigtags[3], &signer_name) == 1);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder1, sigtags[0], &signer_name) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder2, sigtags[0], &signer_name) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder3, sigtags[0], &signer_name) == 0);

    unit_assert(ladder_cache_ladder_exists(lc, test_ladder1, sigtags[1], &signer_name2) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder2, sigtags[2], &signer_name2) == 1);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder3, sigtags[3], &signer_name2) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder1, sigtags[0], &signer_name2) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder2, sigtags[0], &signer_name2) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder3, sigtags[0], &signer_name2) == 0);


    // Test with null parameters
    unit_assert(ladder_cache_ladder_exists(NULL, test_ladder1, sigtags[1], &signer_name) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, NULL, sigtags[1], &signer_name) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder1, NULL, &signer_name) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder1, sigtags[1], NULL) == 0);

    mtllib_buffer_free(test_ladder1);
    mtllib_buffer_free(test_ladder2);
    mtllib_buffer_free(test_ladder3);
    ladder_cache_delete(lc);
}


/**
 * Test the cache find rung function
 */
static void
test_ladder_cache_find_ladder(void)
{
    struct ladder_cache *lc = NULL;
    MTLLIB_BUFFER *test_ladder = test_ladder_cache_setup_ladder(2);
    SERIESID sid;
    size_t hash_size = 16;
    struct domain_name signer_name;
    uint8_t placeholder[32];
    uint8_t *test_sig_buffer;
    size_t test_sig_buffer_len;
    char labels[] = {3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
    signer_name.length = sizeof(labels);
    memcpy(signer_name.labels, labels, signer_name.length);
    uint8_t sigtag[SIGTAG_LEN] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

    // Initalize the cache
    lc = ladder_cache_adjust(lc, ladder_cache_cfg);
    unit_assert(lc != NULL);
    unit_assert(lc->table.size == 4);
    unit_assert(test_ladder_cache_count_nodes(lc) == 0);

    // Add a test ladder to the cache
    unit_assert(ladder_cache_update(lc, test_ladder, hash_size, sigtag, &signer_name) == 1);
    unit_assert(test_ladder_cache_count_nodes(lc) == 1);

    ladder_buffer_get_sid(test_ladder, hash_size, &sid);
    AUTHPATH test_sig = {
	    .flags = 0,
	    .sid = sid,
	    .leaf_index = 4,
	    .rung_left = 4,
	    .rung_right = 5,
	    .sibling_hash_count = 1,
	    .sibling_hash = placeholder,
    };
    RANDOMIZER r = {
        .length = 16,
        .value = placeholder,
    };
    test_sig_buffer_len = mtl_auth_path_to_buffer(&r, &test_sig, 16, &test_sig_buffer);

    // Test for existing ID
    unit_assert(ladder_cache_find_ladder(lc, test_sig_buffer, test_sig_buffer_len, &signer_name) != NULL);

    // Test for non-existing ID
    test_sig_buffer[4] = 0x44;
    unit_assert(ladder_cache_find_ladder(lc, test_sig_buffer, test_sig_buffer_len, &signer_name) == NULL);
    
    mtllib_buffer_free(test_ladder);
}

/**
 * Test the ladder cache flush function
 */
static void
test_ladder_cache_clear(void)
{
    struct ladder_cache *lc = NULL;
    MTLLIB_BUFFER *test_ladder1 = test_ladder_cache_setup_ladder(1);
    MTLLIB_BUFFER *test_ladder2 = test_ladder_cache_setup_ladder(2);
    MTLLIB_BUFFER *test_ladder3 = test_ladder_cache_setup_ladder(2);
    test_ladder3->buffer_data[6] = 0x44;
    size_t hash_size = 16;
    struct domain_name signer_name;
    char labels[] = {3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
    signer_name.length = sizeof(labels);
    memcpy(signer_name.labels, labels, signer_name.length);
    uint8_t i;
    uint8_t sigtags[TEST_MAX_QUERY_NUM][SIGTAG_LEN];
    for (i = 0; i < TEST_MAX_QUERY_NUM; i++) {
        memset(sigtags[i], i, SIGTAG_LEN);
    }

    // Initalize the cache
    lc = ladder_cache_adjust(lc, ladder_cache_cfg);
    unit_assert(lc != NULL);
    unit_assert(lc->table.size == 4);
    unit_assert(test_ladder_cache_count_nodes(lc) == 0);

    // Add a test ladder to the cache
    unit_assert(ladder_cache_update(lc, test_ladder1, hash_size, sigtags[0], &signer_name) == 1);
    unit_assert(test_ladder_cache_count_nodes(lc) == 1);

    // Add a second ladder to the cache
    unit_assert(ladder_cache_update(lc, test_ladder3, hash_size, sigtags[1], &signer_name) == 1);
    unit_assert(test_ladder_cache_count_nodes(lc) == 2);

    // Test clearing the cache
    ladder_cache_clear(lc);
    unit_assert(test_ladder_cache_count_nodes(lc) == 0);

    // Test clearing the cache with NULL parameter
    ladder_cache_clear(NULL);
    unit_assert(test_ladder_cache_count_nodes(lc) == 0);

    mtllib_buffer_free(test_ladder1);
    mtllib_buffer_free(test_ladder2);
    mtllib_buffer_free(test_ladder3);
    ladder_cache_delete(lc);
}

/**
 * Update the LRU access for a given ladder reference
 */
static void
test_ladder_cache_touch(void)
{
    struct ladder_cache *lc = NULL;
    MTLLIB_BUFFER *test_ladder = test_ladder_cache_setup_ladder(2);

    struct domain_name signer_name;
    char labels[] = {3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
    signer_name.length = sizeof(labels);
    memcpy(signer_name.labels, labels, signer_name.length);

    hashvalue_type h = 0;
    uint16_t i;
    // uint16_t s;
    uint8_t sids[12][TEST_SID_LENGTH] =
        {{0x01, 0x7b, 0x9f, 0x9b, 0xb6, 0x9d, 0x69, 0x63},
         {0x02, 0x48, 0x61, 0xea, 0x84, 0xe1, 0xe3, 0xb6},
         {0x03, 0x31, 0xe2, 0x3d, 0x0f, 0x93, 0xd7, 0x91},
         {0x04, 0x2e, 0x28, 0xd2, 0xe2, 0xfa, 0xd9, 0xfd},
         {0x05, 0x78, 0x98, 0x2b, 0x15, 0x02, 0x8f, 0x3b},
         {0x06, 0xf0, 0x25, 0xce, 0xd2, 0x08, 0x84, 0xa0},
         {0x07, 0x69, 0x9d, 0xb6, 0x9b, 0x9f, 0x7b, 0x1b},
         {0x08, 0xe3, 0xe1, 0x84, 0xea, 0x61, 0x48, 0x26},
         {0x09, 0xd7, 0x93, 0x0f, 0x3d, 0xe2, 0x31, 0xce},
         {0x0a, 0xd9, 0xfa, 0xe2, 0xd2, 0x28, 0x2e, 0xb6},
         {0x0b, 0x8f, 0x02, 0x15, 0x2b, 0x98, 0x78, 0x75},
         {0x0c, 0x84, 0x08, 0xd2, 0xce, 0x25, 0xf0, 0x4a}};
    size_t hash_size = TEST_SID_LENGTH / 2;  
    SERIESID sid;
    uint8_t sigtags[TEST_MAX_QUERY_NUM][SIGTAG_LEN];
    for (i = 0; i < TEST_MAX_QUERY_NUM; i++) {
        memset(sigtags[i], i, SIGTAG_LEN);
    }

    // Initalize the cache
    lc = ladder_cache_adjust(lc, ladder_cache_cfg);
    unit_assert(lc != NULL);
    unit_assert(lc->table.size == 4);
    unit_assert(test_ladder_cache_count_nodes(lc) == 0);

    for(i=0; i<12; i++) {
        memcpy(&test_ladder->buffer_data[6],&sids[i], TEST_SID_LENGTH);
        unit_assert(ladder_cache_update(lc, test_ladder, hash_size, sigtags[i], &signer_name) == 1);
    }

    // Check the LRU Table
    ladder_buffer_get_sid(test_ladder, hash_size, &sid);
    h = hashlittle(&signer_name.labels, signer_name.length, 0xaa);
    struct lruhash *table = slabhash_gettable(&lc->table, h);

    struct lruhash_entry *last = table->lru_end;
    struct lruhash_entry *first = table->lru_start;

    // Verify the current LRU state
    unit_assert(table->lru_start != table->lru_end);
    unit_assert(table->lru_start != last);
    unit_assert(table->lru_end == last);

    // Touch the ladder
    ladder_cache_touch(lc, last->data, last, hash_size);

    // Verify the current LRU state
    unit_assert(table->lru_start != table->lru_end);
    unit_assert(table->lru_start == last);
    unit_assert(table->lru_end != last);
    unit_assert(table->lru_start != first);

    mtllib_buffer_free(test_ladder);
    ladder_cache_delete(lc);
}

/**
 * Test the cache record size calculations
 */
static void
test_ladder_cache_sizefunc(void)
{
    MTLLIB_BUFFER *test_ladder1 = test_ladder_cache_setup_ladder(1);
    MTLLIB_BUFFER *test_ladder2 = test_ladder_cache_setup_ladder(2);
    // Cache Ladder Function Size is the sum of the following:
    //    LRU Key Size        (400 bytes)
    //    * TAG                 (32 bytes)
    //    * Domain              (257 bytes + 3 alignment bytes)
    //    * LRU Entry           (104 bytes + 4 alignment bytes)
    //    MTLLIB_BUFFER Size  (32 bytes)
    //    MTLIB Signed Buffer (TBD bytes) - See draft-kaizer-dnsop-ml-dsa-mtl-dnssec specification for this size
    //    LRU Lock Size       (0 bytes)
    const size_t test_ladder1_size = 432 + test_ladder1->buffer_position;  
    const size_t test_ladder2_size = 432 + test_ladder2->buffer_position;
    size_t hash_size = 16;
    SERIESID sid;

    ladder_buffer_get_sid(test_ladder1, hash_size, &sid);

    // Test a single rung ladder
    unit_assert(ladder_cache_sizefunc(&sid, test_ladder1) == test_ladder1_size);

    // Test a double rung ladder
    unit_assert(ladder_cache_sizefunc(&sid, test_ladder2) == test_ladder2_size);

    // Test NULL parameters
    unit_assert(ladder_cache_sizefunc(NULL, test_ladder1) == 0);
    unit_assert(ladder_cache_sizefunc(&sid, NULL) == 0);

    mtllib_buffer_free(test_ladder1);
    mtllib_buffer_free(test_ladder2);
}

/**
 * Test the cache element comparison function
 */
static void
test_ladder_cache_compare(void)
{
    struct ladder_cache_key test1;
    struct ladder_cache_key test2;
    uint8_t tag1[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t tag2[] = {0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8, 0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0};
    char labels1[] = {3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
    char labels2[] = {3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'n', 'e', 't', 0};

    memcpy(&test1.tag, &tag1[0], SIGTAG_LEN);

    memcpy(&test2.tag, &tag1[0], SIGTAG_LEN);

    test1.signer_name.length = sizeof(labels1);
    memcpy(test1.signer_name.labels, labels1, test1.signer_name.length);
    
    test2.signer_name.length = sizeof(labels1);
    memcpy(test2.signer_name.labels, labels1, test2.signer_name.length);

    // Test the same thing
    unit_assert(ladder_cache_compare(&test1, &test2) == 0);

    // Test different tags
    memcpy(&test2.tag, &tag2[0], SIGTAG_LEN);
    unit_assert(ladder_cache_compare(&test1, &test2) == -1);
    unit_assert(ladder_cache_compare(&test2, &test1) == 1);

    // Test different length signers
    test2.signer_name.length--;
    unit_assert(ladder_cache_compare(&test1, &test2) == -1);
    unit_assert(ladder_cache_compare(&test2, &test1) == 1);
    test2.signer_name.length++;

    // Test different signers
    test2.signer_name.length = sizeof(labels2);
    memcpy(test2.signer_name.labels, labels2, test2.signer_name.length);
    unit_assert(ladder_cache_compare(&test1, &test2) == -1);
    unit_assert(ladder_cache_compare(&test2, &test1) == 1);

    // Test NULL values
    unit_assert(ladder_cache_compare(NULL, &test2) == -1);
    unit_assert(ladder_cache_compare(&test1, NULL) == 1);
}

/**
 * Test the ladder cache key free function
 */
static void
test_ladder_cache_key_free(void)
{
    MTLLIB_BUFFER *data_ptr = calloc(1, sizeof(struct ladder_cache_key));

    unit_assert(data_ptr != NULL);
    ladder_cache_key_free(data_ptr, NULL);
    ladder_cache_key_free(NULL, NULL);

    // Since ladder_cache_data_free doesn't return anything
    // and only passes pointer which cannot be updated
    // this test is just checking for segmentation faults
    unit_assert(1 == 1);
}

/**
 * Test the ladder cache data free function
 */
static void
test_ladder_cache_data_free(void)
{
    MTLLIB_BUFFER *data_ptr = test_ladder_cache_setup_ladder(1);

    unit_assert(data_ptr != NULL);
    ladder_cache_data_free(data_ptr, NULL);
    ladder_cache_data_free(NULL, NULL);

    // Since ladder_cache_data_free doesn't return anything
    // and only passes pointer which cannot be updated
    // this test is just checking for segmentation faults
    unit_assert(1 == 1);
}

/**
 * Test the ladder comparison function
 */
static void
test_ladder_cache_is_ladder_equal(void)
{
    MTLLIB_BUFFER *test_ladder1 = test_ladder_cache_setup_ladder(1);
    MTLLIB_BUFFER *test_ladder2 = test_ladder_cache_setup_ladder(2);
    MTLLIB_BUFFER *test_ladder3 = test_ladder_cache_setup_ladder(2);
    size_t hash_size = 16;

    // Test similar ladders
    unit_assert(ladder_cache_is_ladder_equal(test_ladder3, test_ladder2) == 1);

    // Test ladders with different rungs
    unit_assert(ladder_cache_is_ladder_equal(test_ladder1, test_ladder2) == 0);

    // Test with different SID
    test_ladder3->buffer_data[6] = 0x44;
    unit_assert(ladder_cache_is_ladder_equal(test_ladder3, test_ladder2) == 0);

    // Test NULL parameters
    unit_assert(ladder_cache_is_ladder_equal(NULL, test_ladder2) == 0);
    unit_assert(ladder_cache_is_ladder_equal(test_ladder3, NULL) == 0);

    mtllib_buffer_free(test_ladder1);
    mtllib_buffer_free(test_ladder2);
    mtllib_buffer_free(test_ladder3);        
}

/**
 * Test the ladder operation full cycle
 */
static void
test_ladder_cache_full_operation(void)
{
    struct config_file *cfg = config_create();
    struct ladder_cache *lc = NULL;
    MTLLIB_BUFFER *test_ladder = test_ladder_cache_setup_ladder(2);
    hashvalue_type h = 0;
    uint16_t i;
    uint16_t s;
    uint16_t max_node_count = 5;
    uint8_t sids[TEST_MAX_QUERY_NUM][8] =
        {{0x1b, 0x7b, 0x9f, 0x9b, 0xb6, 0x9d, 0x69, 0x63},
         {0x26, 0x48, 0x61, 0xea, 0x84, 0xe1, 0xe3, 0xb6},
         {0xce, 0x31, 0xe2, 0x3d, 0x0f, 0x93, 0xd7, 0x91},
         {0x75, 0x78, 0x98, 0x2b, 0x15, 0x02, 0x8f, 0x3b},
         {0x4a, 0xf0, 0x25, 0xce, 0xd2, 0x08, 0x84, 0xa0},
         {0x3a, 0x66, 0xdd, 0x49, 0xf9, 0xb4, 0xda, 0xaf},
         {0xe2, 0x02, 0x81, 0xc4, 0xfd, 0x5a, 0xc1, 0x72},
         {0xd2, 0x5a, 0x9e, 0xe8, 0x5c, 0x2d, 0x23, 0xa6},
         {0x1d, 0x49, 0x74, 0xef, 0x51, 0xf8, 0x8f, 0x8b},
         {0x5e, 0x6d, 0xd4, 0x57, 0x21, 0xaf, 0x06, 0x04},
         {0xb1, 0x87, 0xc8, 0xae, 0xe2, 0x8a, 0x21, 0xb4},
         {0xe4, 0xbf, 0x9c, 0x40, 0xec, 0xc0, 0xe6, 0x09},
         {0x09, 0x5a, 0xf9, 0x5a, 0x52, 0x88, 0xe6, 0xb0},
         {0xf5, 0xba, 0x07, 0x17, 0x69, 0x0d, 0x1b, 0x1b},
         {0x94, 0xe3, 0xc9, 0x76, 0x6d, 0xea, 0x2b, 0x51},
         {0xa9, 0xc7, 0x91, 0x95, 0x87, 0x77, 0x9f, 0x90},
         {0xd1, 0x98, 0xeb, 0x23, 0x20, 0xd1, 0xd3, 0x16},
         {0x8b, 0xda, 0x2d, 0xf5, 0xe7, 0x48, 0x10, 0x7c},
         {0x2b, 0xd9, 0xf2, 0x99, 0xc4, 0x1d, 0xea, 0x6d}};
    size_t hash_size = 16;

    struct domain_name signer_names[2] = {     // Labels that hash to different buckets
        { .labels = {1, 'a', 3, 'c', 'o', 'm', 0}, .length = 7},
        { .labels = {1, 'f', 3, 'c', 'o', 'm', 0}, .length = 7},
    };
    uint8_t sigtags[TEST_MAX_QUERY_NUM][SIGTAG_LEN];
    for (i = 0; i < TEST_MAX_QUERY_NUM; i++) {
        memset(sigtags[i], i, SIGTAG_LEN);
    }

    uint8_t expected_node_count[TEST_MAX_QUERY_NUM] =
        {1, 2, 3, 3, 4, 4, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6};
    uint8_t bucket_input_list[TEST_MAX_QUERY_NUM] =
        {0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1};



    cfg->ladder_cache_size = 4096;
    cfg->ladder_cache_slabs = 2;

    // Initalize the cache
    lc = ladder_cache_adjust(lc, cfg);
    unit_assert(lc != NULL);
    unit_assert(lc->table.size == 2);
    unit_assert(test_ladder_cache_count_nodes(lc) == 0);

    for (i = 0; i < TEST_MAX_QUERY_NUM; i++)
    {
        // Give each ladder a unique sid
        memcpy(&test_ladder->buffer_data[2], sids[i], TEST_SID_LENGTH);

        // Add the ladder to the cache
        unit_assert(ladder_cache_update(lc, test_ladder, hash_size, sigtags[i], &signer_names[bucket_input_list[i]]) == 1);
        unit_assert(test_ladder_cache_count_nodes(lc) == expected_node_count[i]);
    }

    mtllib_buffer_free(test_ladder);
    ladder_cache_delete(lc);
    config_delete(cfg);
}


/** Test retrieving SigTags */
static void
test_ladder_cache_sigtag(void) {
    uint8_t hash_size = 16;
    MTLLIB_BUFFER *option_data = NULL;
    #define TEST_LADDER_LEN (2 + 32 + 2 + (32 * 2))
    struct domain_name signer_names[4] = {     
        { .labels = {1, 'a', 3, 'c', 'o', 'm', 0}, .length = 7},
        { .labels = {1, 'b', 3, 'c', 'o', 'm', 0}, .length = 7}, // Hashes to same bucket
        { .labels = {1, 'f', 3, 'c', 'o', 'm', 0}, .length = 7}, // Hashes to different bucket
        { .labels = {1, 'g', 3, 'c', 'o', 'm', 0}, .length = 7}, // Uncached domain
    };
    uint8_t ladder[TEST_LADDER_LEN]; // SID and 2 rungs
    MTLLIB_BUFFER *ladder_buff;
    mtllib_buffer_initialize(&ladder_buff, TEST_LADDER_LEN, ladder);
    uint8_t i;
    uint8_t sigtags[TEST_MAX_QUERY_NUM][SIGTAG_LEN];
    for (i = 0; i < TEST_MAX_QUERY_NUM; i++) {
        memset(sigtags[i], i, SIGTAG_LEN);
    }

    struct config_file *cfg = config_create();
    cfg->ladder_cache_slabs = 2;
    struct ladder_cache *lc = ladder_cache_create(cfg);


    // Add test ladders 
    memset(ladder, 1, TEST_LADDER_LEN);
    uint16_to_bytes(ladder, 0); // Flags
    uint16_to_bytes(ladder + 2 + 32, 2); // Rung count
    ladder_cache_update(lc, ladder_buff, hash_size, sigtags[1], &signer_names[0]);

    memset(ladder, 2, TEST_LADDER_LEN);
    uint16_to_bytes(ladder, 0); // Flags
    uint16_to_bytes(ladder + 2 + 32, 2); // Rung count
    ladder_cache_update(lc, ladder_buff, hash_size, sigtags[2], &signer_names[1]);

    memset(ladder, 3, TEST_LADDER_LEN);
    uint16_to_bytes(ladder, 0); // Flags
    uint16_to_bytes(ladder + 2 + 32, 2); // Rung count
    ladder_cache_update(lc, ladder_buff, hash_size, sigtags[3], &signer_names[2]);

    memset(ladder, 4, TEST_LADDER_LEN);
    uint16_to_bytes(ladder, 0); // Flags
    uint16_to_bytes(ladder + 2 + 32, 2); // Rung count
    ladder_cache_update(lc, ladder_buff, hash_size, sigtags[4], &signer_names[0]);

    uint8_t expected_1[] = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
                            4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4};
    uint8_t expected_2[] = {4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,
                            1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}; // Order of SigTags depends on cache state; both considered correct

    // Normal operation
    mtllib_buffer_initialize(&option_data, 3*SIGTAG_LEN, NULL);
    unit_assert(ladder_cache_build_sigtag(lc, &signer_names[0], option_data) == 0);
    unit_assert(mtllib_buffer_in_use(option_data) == 2*SIGTAG_LEN);
    unit_assert((memcmp(mtllib_buffer_data_ptr(option_data), expected_1, 2*SIGTAG_LEN) == 0) || (memcmp(mtllib_buffer_data_ptr(option_data), expected_2, 2*SIGTAG_LEN) == 0));
    mtllib_buffer_free(option_data);

    // Truncated buffer
    mtllib_buffer_initialize(&option_data, 1.5*SIGTAG_LEN, NULL);
    unit_assert(ladder_cache_build_sigtag(lc, &signer_names[0], option_data) == 0);
    unit_assert(mtllib_buffer_in_use(option_data) == 1*SIGTAG_LEN);
    unit_assert((memcmp(mtllib_buffer_data_ptr(option_data), expected_1, 1*SIGTAG_LEN) == 0) || (memcmp(mtllib_buffer_data_ptr(option_data), expected_2, 1*SIGTAG_LEN) == 0));
    mtllib_buffer_free(option_data);

    mtllib_buffer_initialize(&option_data, 0.5*SIGTAG_LEN, NULL);
    unit_assert(ladder_cache_build_sigtag(lc, &signer_names[0], option_data) == 0);
    unit_assert(mtllib_buffer_in_use(option_data) == 0);
    mtllib_buffer_free(option_data);

    // No cached ladder found
    mtllib_buffer_initialize(&option_data, 3*SIGTAG_LEN, NULL);
    unit_assert(ladder_cache_build_sigtag(lc, &signer_names[3], option_data) == 0);
    unit_assert(mtllib_buffer_in_use(option_data) == 0);
    mtllib_buffer_free(option_data);


    // Null checks
    mtllib_buffer_initialize(&option_data, 3*SIGTAG_LEN, NULL);
    unit_assert(ladder_cache_build_sigtag(NULL, &signer_names[0], option_data) == 1);
    unit_assert(ladder_cache_build_sigtag(lc, NULL, option_data) == 1);
    unit_assert(ladder_cache_build_sigtag(lc, &signer_names[0], NULL) == 1);
    unit_assert(mtllib_buffer_in_use(option_data) == 0);
    mtllib_buffer_free(option_data);

}


/** test post-quantum MTL code */
void ladder_cache_test(void)
{
    ladder_cache_cfg = config_create();
    uint8_t test_id = 0;

    unit_show_feature("MTL Ladder Cache");
    test_ladder_cache_create_delete();
    test_ladder_cache_adjust();
    test_ladder_cache_clear();
    test_ladder_cache_is_ladder_equal();
    test_ladder_cache_compare();
    test_ladder_cache_key_free();
    test_ladder_cache_data_free();
    test_ladder_cache_ladder_exists();
    test_ladder_cache_touch();
    test_ladder_cache_sizefunc();
    test_ladder_cache_find_ladder();
    test_ladder_cache_update();
    test_ladder_cache_full_operation();
    test_ladder_cache_sigtag();
    
    config_delete(ladder_cache_cfg);
}