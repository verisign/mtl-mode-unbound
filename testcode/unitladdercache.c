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

static LADDER *
test_ladder_cache_setup_ladder(uint8_t rung_count)
{
    LADDER *test_ladder;
    uint8_t sid[] = {0x36, 0xbd, 0xb6, 0xb3, 0xb4, 0x25, 0xed, 0x90};
    uint8_t rung1_hash[] = {0xd2, 0xbf, 0xe4, 0xa8, 0xab, 0x4f, 0xf0, 0x2c,
                            0x04, 0xe8, 0x82, 0x2e, 0xe1, 0x3b, 0x4f, 0x22}; // 0-3
    uint8_t rung2_hash[] = {0x37, 0x99, 0x48, 0x0d, 0x8d, 0x54, 0xb2, 0xed,
                            0x77, 0xfa, 0x0e, 0x51, 0xd6, 0xb5, 0x90, 0x18}; // 4-5

    if (rung_count > 2)
    {
        return NULL;
    }

    // Setup a test ladder to verify the signature with
    test_ladder = malloc(sizeof(LADDER));
    if (test_ladder != NULL)
    {
        test_ladder->flags = 0;
        test_ladder->rung_count = rung_count;
        test_ladder->sid.length = 8;
        memcpy(test_ladder->sid.id, sid, 8);
        test_ladder->rungs = malloc(sizeof(RUNG) * rung_count);
        if (rung_count >= 1)
        {
            test_ladder->rungs[0].left_index = 0;
            test_ladder->rungs[0].right_index = 3;
            test_ladder->rungs[0].hash_length = 16;
            memcpy(test_ladder->rungs[0].hash, &rung1_hash[0], 16);
        }
        if (rung_count >= 2)
        {
            test_ladder->rungs[1].left_index = 4;
            test_ladder->rungs[1].right_index = 5;
            test_ladder->rungs[1].hash_length = 16;
            memcpy(test_ladder->rungs[1].hash, &rung2_hash[0], 16);
        }
    }

    return test_ladder;
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
    unit_assert(lc != tmp_lc);
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
    LADDER *test_ladder1 = test_ladder_cache_setup_ladder(1);
    LADDER *test_ladder2 = test_ladder_cache_setup_ladder(2);
    LADDER *test_ladder3 = test_ladder_cache_setup_ladder(2);
    test_ladder3->sid.id[4] = 0x44;

    // Initalize the cache
    lc = ladder_cache_adjust(lc, ladder_cache_cfg);
    unit_assert(lc != NULL);
    unit_assert(lc->table.size == 4);
    unit_assert(test_ladder_cache_count_nodes(lc) == 0);

    // Test adding a ladder to the cache
    unit_assert(ladder_cache_update(lc, test_ladder1) == 1);
    unit_assert(test_ladder_cache_count_nodes(lc) == 1);

    // Test adding a ladder to the cache a second time - no change
    unit_assert(ladder_cache_update(lc, test_ladder1) == 2);
    unit_assert(test_ladder_cache_count_nodes(lc) == 1);
    mtl_ladder_free(test_ladder1);

    // Test adding a modified version of the first node
    unit_assert(ladder_cache_update(lc, test_ladder2) == 1);
    unit_assert(test_ladder_cache_count_nodes(lc) == 1);
    mtl_ladder_free(test_ladder2);

    // Test adding a completely different node
    unit_assert(ladder_cache_update(lc, test_ladder3) == 1);
    unit_assert(test_ladder_cache_count_nodes(lc) == 2);

    // Test with NULL parameters
    unit_assert(ladder_cache_update(NULL, test_ladder3) == 0);
    unit_assert(test_ladder_cache_count_nodes(lc) == 2);
    unit_assert(ladder_cache_update(lc, NULL) == 0);
    unit_assert(test_ladder_cache_count_nodes(lc) == 2);

    mtl_ladder_free(test_ladder3);
    ladder_cache_delete(lc);
}

/**
 * Test the function that determines if a ladder is in cache
 */
static void
test_ladder_cache_ladder_exists(void)
{
    struct ladder_cache *lc = NULL;
    LADDER *test_ladder1 = test_ladder_cache_setup_ladder(1);
    LADDER *test_ladder2 = test_ladder_cache_setup_ladder(2);
    LADDER *test_ladder3 = test_ladder_cache_setup_ladder(2);
    test_ladder3->sid.id[4] = 0x44;

    // Initalize the cache
    lc = ladder_cache_adjust(lc, ladder_cache_cfg);
    unit_assert(lc != NULL);
    unit_assert(lc->table.size == 4);
    unit_assert(test_ladder_cache_count_nodes(lc) == 0);

    // Add a test ladder to the cache
    unit_assert(ladder_cache_update(lc, test_ladder1) == 1);
    unit_assert(test_ladder_cache_count_nodes(lc) == 1);

    // Test with one ladder in cache
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder1) == 1);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder2) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder3) == 0);

    // Add a second ladder to the cache
    unit_assert(ladder_cache_update(lc, test_ladder3) == 1);
    unit_assert(test_ladder_cache_count_nodes(lc) == 2);

    // Test with two ladders in cache
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder1) == 1);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder2) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, test_ladder3) == 1);

    // Test with null parameters
    unit_assert(ladder_cache_ladder_exists(NULL, test_ladder1) == 0);
    unit_assert(ladder_cache_ladder_exists(lc, NULL) == 0);

    mtl_ladder_free(test_ladder1);
    mtl_ladder_free(test_ladder2);
    mtl_ladder_free(test_ladder3);
    ladder_cache_delete(lc);
}

/**
 * Test the cache find rung function
 */
static void
test_ladder_cache_find_rung(void)
{
    struct ladder_cache *lc = NULL;
    LADDER *test_ladder = test_ladder_cache_setup_ladder(2);
    AUTHPATH auth;

    // Initalize the cache
    lc = ladder_cache_adjust(lc, ladder_cache_cfg);
    unit_assert(lc != NULL);
    unit_assert(lc->table.size == 4);
    unit_assert(test_ladder_cache_count_nodes(lc) == 0);

    // Add a test ladder to the cache
    unit_assert(ladder_cache_update(lc, test_ladder) == 1);
    unit_assert(test_ladder_cache_count_nodes(lc) == 1);

    auth.sid.length = test_ladder->sid.length;
    memcpy(&auth.sid.id, test_ladder->sid.id, auth.sid.length);

    // Test for existing path
    auth.leaf_index = 4;
    auth.sibling_hash_count = 1;
    auth.rung_left = 4;
    auth.rung_right = 5;
    unit_assert(ladder_cache_find_rung(lc, &auth) != NULL);

    // Test for existing path with multiple depth
    auth.leaf_index = 0;
    auth.sibling_hash_count = 2;
    auth.rung_left = 0;
    auth.rung_right = 3;
    unit_assert(ladder_cache_find_rung(lc, &auth) != NULL);

    // Test for non-existing path (leaf index)
    auth.leaf_index = 7;
    auth.sibling_hash_count = 4;
    auth.rung_left = 0;
    auth.rung_right = 7;
    unit_assert(ladder_cache_find_rung(lc, &auth) == NULL);

    // Test for non-existing path (SID)
    auth.sid.id[4] = 0x44;
    auth.leaf_index = 0;
    auth.sibling_hash_count = 2;
    auth.rung_left = 0;
    auth.rung_right = 3;
    unit_assert(ladder_cache_find_rung(lc, &auth) == NULL);

    // Test with NULL parameters
    auth.sid.id[4] = 0xb4;
    auth.leaf_index = 4;
    auth.sibling_hash_count = 1;
    auth.rung_left = 4;
    auth.rung_right = 5;
    unit_assert(ladder_cache_find_rung(lc, &auth) != NULL);
    unit_assert(ladder_cache_find_rung(NULL, &auth) == NULL);
    unit_assert(ladder_cache_find_rung(lc, NULL) == NULL);

    mtl_ladder_free(test_ladder);
    ladder_cache_delete(lc);
}

/**
 * Test the ladder cache flush function
 */
static void
test_ladder_cache_clear(void)
{
    struct ladder_cache *lc = NULL;
    LADDER *test_ladder1 = test_ladder_cache_setup_ladder(1);
    LADDER *test_ladder2 = test_ladder_cache_setup_ladder(2);
    LADDER *test_ladder3 = test_ladder_cache_setup_ladder(2);
    test_ladder3->sid.id[4] = 0x44;

    // Initalize the cache
    lc = ladder_cache_adjust(lc, ladder_cache_cfg);
    unit_assert(lc != NULL);
    unit_assert(lc->table.size == 4);
    unit_assert(test_ladder_cache_count_nodes(lc) == 0);

    // Add a test ladder to the cache
    unit_assert(ladder_cache_update(lc, test_ladder1) == 1);
    unit_assert(test_ladder_cache_count_nodes(lc) == 1);

    // Add a second ladder to the cache
    unit_assert(ladder_cache_update(lc, test_ladder3) == 1);
    unit_assert(test_ladder_cache_count_nodes(lc) == 2);

    // Test clearing the cache
    ladder_cache_clear(lc);
    unit_assert(test_ladder_cache_count_nodes(lc) == 0);

    // Test clearing the cache with NULL parameter
    ladder_cache_clear(NULL);
    unit_assert(test_ladder_cache_count_nodes(lc) == 0);

    mtl_ladder_free(test_ladder1);
    mtl_ladder_free(test_ladder2);
    mtl_ladder_free(test_ladder3);
    ladder_cache_delete(lc);
}

/**
 * Update the LRU access for a given ladder reference
 */
static void
test_ladder_cache_touch(void)
{
    struct ladder_cache *lc = NULL;
    LADDER *test_ladder = test_ladder_cache_setup_ladder(2);
    hashvalue_type h = 0;
    uint16_t i;
    uint16_t s;
    uint8_t sids[6][TEST_SID_LENGTH] =
        {{0x1b, 0x7b, 0x9f, 0x9b, 0xb6, 0x9d, 0x69, 0x63},
         {0x26, 0x48, 0x61, 0xea, 0x84, 0xe1, 0xe3, 0xb6},
         {0xce, 0x31, 0xe2, 0x3d, 0x0f, 0x93, 0xd7, 0x91},
         {0xb6, 0x2e, 0x28, 0xd2, 0xe2, 0xfa, 0xd9, 0xfd},
         {0x75, 0x78, 0x98, 0x2b, 0x15, 0x02, 0x8f, 0x3b},
         {0x4a, 0xf0, 0x25, 0xce, 0xd2, 0x08, 0x84, 0xa0}};

    // Initalize the cache
    lc = ladder_cache_adjust(lc, ladder_cache_cfg);
    unit_assert(lc != NULL);
    unit_assert(lc->table.size == 4);
    unit_assert(test_ladder_cache_count_nodes(lc) == 0);

    for (i = 0; i < 6; i++)
    {
        // Give each ladder a unique sid
        test_ladder->sid.length = TEST_SID_LENGTH;
        memcpy(test_ladder->sid.id, &sids[i], TEST_SID_LENGTH);

        // Add the ladder to the cache
        unit_assert(ladder_cache_update(lc, test_ladder) == 1);
        unit_assert(test_ladder_cache_count_nodes(lc) == (i + 1));
    }

    // Check the LRU Table
    h = hashlittle(test_ladder->sid.id, test_ladder->sid.length, 0xaa);
    struct lruhash *table = slabhash_gettable(&lc->table, h);

    struct lruhash_entry *last = table->lru_end;
    struct lruhash_entry *first = table->lru_start;
    LADDER *ladder = (LADDER *)last->data;
    h = hashlittle(ladder->sid.id, ladder->sid.length, 0xaa);

    // Verify the current LRU state
    unit_assert(table->lru_start != table->lru_end);
    unit_assert(table->lru_start != last);
    unit_assert(table->lru_end == last);

    // Touch the ladder
    ladder_cache_touch(lc, ladder, last);

    // Verify the current LRU state
    unit_assert(table->lru_start != table->lru_end);
    unit_assert(table->lru_start == last);
    unit_assert(table->lru_end != last);
    unit_assert(table->lru_start != first);

    mtl_ladder_free(test_ladder);
    ladder_cache_delete(lc);
}

/**
 * Test the cache record size calculations
 */
static void
test_ladder_cache_sizefunc(void)
{
    LADDER *test_ladder1 = test_ladder_cache_setup_ladder(1);
    LADDER *test_ladder2 = test_ladder_cache_setup_ladder(2);
    RUNG *rungs = NULL;
    LADDER *new_rec = NULL;

    new_rec = (LADDER *)calloc(1, sizeof(LADDER));
    rungs = (RUNG *)calloc(2, sizeof(RUNG));
    unit_assert(new_rec != NULL);

    // Test a single rung ladder
    memcpy(new_rec, test_ladder1, sizeof(LADDER));
    new_rec->rungs = rungs;
    memcpy(new_rec->rungs, test_ladder1->rungs, sizeof(RUNG) * test_ladder1->rung_count);
    unit_assert(ladder_cache_sizefunc(&test_ladder1->sid, new_rec) == 332);

    // Test a double rung ladder
    memcpy(new_rec, test_ladder2, sizeof(LADDER));
    new_rec->rungs = rungs;
    memcpy(new_rec->rungs, test_ladder2->rungs, sizeof(RUNG) * test_ladder2->rung_count);
    unit_assert(ladder_cache_sizefunc(&test_ladder2->sid, new_rec) == 408);

    // Test NULL parameters
    unit_assert(ladder_cache_sizefunc(NULL, new_rec) == 0);
    unit_assert(ladder_cache_sizefunc(&test_ladder2->sid, NULL) == 0);

    mtl_ladder_free(test_ladder1);
    mtl_ladder_free(test_ladder2);
    free(new_rec);
    free(rungs);
}

/**
 * Test the cache element comparison function
 */
static void
test_ladder_cache_compare(void)
{
    SERIESID test1;
    SERIESID test2;
    uint8_t sid1[] = {0x36, 0xbd, 0xb6, 0xb3, 0xb4, 0x25, 0xed, 0x90};
    uint8_t sid2[] = {0x36, 0xbd, 0xb8, 0xb3, 0xb4, 0x25, 0xed, 0xaa, 0x29, 0x11};

    test1.length = 8;
    memcpy(&test1.id, &sid1[0], test1.length);

    test2.length = 8;
    memcpy(&test2.id, &sid1[0], test2.length);

    // Test the same thing
    unit_assert(ladder_cache_compare(&test1, &test2) == 0);

    // Test different lengths
    test2.length = 10;
    memcpy(&test2.id, &sid2[0], test2.length);
    unit_assert(ladder_cache_compare(&test1, &test2) == -1);
    unit_assert(ladder_cache_compare(&test2, &test1) == 1);

    // Test different SIDS
    test2.length = 8;
    memcpy(&test2.id, &sid2[0], test2.length);
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
    LADDER *data_ptr = calloc(1, sizeof(struct ladder_cache_key));

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
    LADDER *data_ptr = test_ladder_cache_setup_ladder(1);

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
    LADDER *test_ladder1 = test_ladder_cache_setup_ladder(1);
    LADDER *test_ladder2 = test_ladder_cache_setup_ladder(2);
    LADDER *test_ladder3 = test_ladder_cache_setup_ladder(2);

    // Test similar ladders
    unit_assert(ladder_cache_is_ladder_equal(test_ladder3, test_ladder2) == 1);

    // Test ladders with different rungs
    unit_assert(ladder_cache_is_ladder_equal(test_ladder1, test_ladder2) == 0);

    // Test with different SID
    test_ladder3->sid.id[4] = 0x44;
    unit_assert(ladder_cache_is_ladder_equal(test_ladder3, test_ladder2) == 0);

    // Test NULL parameters
    unit_assert(ladder_cache_is_ladder_equal(NULL, test_ladder2) == 0);
    unit_assert(ladder_cache_is_ladder_equal(test_ladder3, NULL) == 0);

    mtl_ladder_free(test_ladder1);
    mtl_ladder_free(test_ladder2);
    mtl_ladder_free(test_ladder3);
}

/**
 * Test the ladder operation full cycle
 */
static void
test_ladder_cache_full_operation(void)
{
    struct config_file *cfg = config_create();
    struct ladder_cache *lc = NULL;
    LADDER *test_ladder = test_ladder_cache_setup_ladder(2);
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
    uint8_t node_count[TEST_MAX_QUERY_NUM] =
        {1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4};

    cfg->ladder_cache_size = 2048;
    cfg->ladder_cache_slabs = 2;

    // Initalize the cache
    lc = ladder_cache_adjust(lc, cfg);
    unit_assert(lc != NULL);
    unit_assert(lc->table.size == 2);
    unit_assert(test_ladder_cache_count_nodes(lc) == 0);

    for (i = 0; i < TEST_MAX_QUERY_NUM; i++)
    {
        // Give each ladder a unique sid
        test_ladder->sid.length = TEST_SID_LENGTH;
        memcpy(test_ladder->sid.id, sids[i], TEST_SID_LENGTH);

        // Add the ladder to the cache
        unit_assert(ladder_cache_update(lc, test_ladder) == 1);
        unit_assert(test_ladder_cache_count_nodes(lc) == node_count[i]);
    }

    mtl_ladder_free(test_ladder);
    ladder_cache_delete(lc);
    config_delete(cfg);
}

/** test post-quantum MTL code */
void ladder_cache_test(void)
{
    ladder_cache_cfg = config_create();
    uint8_t test_id = 0;

    unit_show_feature("MTL Ladder Cache");
    test_ladder_cache_create_delete();
    test_ladder_cache_adjust();
    test_ladder_cache_update();
    test_ladder_cache_ladder_exists();
    test_ladder_cache_find_rung();
    test_ladder_cache_clear();
    test_ladder_cache_touch();
    test_ladder_cache_sizefunc();
    test_ladder_cache_compare();
    test_ladder_cache_key_free();
    test_ladder_cache_data_free();
    test_ladder_cache_is_ladder_equal();
    test_ladder_cache_full_operation();

    config_delete(ladder_cache_cfg);
}