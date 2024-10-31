/*
 * testcode/unitpqalgo.c - MTL PQC Algorithm function tests.
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
 * unit test for post-quantum zone verification.
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

#include "unitpqalgo_full_sig.h"
#include "unitpqalgo_condensed_sig.h"

#include "util/data/packed_rrset.h"
#include "validator/val_pqalgo.h"
#include "validator/val_secalgo.h"

/**
 * Create the worker/daemon environment for the test
 */
static void *
test_setup_test_env(void)
{
    struct module_env *env = NULL;

    env = calloc(1, sizeof(struct module_env));

    env->ladder_cache = NULL;
    env->cfg = config_create();
    env->ladder_cache = ladder_cache_adjust(env->ladder_cache,
                                            env->cfg);
    unit_assert(env->ladder_cache != NULL);

    return env;
}

/**
 * Clean up the worker/daemon environment for the test
 */
static void
test_setup_test_env_free(struct module_env *env)
{
    ladder_cache_delete(env->ladder_cache);
    config_delete(env->cfg);
    free(env);
}

/**
 * Test the sldns key size function
 */
static void
test_sldns_rr_dnskey_key_size_raw(void)
{
    // Note - Key record in bytes is passed is and key bit length is returned
    unit_assert(sldns_rr_dnskey_key_size_raw(NULL, 16,
                                             LDNS_SLH_DSA_MTL_SHA2_128s) == 128);
    unit_assert(sldns_rr_dnskey_key_size_raw(NULL, 16,
                                             LDNS_SLH_DSA_MTL_SHAKE_128s) == 128);
}

/**
 * Test converting bytes to 32 bit uint
 */
static void
test_bytes_to_uint32(void)
{
    uint32_t test_value_1 = 0x97481620;
    uint32_t test_value_2 = 0x7531;
    uint32_t test_value_3 = 0x1;
    uint32_t result;
    uint8_t buffer_1[] = {0x97, 0x48, 0x16, 0x20};
    uint8_t buffer_2[] = {0x00, 0x00, 0x75, 0x31};
    uint8_t buffer_3[] = {0x00, 0x00, 0x00, 0x01};
    const size_t result_bytes = 4;

    unit_assert(bytes_to_uint32(&buffer_1[0], &result) == result_bytes);
    unit_assert(result == test_value_1);
    unit_assert(bytes_to_uint32(&buffer_2[0], &result) == result_bytes);
    unit_assert(result == test_value_2);
    unit_assert(bytes_to_uint32(&buffer_3[0], &result) == result_bytes);
    unit_assert(result == test_value_3);
    unit_assert(bytes_to_uint32(NULL, &result) == 0);
    unit_assert(bytes_to_uint32(&buffer_3[0], NULL) == 0);
}

/**
 * Test validation of post quantum algorithm IDs
 */
static void
test_pqalgo_is_post_quantum_algorithm(void)
{
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_RSAMD5) == 0);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_DH) == 0);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_DSA) == 0);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_ECC) == 0);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_RSASHA1) == 0);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_DSA_NSEC3) == 0);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_RSASHA1_NSEC3) == 0);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_RSASHA256) == 0);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_RSASHA512) == 0);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_ECC_GOST) == 0);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_ECDSAP256SHA256) == 0);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_ECDSAP384SHA384) == 0);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_ED25519) == 0);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_ED448) == 0);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_SLH_DSA_MTL_SHA2_128s) == 1);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_SLH_DSA_MTL_SHAKE_128s) == 1);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_INDIRECT) == 0);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_PRIVATEDNS) == 0);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_PRIVATEOID) == 0);
}

/**
 * Test validation of MTL signature algorithm IDs
 */
static void
test_pqalgo_is_mtl_mode_algorithm(void)
{
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_RSAMD5) == 0);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_DH) == 0);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_DSA) == 0);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_ECC) == 0);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_RSASHA1) == 0);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_DSA_NSEC3) == 0);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_RSASHA1_NSEC3) == 0);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_RSASHA256) == 0);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_RSASHA512) == 0);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_ECC_GOST) == 0);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_ECDSAP256SHA256) == 0);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_ECDSAP384SHA384) == 0);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_ED25519) == 0);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_ED448) == 0);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_SLH_DSA_MTL_SHA2_128s) == 1);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_SLH_DSA_MTL_SHAKE_128s) == 1);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_INDIRECT) == 0);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_PRIVATEDNS) == 0);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_PRIVATEOID) == 0);
}

/**
 * Test the initalization of the MTL parameter set
 */
static void
test_pqalgo_mtl_setup_params()
{
    uint8_t oid_sha2[OID_LEN] = {0x2B, 0xCE, 0x0F, 0x06, 0x0A, 0x10};
    uint8_t oid_shake[OID_LEN] = {0x2B, 0xCE, 0x0F, 0x06, 0x0D, 0x10};
    uint16_t seed_len = 0;
    size_t oid_len = 0;
    uint8_t *oid;
    char oqs_alg_id[64];
    uint16_t key_len;

    unit_assert(pqalgo_mtl_setup_params(LDNS_SLH_DSA_MTL_SHA2_128s,
                                        &seed_len,
                                        &oid_len,
                                        &oid,
                                        &oqs_alg_id[0],
                                        &key_len) == 1);
    unit_assert(seed_len == 16);
    unit_assert(oid_len = 6);
    unit_assert(strncmp(oqs_alg_id,
                        "SPHINCS+-SHA2-128s-simple",
                        32) == 0);
    unit_assert(memcmp(oid, oid_sha2, OID_LEN) == 0);
    unit_assert(key_len == 32);
    free(oid);

    unit_assert(pqalgo_mtl_setup_params(LDNS_SLH_DSA_MTL_SHAKE_128s,
                                        &seed_len,
                                        &oid_len,
                                        &oid,
                                        &oqs_alg_id[0],
                                        &key_len) == 1);
    unit_assert(seed_len == 16);
    unit_assert(oid_len = 6);
    unit_assert(strncmp(oqs_alg_id,
                        "SPHINCS+-SHAKE-128s-simple",
                        32) == 0);
    unit_assert(memcmp(oid, oid_shake, OID_LEN) == 0);
    unit_assert(key_len == 32);
    free(oid);

    unit_assert(pqalgo_mtl_setup_params(LDNS_ECDSAP256SHA256, &seed_len,
                                        &oid_len, &oid, &oqs_alg_id[0],
                                        &key_len) == 0);
    unit_assert(pqalgo_mtl_setup_params(LDNS_SLH_DSA_MTL_SHA2_128s,
                                        NULL,
                                        &oid_len,
                                        &oid,
                                        &oqs_alg_id[0],
                                        &key_len) == 0);
    unit_assert(pqalgo_mtl_setup_params(LDNS_SLH_DSA_MTL_SHA2_128s,
                                        &seed_len,
                                        NULL,
                                        &oid,
                                        &oqs_alg_id[0],
                                        &key_len) == 0);
    unit_assert(pqalgo_mtl_setup_params(LDNS_SLH_DSA_MTL_SHA2_128s,
                                        &seed_len,
                                        &oid_len,
                                        NULL,
                                        &oqs_alg_id[0],
                                        &key_len) == 0);
    unit_assert(pqalgo_mtl_setup_params(LDNS_SLH_DSA_MTL_SHA2_128s,
                                        &seed_len,
                                        &oid_len,
                                        &oid,
                                        NULL,
                                        &key_len) == 0);
    unit_assert(pqalgo_mtl_setup_params(LDNS_SLH_DSA_MTL_SHA2_128s,
                                        &seed_len,
                                        &oid_len,
                                        &oid,
                                        &oqs_alg_id[0],
                                        NULL) == 0);
}

/**
 * Test the helper that indicates if a signature is a full signature
 */
static void
test_pqalgo_verify_mtl_full_signature()
{
    uint8_t full_buffer[] = {0x01, 0xaa, 0xaa, 0xaa, 0xaa};
    uint8_t condensed_buffer[] = {0x00, 0x55, 0x55, 0x55, 0x55};
    uint8_t bad_buffer[] = {0x03, 0xee, 0xee, 0xee, 0xee};

    unit_assert(pqalgo_verify_mtl_full_signature(full_buffer) == 1);
    unit_assert(pqalgo_verify_mtl_full_signature(condensed_buffer) == 0);
    unit_assert(pqalgo_verify_mtl_full_signature(bad_buffer) == 0);
}

/**
 * Test the PQ MTL condensed signature function
 */
static void
test_pqalgo_verify_rrsig_mtl_raw()
{
    LADDER *test_ladder;
    uint8_t sid[] = {0x36, 0xbd, 0xb6, 0xb3, 0xb4, 0x25, 0xed, 0x90};
    uint8_t rung1_hash[] =
        {0xd2, 0xbf, 0xe4, 0xa8, 0xab, 0x4f, 0xf0, 0x2c, 0x04, 0xe8, 0x82, 0x2e,
         0xe1, 0x3b, 0x4f, 0x22}; // 0-3
    uint8_t rung2_hash[] =
        {0x37, 0x99, 0x48, 0x0d, 0x8d, 0x54, 0xb2, 0xed, 0x77, 0xfa, 0x0e, 0x51,
         0xd6, 0xb5, 0x90, 0x18}; // 4-5

    uint8_t key_buffer[] =
        {0x01, 0x8a, 0x0b, 0xc6, 0x37, 0x10, 0xb5, 0xfd, 0x15, 0xf2, 0xe8, 0xac,
         0x9a, 0xa8, 0x99, 0xdb, 0xc3, 0x2e, 0x5b, 0xd3, 0x1f, 0xd4, 0xd5, 0x1d,
         0xa3, 0xe3, 0x8b, 0x24, 0x00, 0x37, 0x5f, 0x62};
    size_t key_buffer_len = 32;
    uint8_t bad_key_buffer[] =
        {0x01, 0xab, 0x7a, 0x93, 0xc0, 0x7c, 0x44, 0x1a, 0x37, 0xb3, 0xeb, 0x9c,
         0x72, 0xd4, 0x85, 0x09, 0x5e, 0x04, 0xfb, 0x37, 0xcc, 0xf2, 0x6d, 0xc0,
         0xa9, 0x33, 0x0a, 0xe4, 0xef, 0x3b, 0xd9, 0x55, 0x0b};
    uint8_t rrset_msg_buff[] =
        {0x00, 0x01, 0xf8, 0x03, 0x00, 0x00, 0x02, 0x58, 0x67, 0x06, 0x98, 0xf7,
         0x66, 0xe1, 0xae, 0xf7, 0xd5, 0x0e, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70,
         0x6c, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x03, 0x77, 0x77, 0x77, 0x07,
         0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x00,
         0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x04, 0x7f, 0x00,
         0x00, 0x02};
    size_t rrset_msg_buff_len = 62;
    sldns_buffer *message;
    struct module_env *env = test_setup_test_env();

    // Setup a test ladder to verify the signature with
    test_ladder = malloc(sizeof(LADDER));
    test_ladder->flags = 0;
    test_ladder->rung_count = 2;
    test_ladder->sid.length = 8;
    memcpy(test_ladder->sid.id, sid, 8);
    test_ladder->rungs = malloc(sizeof(RUNG) * 2);
    test_ladder->rungs[0].left_index = 0;
    test_ladder->rungs[0].right_index = 3;
    test_ladder->rungs[0].hash_length = 16;
    memcpy(test_ladder->rungs[0].hash, &rung1_hash[0], 16);
    test_ladder->rungs[1].left_index = 4;
    test_ladder->rungs[1].right_index = 5;
    test_ladder->rungs[1].hash_length = 16;
    memcpy(test_ladder->rungs[1].hash, &rung2_hash[0], 16);

    // Initalize the ladder cache
    unit_assert(ladder_cache_update(env->ladder_cache, test_ladder) == 1);
    mtl_ladder_free(test_ladder);

    // Setup the signature buffer
    message = sldns_buffer_new(rrset_msg_buff_len);
    sldns_buffer_write(message, &rrset_msg_buff[0], rrset_msg_buff_len);

    // Verify the raw signature verifies with correct parameters
    unit_assert(pqalgo_verify_rrsig_mtl_raw(&condensed_sig_buffer[0],
                                            condensed_sig_buffer_len,
                                            message,
                                            &key_buffer[0],
                                            key_buffer_len,
                                            LDNS_SLH_DSA_MTL_SHA2_128s,
                                            env) == LDNS_STATUS_OK);
    unit_assert(pqalgo_verify_rrsig_mtl_raw(&condensed_sig_buffer[0],
                                            condensed_sig_buffer_len,
                                            message,
                                            &bad_key_buffer[0],
                                            key_buffer_len,
                                            LDNS_SLH_DSA_MTL_SHA2_128s,
                                            env) == LDNS_STATUS_CRYPTO_BOGUS);

    // Test with bad parameters
    unit_assert(pqalgo_verify_rrsig_mtl_raw(NULL,
                                            condensed_sig_buffer_len,
                                            message,
                                            &key_buffer[0],
                                            key_buffer_len,
                                            LDNS_SLH_DSA_MTL_SHA2_128s,
                                            env) == LDNS_STATUS_CRYPTO_BOGUS);
    unit_assert(pqalgo_verify_rrsig_mtl_raw(&condensed_sig_buffer[0],
                                            0,
                                            message,
                                            &key_buffer[0],
                                            key_buffer_len,
                                            LDNS_SLH_DSA_MTL_SHA2_128s,
                                            env) == LDNS_STATUS_CRYPTO_BOGUS);
    unit_assert(pqalgo_verify_rrsig_mtl_raw(&condensed_sig_buffer[0],
                                            condensed_sig_buffer_len,
                                            NULL,
                                            &key_buffer[0],
                                            key_buffer_len,
                                            LDNS_SLH_DSA_MTL_SHA2_128s,
                                            env) == LDNS_STATUS_CRYPTO_BOGUS);
    unit_assert(pqalgo_verify_rrsig_mtl_raw(&condensed_sig_buffer[0],
                                            condensed_sig_buffer_len,
                                            message,
                                            NULL,
                                            key_buffer_len,
                                            LDNS_SLH_DSA_MTL_SHA2_128s,
                                            env) == LDNS_STATUS_CRYPTO_BOGUS);
    unit_assert(pqalgo_verify_rrsig_mtl_raw(&condensed_sig_buffer[0],
                                            condensed_sig_buffer_len,
                                            message,
                                            &key_buffer[0],
                                            0,
                                            LDNS_SLH_DSA_MTL_SHA2_128s,
                                            env) == LDNS_STATUS_CRYPTO_BOGUS);
    unit_assert(pqalgo_verify_rrsig_mtl_raw(&condensed_sig_buffer[0],
                                            condensed_sig_buffer_len,
                                            message,
                                            &key_buffer[0],
                                            key_buffer_len,
                                            LDNS_SLH_DSA_MTL_SHAKE_128s,
                                            env) == LDNS_STATUS_CRYPTO_BOGUS);

    // Test without a cached ladder
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig_mtl_raw(&condensed_sig_buffer[0],
                                            condensed_sig_buffer_len,
                                            message,
                                            &key_buffer[0],
                                            key_buffer_len,
                                            LDNS_SLH_DSA_MTL_SHA2_128s,
                                            env) == LDNS_STATUS_CRYPTO_EXTEND);

    sldns_buffer_free(message);
    test_setup_test_env_free(env);
}

/**
 * Test the PQ MTL ladder signature function
 */
static void
test_pqalgo_verify_rrsig_mtl_ladder()
{
    uint8_t key_buffer[] =
        {0x01, 0x8a, 0x0b, 0xc6, 0x37, 0x10, 0xb5, 0xfd, 0x15, 0xf2, 0xe8, 0xac,
         0x9a, 0xa8, 0x99, 0xdb, 0xc3, 0x2e, 0x5b, 0xd3, 0x1f, 0xd4, 0xd5, 0x1d,
         0xa3, 0xe3, 0x8b, 0x24, 0x00, 0x37, 0x5f, 0x62};
    size_t key_buffer_len = 32;
    uint8_t bad_key_buffer[] =
        {0x01, 0xab, 0x7a, 0x93, 0xc0, 0x7c, 0x44, 0x1a, 0x37, 0xb3, 0xeb, 0x9c,
         0x72, 0xd4, 0x85, 0x09, 0x5e, 0x04, 0xfb, 0x37, 0xcc, 0xf2, 0x6d, 0xc0,
         0xa9, 0x33, 0x0a, 0xe4, 0xef, 0x3b, 0xd9, 0x55, 0x0b};
    struct module_env *env = test_setup_test_env();

    // Use the full signature buffer from the include as it is very large
    unit_assert(pqalgo_verify_rrsig_mtl_ladder(&full_sig_buffer[0],
                                               full_sig_buffer_len,
                                               &key_buffer[0],
                                               key_buffer_len,
                                               LDNS_SLH_DSA_MTL_SHA2_128s,
                                               env) == LDNS_STATUS_OK);
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig_mtl_ladder(NULL,
                                               full_sig_buffer_len,
                                               &key_buffer[0],
                                               key_buffer_len,
                                               LDNS_SLH_DSA_MTL_SHA2_128s,
                                               env) == LDNS_STATUS_CRYPTO_BOGUS);
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig_mtl_ladder(&full_sig_buffer[0],
                                               0,
                                               &key_buffer[0],
                                               key_buffer_len,
                                               LDNS_SLH_DSA_MTL_SHA2_128s,
                                               env) == LDNS_STATUS_CRYPTO_BOGUS);
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig_mtl_ladder(&full_sig_buffer[0],
                                               1024,
                                               &key_buffer[0],
                                               key_buffer_len,
                                               LDNS_SLH_DSA_MTL_SHA2_128s,
                                               env) != LDNS_STATUS_OK);
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig_mtl_ladder(&full_sig_buffer[0],
                                               full_sig_buffer_len,
                                               NULL,
                                               key_buffer_len,
                                               LDNS_SLH_DSA_MTL_SHA2_128s,
                                               env) == LDNS_STATUS_CRYPTO_BOGUS);
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig_mtl_ladder(&full_sig_buffer[0],
                                               full_sig_buffer_len,
                                               &key_buffer[0],
                                               0,
                                               LDNS_SLH_DSA_MTL_SHA2_128s,
                                               env) == LDNS_STATUS_CRYPTO_BOGUS);
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig_mtl_ladder(&full_sig_buffer[0],
                                               full_sig_buffer_len,
                                               &key_buffer[0],
                                               16,
                                               LDNS_SLH_DSA_MTL_SHA2_128s,
                                               env) == LDNS_STATUS_CRYPTO_BOGUS);
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig_mtl_ladder(&full_sig_buffer[0],
                                               full_sig_buffer_len,
                                               &key_buffer[0],
                                               key_buffer_len,
                                               LDNS_SLH_DSA_MTL_SHAKE_128s,
                                               env) == LDNS_STATUS_CRYPTO_BOGUS);
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig_mtl_ladder(&full_sig_buffer[0],
                                               full_sig_buffer_len,
                                               &bad_key_buffer[0],
                                               key_buffer_len,
                                               LDNS_SLH_DSA_MTL_SHA2_128s,
                                               env) == LDNS_STATUS_CRYPTO_BOGUS);
    ladder_cache_clear(env->ladder_cache);
    test_setup_test_env_free(env);
}

/**
 * Test the PQ MTL signature verification function
 */
static void
test_pqalgo_verify_rrsig()
{
    uint8_t key_buffer[] =
        {0x01, 0x8a, 0x0b, 0xc6, 0x37, 0x10, 0xb5, 0xfd, 0x15, 0xf2, 0xe8, 0xac,
         0x9a, 0xa8, 0x99, 0xdb, 0xc3, 0x2e, 0x5b, 0xd3, 0x1f, 0xd4, 0xd5, 0x1d,
         0xa3, 0xe3, 0x8b, 0x24, 0x00, 0x37, 0x5f, 0x62};
    size_t key_buffer_len = 32;
    uint8_t bad_key_buffer[] =
        {0x01, 0xab, 0x7a, 0x93, 0xc0, 0x7c, 0x44, 0x1a, 0x37, 0xb3, 0xeb, 0x9c,
         0x72, 0xd4, 0x85, 0x09, 0x5e, 0x04, 0xfb, 0x37, 0xcc, 0xf2, 0x6d, 0xc0,
         0xa9, 0x33, 0x0a, 0xe4, 0xef, 0x3b, 0xd9, 0x55, 0x0b};
    uint8_t full_sig_src[] =
        {0x00, 0x06, 0xf8, 0x02, 0x00, 0x00, 0x02, 0x58, 0x67, 0x06, 0x98, 0xf7,
         0x66, 0xe1, 0xae, 0xf7, 0xd5, 0x0e, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70,
         0x6c, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d,
         0x70, 0x6c, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x00, 0x06, 0x00, 0x01,
         0x00, 0x00, 0x02, 0x58, 0x00, 0x35, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70,
         0x6c, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x0a, 0x68, 0x6f, 0x73, 0x74,
         0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x03, 0x6e, 0x69, 0x63, 0x03, 0x63,
         0x6f, 0x6d, 0x00, 0x78, 0x57, 0xcf, 0x3d, 0x00, 0x00, 0x2a, 0x30, 0x00,
         0x00, 0x0e, 0x10, 0x00, 0x09, 0x3a, 0x80, 0x00, 0x00, 0x00, 0x3c};
    size_t full_sig_src_len = 107;
    uint8_t cond_sig_src[] =
        {0x00, 0x01, 0xf8, 0x03, 0x00, 0x00, 0x02, 0x58, 0x67, 0x06, 0x98, 0xf7,
         0x66, 0xe1, 0xae, 0xf7, 0xd5, 0x0e, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70,
         0x6c, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x03, 0x77, 0x77, 0x77, 0x07,
         0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x00,
         0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x04, 0x7f, 0x00,
         0x00, 0x02};
    size_t cond_sig_src_len = 62;
    sldns_buffer *full_message;
    sldns_buffer *cond_message;

    struct module_env *env = test_setup_test_env();

    // Setup the signature buffer
    full_message = sldns_buffer_new(full_sig_src_len);
    sldns_buffer_write(full_message, &full_sig_src[0], full_sig_src_len);
    cond_message = sldns_buffer_new(cond_sig_src_len);
    sldns_buffer_write(cond_message, &cond_sig_src[0], cond_sig_src_len);

    // Verify that a full signature works
    unit_assert(pqalgo_verify_rrsig(full_message,
                                    &full_sig_buffer[0],
                                    full_sig_buffer_len,
                                    &key_buffer[0],
                                    key_buffer_len,
                                    LDNS_SLH_DSA_MTL_SHA2_128s,
                                    env) == sec_status_secure);

    // Verify a condensed signature now that the ladder is cached
    unit_assert(pqalgo_verify_rrsig(cond_message,
                                    &condensed_sig_buffer[0],
                                    condensed_sig_buffer_len,
                                    &key_buffer[0],
                                    key_buffer_len,
                                    LDNS_SLH_DSA_MTL_SHA2_128s,
                                    env) == sec_status_secure);

    // Verify a condensed signature that has no ladder (request extended query)
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig(cond_message,
                                    &condensed_sig_buffer[0],
                                    condensed_sig_buffer_len,
                                    &key_buffer[0],
                                    key_buffer_len,
                                    LDNS_SLH_DSA_MTL_SHA2_128s,
                                    env) == sec_status_extend);

    // Verify calls with bad parameters
    unit_assert(pqalgo_verify_rrsig(NULL,
                                    &full_sig_buffer[0],
                                    full_sig_buffer_len,
                                    &key_buffer[0],
                                    key_buffer_len,
                                    LDNS_SLH_DSA_MTL_SHA2_128s,
                                    env) == sec_status_bogus);
    unit_assert(pqalgo_verify_rrsig(full_message,
                                    NULL,
                                    full_sig_buffer_len,
                                    &key_buffer[0],
                                    key_buffer_len,
                                    LDNS_SLH_DSA_MTL_SHA2_128s,
                                    env) == sec_status_bogus);
    unit_assert(pqalgo_verify_rrsig(full_message,
                                    &full_sig_buffer[0],
                                    0,
                                    &key_buffer[0],
                                    key_buffer_len,
                                    LDNS_SLH_DSA_MTL_SHA2_128s,
                                    env) == sec_status_bogus);
    unit_assert(pqalgo_verify_rrsig(full_message,
                                    &full_sig_buffer[0],
                                    full_sig_buffer_len,
                                    NULL,
                                    key_buffer_len,
                                    LDNS_SLH_DSA_MTL_SHA2_128s,
                                    env) == sec_status_bogus);
    unit_assert(pqalgo_verify_rrsig(full_message,
                                    &full_sig_buffer[0],
                                    full_sig_buffer_len,
                                    &key_buffer[0],
                                    0,
                                    LDNS_SLH_DSA_MTL_SHA2_128s,
                                    env) == sec_status_bogus);
    unit_assert(pqalgo_verify_rrsig(full_message,
                                    &full_sig_buffer[0],
                                    full_sig_buffer_len,
                                    &key_buffer[0],
                                    key_buffer_len,
                                    LDNS_SLH_DSA_MTL_SHAKE_128s,
                                    env) == sec_status_bogus);

    // Verify with a bad key
    unit_assert(pqalgo_verify_rrsig(full_message,
                                    &full_sig_buffer[0],
                                    full_sig_buffer_len,
                                    &bad_key_buffer[0],
                                    key_buffer_len,
                                    LDNS_SLH_DSA_MTL_SHA2_128s,
                                    env) == sec_status_bogus);
    unit_assert(pqalgo_verify_rrsig(cond_message,
                                    &condensed_sig_buffer[0],
                                    condensed_sig_buffer_len,
                                    &bad_key_buffer[0],
                                    key_buffer_len,
                                    LDNS_SLH_DSA_MTL_SHA2_128s,
                                    env) == sec_status_bogus);
    sldns_buffer_free(cond_message);
    sldns_buffer_free(full_message);
    test_setup_test_env_free(env);
}

/** test post-quantum MTL code */
void pqalgo_test(void)
{
    unit_show_feature("post-quantum DNSSEC");
    test_sldns_rr_dnskey_key_size_raw();
    test_bytes_to_uint32();
    test_pqalgo_is_post_quantum_algorithm();
    test_pqalgo_is_mtl_mode_algorithm();
    test_pqalgo_mtl_setup_params();
    test_pqalgo_verify_mtl_full_signature();
    test_pqalgo_verify_rrsig_mtl_raw();
    test_pqalgo_verify_rrsig_mtl_ladder();
    test_pqalgo_verify_rrsig();
}