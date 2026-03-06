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
#include "validator/val_pqc_algo.h"

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
    extern PQC_DNSSEC_ALGOS unbound_pqc_val_algos[];

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
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_INDIRECT) == 0);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_PRIVATEDNS) == 0);
    unit_assert(pqalgo_is_post_quantum_algorithm(LDNS_PRIVATEOID) == 0);

    size_t algo_idx = 0;
    while (unbound_pqc_val_algos[algo_idx].name != NULL)
    {
        if(unbound_pqc_val_algos[algo_idx].enabled == ENABLED) {
            unit_assert(pqalgo_is_post_quantum_algorithm(unbound_pqc_val_algos[algo_idx].number) == 1);                    
        } else {
            unit_assert(pqalgo_is_post_quantum_algorithm(unbound_pqc_val_algos[algo_idx].number) == 0);        
        }
        algo_idx++;
    }
}

/**
 * Test validation of MTL signature algorithm IDs
 */
static void
test_pqalgo_is_mtl_mode_algorithm(void)
{
    extern PQC_DNSSEC_ALGOS unbound_pqc_val_algos[];

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
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_INDIRECT) == 0);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_PRIVATEDNS) == 0);
    unit_assert(pqalgo_is_mtl_mode_algorithm(LDNS_PRIVATEOID) == 0);

    size_t algo_idx = 0;
    while (unbound_pqc_val_algos[algo_idx].name != NULL)
    {
        if((unbound_pqc_val_algos[algo_idx].enabled == ENABLED)  && (unbound_pqc_val_algos[algo_idx].library == ALGO_MTLLIB)) {
            unit_assert(pqalgo_is_mtl_mode_algorithm(unbound_pqc_val_algos[algo_idx].number) == 1);                    
        } else {
            unit_assert(pqalgo_is_mtl_mode_algorithm(unbound_pqc_val_algos[algo_idx].number) == 0);        
        }
        algo_idx++;
    }    
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
    size_t hash_size = 16;
    sldns_buffer *message;
    struct module_env *env = test_setup_test_env();

    // Setup a test ladder to verify the signature with   
    MTLLIB_BUFFER *test_pqctest_ladder_buffer = NULL;
    mtllib_buffer_initialize(&test_pqctest_ladder_buffer, pqctest_ladder_buffer_len, pqctest_ladder_buffer);

    // Initalize the ladder cache
    unit_assert(ladder_cache_update(env->ladder_cache, test_pqctest_ladder_buffer, hash_size) == 1);
    mtllib_buffer_free(test_pqctest_ladder_buffer);

    // Setup the signature buffer
    message = sldns_buffer_new(pqctest_message_buffer_len);
    sldns_buffer_write(message, &pqctest_message_buffer[0], pqctest_message_buffer_len);

    // Get the algorithm properties including ID
    PQC_DNSSEC_ALGOS* alg = val_algo_props("SLH-DSA-SHAKE-128s-MTL-SHAKE-128");
    unit_assert(alg != NULL);

    // Verify the raw signature verifies with correct parameters
    // Note: This expects there is a valid ladder in cache
    unit_assert(pqalgo_verify_rrsig_mtl_raw(&pqctest_condensed_sig_buffer[0],
                                            pqctest_condensed_sig_buffer_len,
                                            message,
                                            &pqctest_pubkey_buffer[0],
                                            pqctest_pubkey_buffer_len,
                                            alg->number,
                                            env) == LDNS_STATUS_OK);

    // Test with bad parameters
    unit_assert(pqalgo_verify_rrsig_mtl_raw(NULL,
                                            pqctest_condensed_sig_buffer_len,
                                            message,
                                            &pqctest_pubkey_buffer[0],
                                            pqctest_pubkey_buffer_len,
                                            alg->number,
                                            env) == LDNS_STATUS_CRYPTO_BOGUS);
    unit_assert(pqalgo_verify_rrsig_mtl_raw(&pqctest_condensed_sig_buffer[0],
                                            0,
                                            message,
                                            &pqctest_pubkey_buffer[0],
                                            pqctest_pubkey_buffer_len,
                                            alg->number,
                                            env) == LDNS_STATUS_CRYPTO_BOGUS);
    unit_assert(pqalgo_verify_rrsig_mtl_raw(&pqctest_condensed_sig_buffer[0],
                                            pqctest_condensed_sig_buffer_len,
                                            NULL,
                                            &pqctest_pubkey_buffer[0],
                                            pqctest_pubkey_buffer_len,
                                            alg->number,
                                            env) == LDNS_STATUS_CRYPTO_BOGUS);
    unit_assert(pqalgo_verify_rrsig_mtl_raw(&pqctest_condensed_sig_buffer[0],
                                            pqctest_condensed_sig_buffer_len,
                                            message,
                                            NULL,
                                            pqctest_pubkey_buffer_len,
                                            alg->number,
                                            env) == LDNS_STATUS_CRYPTO_BOGUS);
    unit_assert(pqalgo_verify_rrsig_mtl_raw(&pqctest_condensed_sig_buffer[0],
                                            pqctest_condensed_sig_buffer_len,
                                            message,
                                            &pqctest_pubkey_buffer[0],
                                            0,
                                            alg->number,
                                            env) == LDNS_STATUS_CRYPTO_BOGUS);
    unit_assert(pqalgo_verify_rrsig_mtl_raw(&pqctest_condensed_sig_buffer[0],
                                            pqctest_condensed_sig_buffer_len,
                                            message,
                                            &pqctest_pubkey_buffer[0],
                                            pqctest_pubkey_buffer_len,
                                            0,
                                            env) == LDNS_STATUS_CRYPTO_BOGUS);

    // Test without a cached ladder
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig_mtl_raw(&pqctest_condensed_sig_buffer[0],
                                            pqctest_condensed_sig_buffer_len,
                                            message,
                                            &pqctest_pubkey_buffer[0],
                                            pqctest_pubkey_buffer_len,
                                            alg->number,
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
    struct module_env *env = test_setup_test_env();

    // Get the algorithm properties including ID
    PQC_DNSSEC_ALGOS* alg = val_algo_props("SLH-DSA-SHAKE-128s-MTL-SHAKE-128");
    unit_assert(alg != NULL);
    PQC_DNSSEC_ALGOS* alg_sha = val_algo_props("SLH-DSA-SHA2-128s-MTL-SHA2-128");
    unit_assert(alg_sha != NULL);

    // Use the full signature buffer from the include as it is very large
    unit_assert(pqalgo_verify_rrsig_mtl_ladder(&pqctest_full_sig_buffer[0],
                                               pqctest_full_sig_buffer_len,
                                               &pqctest_pubkey_buffer[0],
                                               pqctest_pubkey_buffer_len,
                                               alg->number,
                                               env) == LDNS_STATUS_OK);
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig_mtl_ladder(NULL,
                                               pqctest_full_sig_buffer_len,
                                               &pqctest_pubkey_buffer[0],
                                               pqctest_pubkey_buffer_len,
                                               alg->number,
                                               env) == LDNS_STATUS_CRYPTO_BOGUS);
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig_mtl_ladder(&pqctest_full_sig_buffer[0],
                                               0,
                                               &pqctest_pubkey_buffer[0],
                                               pqctest_pubkey_buffer_len,
                                               alg->number,
                                               env) == LDNS_STATUS_CRYPTO_BOGUS);
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig_mtl_ladder(&pqctest_full_sig_buffer[0],
                                               1024,
                                               &pqctest_pubkey_buffer[0],
                                               pqctest_pubkey_buffer_len,
                                               alg->number,
                                               env) != LDNS_STATUS_OK);
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig_mtl_ladder(&pqctest_full_sig_buffer[0],
                                               pqctest_full_sig_buffer_len,
                                               NULL,
                                               pqctest_pubkey_buffer_len,
                                               alg->number,
                                               env) == LDNS_STATUS_CRYPTO_BOGUS);
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig_mtl_ladder(&pqctest_full_sig_buffer[0],
                                               pqctest_full_sig_buffer_len,
                                               &pqctest_pubkey_buffer[0],
                                               0,
                                               alg->number,
                                               env) == LDNS_STATUS_CRYPTO_BOGUS);
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig_mtl_ladder(&pqctest_full_sig_buffer[0],
                                               pqctest_full_sig_buffer_len,
                                               &pqctest_pubkey_buffer[0],
                                               16,
                                               alg->number,
                                               env) == LDNS_STATUS_CRYPTO_BOGUS);
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig_mtl_ladder(&pqctest_full_sig_buffer[0],
                                               pqctest_full_sig_buffer_len,
                                               &pqctest_pubkey_buffer[0],
                                               pqctest_pubkey_buffer_len,
                                               alg_sha->number,
                                               env) == LDNS_STATUS_CRYPTO_BOGUS);
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig_mtl_ladder(&pqctest_full_sig_buffer[0],
                                               pqctest_full_sig_buffer_len,
                                               &pqctest_bad_pubkey_buffer[0],
                                               pqctest_pubkey_buffer_len,
                                               alg->number,
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
    sldns_buffer *sig_message = NULL;
    struct module_env *env = test_setup_test_env();

    // Setup the signature buffer
    sig_message = sldns_buffer_new(pqctest_message_buffer_len);
    sldns_buffer_write(sig_message, &pqctest_message_buffer[0], pqctest_message_buffer_len);

    PQC_DNSSEC_ALGOS* alg = val_algo_props("SLH-DSA-SHAKE-128s-MTL-SHAKE-128");
    unit_assert(alg != NULL);
    PQC_DNSSEC_ALGOS* alg_sha = val_algo_props("SLH-DSA-SHA2-128s-MTL-SHA2-128");
    unit_assert(alg_sha != NULL);

    // Verify that a full signature works
    unit_assert(pqalgo_verify_rrsig(sig_message,
                                    &pqctest_full_sig_buffer[0],
                                    pqctest_full_sig_buffer_len,
                                    &pqctest_pubkey_buffer[0],
                                    pqctest_pubkey_buffer_len,
                                    alg->number,
                                    env) == sec_status_secure);

    // Verify a condensed signature now that the ladder is cached
    unit_assert(pqalgo_verify_rrsig(sig_message,
                                    &pqctest_condensed_sig_buffer[0],
                                    pqctest_condensed_sig_buffer_len,
                                    &pqctest_pubkey_buffer[0],
                                    pqctest_pubkey_buffer_len,
                                    alg->number,
                                    env) == sec_status_secure);

    // Verify a condensed signature that has no ladder (request extended query)
    ladder_cache_clear(env->ladder_cache);
    unit_assert(pqalgo_verify_rrsig(sig_message,
                                    &pqctest_condensed_sig_buffer[0],
                                    pqctest_condensed_sig_buffer_len,
                                    &pqctest_pubkey_buffer[0],
                                    pqctest_pubkey_buffer_len,
                                    alg->number,
                                    env) == sec_status_extend);

    // Verify calls with bad parameters
    unit_assert(pqalgo_verify_rrsig(NULL,
                                    &pqctest_full_sig_buffer[0],
                                    pqctest_full_sig_buffer_len,
                                    &pqctest_pubkey_buffer[0],
                                    pqctest_pubkey_buffer_len,
                                    alg->number,
                                    env) == sec_status_bogus);
    unit_assert(pqalgo_verify_rrsig(sig_message,
                                    NULL,
                                    pqctest_full_sig_buffer_len,
                                    &pqctest_pubkey_buffer[0],
                                    pqctest_pubkey_buffer_len,
                                    alg->number,
                                    env) == sec_status_bogus);
    unit_assert(pqalgo_verify_rrsig(sig_message,
                                    &pqctest_full_sig_buffer[0],
                                    0,
                                    &pqctest_pubkey_buffer[0],
                                    pqctest_pubkey_buffer_len,
                                    alg->number,
                                    env) == sec_status_bogus);
    unit_assert(pqalgo_verify_rrsig(sig_message,
                                    &pqctest_full_sig_buffer[0],
                                    pqctest_full_sig_buffer_len,
                                    NULL,
                                    pqctest_pubkey_buffer_len,
                                    alg->number,
                                    env) == sec_status_bogus);
    unit_assert(pqalgo_verify_rrsig(sig_message,
                                    &pqctest_full_sig_buffer[0],
                                    pqctest_full_sig_buffer_len,
                                    &pqctest_pubkey_buffer[0],
                                    0,
                                    alg->number,
                                    env) == sec_status_bogus);
    unit_assert(pqalgo_verify_rrsig(sig_message,
                                    &pqctest_full_sig_buffer[0],
                                    pqctest_full_sig_buffer_len,
                                    &pqctest_pubkey_buffer[0],
                                    pqctest_pubkey_buffer_len,
                                    alg_sha->number,
                                    env) == sec_status_bogus);

    // Verify with a bad key
    unit_assert(pqalgo_verify_rrsig(sig_message,
                                    &pqctest_full_sig_buffer[0],
                                    pqctest_full_sig_buffer_len,
                                    &pqctest_bad_pubkey_buffer[0],
                                    pqctest_pubkey_buffer_len,
                                    alg->number,
                                    env) == sec_status_bogus);
    // Verify secure even though bad key because of cached ladder
    //    and condensed signature
    unit_assert(pqalgo_verify_rrsig(sig_message,
                                    &pqctest_condensed_sig_buffer[0],
                                    pqctest_condensed_sig_buffer_len,
                                    &pqctest_bad_pubkey_buffer[0],
                                    pqctest_pubkey_buffer_len,
                                    alg->number,
                                    env) == sec_status_secure);
    sldns_buffer_free(sig_message);
    test_setup_test_env_free(env);
}

/** test post-quantum MTL code */
void pqalgo_test(void)
{
    unit_show_feature("post-quantum DNSSEC");
    test_bytes_to_uint32();
    test_pqalgo_is_post_quantum_algorithm();
    test_pqalgo_is_mtl_mode_algorithm();
    test_pqalgo_verify_mtl_full_signature();
    test_pqalgo_verify_rrsig_mtl_raw();
    test_pqalgo_verify_rrsig_mtl_ladder();
    test_pqalgo_verify_rrsig();
}