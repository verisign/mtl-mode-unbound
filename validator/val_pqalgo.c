/*
 * validator/val_pqalgo.c - validator post-quantum security algorithm functions.
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
 * This file contains helper functions for the validator module.
 * These functions take raw data buffers, formatted for crypto verification,
 * and do the library calls (for post-quantum signature algorithms).
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "config.h"
/* packed_rrset on top to define enum types (forced by c99 standard) */
#include "util/data/packed_rrset.h"
#include "validator/val_pqalgo.h"
#include "validator/val_secalgo.h"
#include "validator/val_nsec3.h"
#include "util/log.h"
#include "util/module.h"
#include "sldns/rrdef.h"
#include "sldns/keyraw.h"
#include "sldns/sbuffer.h"
#include "services/cache/ladder.h"

#include <mtllib/mtl.h>
#include <mtllib/mtl_spx.h>
#include <oqs/sig.h>

/**
 * Convert a 32 bit endian byte array to unsigned integer
 * @param buffer:     Byte array input
 * @param value:      Unsigned 32 bit integer result
 * @return number of bytes for input
 */
size_t bytes_to_uint32(unsigned char *buffer, uint32_t *value)
{
    if ((buffer == NULL) || (value == NULL))
    {
        return 0;
    }
    *value = 0;

    if (BIG_ENDIAN_PLATFORM)
    {
        *value += buffer[3] << 24;
        *value += buffer[2] << 16;
        *value += buffer[1] << 8;
        *value += buffer[0];
    }
    else
    {
        *value += buffer[0] << 24;
        *value += buffer[1] << 16;
        *value += buffer[2] << 8;
        *value += buffer[3];
    }

    return 4;
}

/**
 * Check if the algorithm is a post-quantum algorithm
 * @param algo: DNSKEY algorithm.
 * @return 1 if it is and 0 if it is not
 */
uint8_t
pqalgo_is_post_quantum_algorithm(int algo)
{
    switch (algo)
    {
    case LDNS_SLH_DSA_MTL_SHA2_128s:
    case LDNS_SLH_DSA_MTL_SHAKE_128s:
        return 1;
        break;
    default:
        return 0;
    }
}

/**
 * Check if the algorithm is a MTL mode algorithm
 * @param algo: DNSKEY algorithm.
 * @return 1 if it is and 0 if it is not
 */
uint8_t
pqalgo_is_mtl_mode_algorithm(int algo)
{
    switch (algo)
    {
    case LDNS_SLH_DSA_MTL_SHA2_128s:
    case LDNS_SLH_DSA_MTL_SHAKE_128s:
        return 1;
        break;
    default:
        return 0;
    }
}

/**
 * Setup the MTL Parameters based on the algorithm
 * @param algo: DNSKEY algorithm.
 * @param seed_len: Pointer to where the seed length should be set.
 * @param oid_len: Pointer to where the oid length should be set
 * @param oid: Pointer to pointer where the OID should be placed.
 * @param oqs_alg_id: Pointer to where the algorithm ID should be placed.
 * @param key_len; Pointer to where the key length should be placed.
 * @return 1 if succesful and 0 if not
 */
uint8_t
pqalgo_mtl_setup_params(uint8_t algo, uint16_t *seed_len, size_t *oid_len,
                        uint8_t **oid, char *oqs_alg_id, uint16_t *key_len)
{
    uint8_t oid_sha2[OID_LEN] = {0x2B, 0xCE, 0x0F, 0x06, 0x0A, 0x10};
    uint8_t oid_shake[OID_LEN] = {0x2B, 0xCE, 0x0F, 0x06, 0x0D, 0x10};

    if ((seed_len == NULL) || (oid_len == NULL) ||
        (oqs_alg_id == NULL) || (key_len == NULL))
    {
        return 0;
    }

    if (oid == NULL)
    {
        return 0;
    }

    switch (algo)
    {
    case LDNS_SLH_DSA_MTL_SHA2_128s:
        *seed_len = 16;
        *key_len = 32;
        *oid_len = OID_LEN;
        *oid = malloc(OID_LEN);
        memcpy(*oid, oid_sha2, OID_LEN);
        strncpy(oqs_alg_id, "SPHINCS+-SHA2-128s-simple", 32);
        return 1;
        break;
    case LDNS_SLH_DSA_MTL_SHAKE_128s:
        *seed_len = 16;
        *key_len = 32;
        *oid_len = OID_LEN;
        *oid = malloc(OID_LEN);
        memcpy(*oid, oid_shake, OID_LEN);
        strncpy(oqs_alg_id, "SPHINCS+-SHAKE-128s-simple", 32);
        return 1;
        break;
    default:
        return 0;
    }
    return 0;
}

/**
 * Check if the MTL signature is a full signature
 * @param sig: the RRSIG data buffer with the signature
 * @return 1 if it is and 0 if it is not
 */
uint8_t
pqalgo_verify_mtl_full_signature(unsigned char *sig)
{
    if (sig == NULL)
    {
        return 0;
    }
    switch (sig[0])
    {
    case 1:
        return 1;
        break;
    case 0:
        return 0;
        break;
    default:
        // This is a invalid signature...
        return 0;
    }
}

/**
 * Verify the raw mtl signature on the rrsig (e.g. condensed sig)
 * @param sig: Pointer to the signature buffer.
 * @param sig_len: Length of the signature buffer.
 * @param rrset: Pointer to the rrset buffer with the raw sig.
 * @param key: Pointer to the signature buffer.
 * @param keylen: Length of the signature buffer.
 * @param algo: Algorithm used to sign the rrsig.
 * @param env: The module environment the quere is running in.
 * @return LDNS_STATUS_OK if it verifies and error code if not
 */
uint8_t
pqalgo_verify_rrsig_mtl_raw(unsigned char *sig, size_t siglen,
                            sldns_buffer *rrset, unsigned char *key,
                            size_t keylen, uint8_t algo, struct module_env *env)
{
    uint8_t result = LDNS_STATUS_OK;
    size_t sig_size = 0;
    RANDOMIZER *mtl_rand = NULL;
    AUTHPATH *auth_path = NULL;
    MTL_CTX *mtl_ctx = NULL;
    RUNG *rung = NULL;
    SPX_PARAMS *params;
    SEED seed;
    uint8_t *buffer;
    size_t buffer_len;

    if ((sig == NULL) || (siglen == 0) || (rrset == NULL) ||
        (key == NULL) || (keylen == 0) ||
        (!pqalgo_is_mtl_mode_algorithm(algo)))
    {
        return LDNS_STATUS_CRYPTO_BOGUS;
    }

    seed.length = 0;
    if ((algo == LDNS_SLH_DSA_MTL_SHA2_128s) ||
        (algo == LDNS_SLH_DSA_MTL_SHAKE_128s))
    {
        if (keylen != 32)
        {
            return LDNS_STATUS_CRYPTO_BOGUS;
        }
        seed.length = 16;
    }
    else
    {
        return LDNS_STATUS_CRYPTO_BOGUS;
    }
    memset(&seed.seed, 0, seed.length);

    buffer = &sig[1];
    buffer_len = siglen - 1;
    sig_size = mtl_auth_path_from_buffer((char *)buffer,
                                         buffer_len,
                                         seed.length,
                                         8,
                                         &mtl_rand, &auth_path);
    buffer += sig_size;
    buffer_len -= sig_size;

    params = calloc(1, sizeof(SPX_PARAMS));
    if(params == NULL) {
        mtl_authpath_free(auth_path);
        mtl_randomizer_free(mtl_rand);
        return LDNS_STATUS_MEM_ERR;
    }

    // Setup the key for this validation
    params->pk_seed.length = keylen / 2;
    memcpy(params->pk_seed.seed, key, params->pk_seed.length);
    params->pk_root.length = keylen / 2;
    memcpy(params->pk_root.key, key + params->pk_seed.length,
           params->pk_root.length);
    params->prf.length = keylen / 2;
    memset(params->prf.data, 0, params->prf.length);
    params->robust = 0;

    mtl_initns(&mtl_ctx, &seed, &auth_path->sid, NULL);

    // Setup the signature scheme specific functions
    if (algo == LDNS_SLH_DSA_MTL_SHAKE_128s)
    {
        mtl_set_scheme_functions(mtl_ctx, params, 0,
                                 spx_mtl_node_set_hash_message_shake,
                                 spx_mtl_node_set_hash_leaf_shake,
                                 spx_mtl_node_set_hash_int_shake, NULL);
    }
    else if (algo == LDNS_SLH_DSA_MTL_SHA2_128s)
    {
        mtl_set_scheme_functions(mtl_ctx, params, 0,
                                 spx_mtl_node_set_hash_message_sha2,
                                 spx_mtl_node_set_hash_leaf_sha2,
                                 spx_mtl_node_set_hash_int_sha2, NULL);
    }
    else
    {
        log_info("ERROR: Bad algorithm");
        free(mtl_ctx);
        mtl_ctx = NULL;
    }
    mtl_ctx->randomize = 1;

    rung = ladder_cache_find_rung(env->ladder_cache, auth_path);
    if (rung == NULL)
    {
        /* If condensed and failed return a special code so that
         * test_sig_key knows to look for a full sig with a ladder
         */
        result = LDNS_STATUS_CRYPTO_EXTEND;
    }
    else
    {
        if ((mtl_ctx == NULL) ||
            (mtl_hash_and_verify(mtl_ctx,
                                 sldns_buffer_begin(rrset),
                                 sldns_buffer_limit(rrset),
                                 mtl_rand,
                                 auth_path,
                                 rung) != 0))
        {
            result = LDNS_STATUS_CRYPTO_BOGUS;
        }
    }

    mtl_authpath_free(auth_path);
    mtl_randomizer_free(mtl_rand);
    free(mtl_ctx);
    free(params);

    return result;
}

/**
 * Verify the mtl ladder with the underlying signature
 * @param sig: Pointer to the signature buffer.
 * @param sig_len: Length of the signature buffer.
 * @param key: Pointer to the signature buffer.
 * @param keylen: Length of the signature buffer.
 * @param algo: Algorithm used to sign the rrsig.
 * @param env: The module environment the quere is running in.
 * @return LDNS_STATUS_OK if it verifies and error code if not
 */
uint8_t
pqalgo_verify_rrsig_mtl_ladder(unsigned char *sig, size_t siglen,
                               unsigned char *key, size_t keylen,
                               uint8_t algo, struct module_env *env)
{
    uint8_t result = LDNS_STATUS_OK;
    size_t sig_size = 0;
    RANDOMIZER *mtl_rand = NULL;
    AUTHPATH *auth_path = NULL;
    SPX_PARAMS *params;
    SEED seed;
    LADDER *ladder = NULL;
    size_t ladder_buff_len = 0;
    uint8_t *buffer;
    size_t buffer_len;
    uint8_t *underlying_buffer = NULL;
    uint32_t underlying_buffer_len;
    uint8_t *oid = NULL;
    size_t oid_len = 6;
    char oqs_alg_id[32];
    OQS_SIG *oqs_sig = NULL;
    uint32_t sig_length = 0;
    MTL_CTX *mtl_ctx;
    uint16_t algo_key_len = 0;

    if ((sig == NULL) || (siglen == 0) ||
        (key == NULL) || (keylen == 0) ||
        (!pqalgo_is_mtl_mode_algorithm(algo)))
    {
        return LDNS_STATUS_CRYPTO_BOGUS;
    }

    if (pqalgo_mtl_setup_params(algo, &seed.length, &oid_len,
                                &oid, &oqs_alg_id[0], &algo_key_len) == 0)
    {
        return LDNS_STATUS_CRYPTO_BOGUS;
    }

    if (keylen != algo_key_len)
    {
        free(oid);
        return LDNS_STATUS_CRYPTO_BOGUS;
    }

    memset(&seed.seed, 0, seed.length);

    buffer = &sig[1];
    buffer_len = siglen - 1;
    sig_size = mtl_auth_path_from_buffer((char *)buffer,
                                         buffer_len,
                                         seed.length,
                                         8,
                                         &mtl_rand, &auth_path);
    buffer += sig_size;
    buffer_len -= sig_size;

    params = calloc(1, sizeof(SPX_PARAMS));
    if(params == NULL) {
        mtl_authpath_free(auth_path);
        mtl_randomizer_free(mtl_rand);
        return LDNS_STATUS_MEM_ERR;
    }

    // Setup the key for this validation
    params->pk_seed.length = keylen / 2;
    memcpy(params->pk_seed.seed, key, params->pk_seed.length);
    params->pk_root.length = keylen / 2;
    memcpy(params->pk_root.key, key + params->pk_seed.length,
           params->pk_root.length);
    params->prf.length = keylen / 2;
    memset(params->prf.data, 0, params->prf.length);
    params->robust = 0;

    mtl_initns(&mtl_ctx, &seed, &auth_path->sid, NULL);

    mtl_authpath_free(auth_path);
    mtl_randomizer_free(mtl_rand);

    // Setup the signature scheme specific functions
    if (algo == LDNS_SLH_DSA_MTL_SHAKE_128s)
    {
        mtl_set_scheme_functions(mtl_ctx, params, 0,
                                 spx_mtl_node_set_hash_message_shake,
                                 spx_mtl_node_set_hash_leaf_shake,
                                 spx_mtl_node_set_hash_int_shake, NULL);
    }
    else if (algo == LDNS_SLH_DSA_MTL_SHA2_128s)
    {
        mtl_set_scheme_functions(mtl_ctx, params, 0,
                                 spx_mtl_node_set_hash_message_sha2,
                                 spx_mtl_node_set_hash_leaf_sha2,
                                 spx_mtl_node_set_hash_int_sha2, NULL);
    }
    else
    {
        log_info("ERROR: Bad algorithm\n");
        mtl_free(mtl_ctx);
        free(params);
        mtl_ctx = NULL;
    }
    mtl_ctx->randomize = 1;

    if (pqalgo_verify_mtl_full_signature(sig))
    {
        // Get the ladder from the buffer
        ladder_buff_len = mtl_ladder_from_buffer((char *)buffer, buffer_len,
                                                 seed.length, mtl_ctx->sid.length,
                                                 &ladder);

        // Verify the signature on the ladder
        if (buffer_len > ladder_buff_len + 100)
        {
            // Get the scheme separated ladder buffer
            underlying_buffer_len = mtl_get_scheme_separated_buffer(mtl_ctx, ladder,
                                                                    mtl_ctx->nodes.hash_size,
                                                                    &underlying_buffer,
                                                                    oid, oid_len);

            free(oid);
            if (ladder_cache_ladder_exists(env->ladder_cache, ladder))
            {
                mtl_ladder_free(ladder);
                free(underlying_buffer);
                mtl_free(mtl_ctx);
                free(params);
                return LDNS_STATUS_OK;
            }

            oqs_sig = OQS_SIG_new(oqs_alg_id);
            if (oqs_sig != NULL)
            {
                buffer += ladder_buff_len;
                buffer_len -= ladder_buff_len;

                // Get the signature length
                bytes_to_uint32(buffer, &sig_length);
                buffer += 4;
                buffer_len -= 4;

                if (sig_length <= buffer_len)
                {
                    // Verify the signature
                    if (OQS_SIG_verify(oqs_sig, underlying_buffer,
                                       underlying_buffer_len, buffer,
                                       sig_length, key) != OQS_SUCCESS)
                    {
                        result = LDNS_STATUS_CRYPTO_BOGUS;
                    }
                    else
                    {
                        result = LDNS_STATUS_OK;
                        ladder_cache_update(env->ladder_cache, ladder);
                    }
                }
                else
                {
                    result = LDNS_STATUS_CRYPTO_BOGUS;
                }
                OQS_SIG_free(oqs_sig);
            }
            else
            {
                result = LDNS_STATUS_CRYPTO_BOGUS;
            }
            free(underlying_buffer);
        }
        else
        {
            result = LDNS_STATUS_CRYPTO_BOGUS;
        }
        mtl_ladder_free(ladder);
    }
    mtl_free(mtl_ctx);
    free(params);
    return result;
}

/**
 * Verify the mtl signature (full, condensed, both)
 * @param buf: The rrsig buffer with the signature in it
 * @param sig: Pointer to the signature buffer.
 * @param sig_len: Length of the signature buffer.
 * @param key: Pointer to the signature buffer.
 * @param keylen: Length of the signature buffer.
 * @param algo: Algorithm used to sign the rrsig.
 * @param env: The module environment the quere is running in.
 * @return LDNS_STATUS_OK if it verifies, LDNS_STATUS_CRYPTO_EXTEND
 *         if the condensed signature is ok but there is no ladder
 *         to validate it, and error code if not
 */
uint8_t pqalgo_verify_rrsig(sldns_buffer *buf, unsigned char *sig,
                            size_t siglen, unsigned char *key,
                            size_t keylen, uint8_t algo,
                            struct module_env *env)
{
    uint8_t status;

    if ((sig == NULL) || (siglen == 0) || (key == NULL) || (keylen == 0))
    {
        return sec_status_bogus;
    }

    if (pqalgo_is_mtl_mode_algorithm(algo))
    {
        // If this is a full signature verify the ladder
        //    (if it is not already in cache) and cache it
        if (pqalgo_verify_mtl_full_signature(sig))
        {
            if (pqalgo_verify_rrsig_mtl_ladder(sig, siglen, key,
                                               keylen, algo, env) != LDNS_STATUS_OK)
            {
                log_info("MTL signature (%d) - Full Signature Verification FAILED!", algo);
                return sec_status_bogus;
            }
            log_info("MTL signature (%d) - Full Signature Verification SUCCESS!", algo);
        }
        else
        {
            log_info("MTL signature (%d) - No Full Signature", algo);
        }

        status = pqalgo_verify_rrsig_mtl_raw(sig, siglen, buf,
                                             key, keylen, algo, env);

        if (status != LDNS_STATUS_OK)
        {
            log_info("MTL signature (%d) - Condensed Signature Verification FAILED!", algo);
            if (status == LDNS_STATUS_CRYPTO_EXTEND)
            {
                return sec_status_extend;
            }
            return sec_status_bogus;
        }
        else
        {
            log_info("MTL signature (%d) - Condensed Signature Verification SUCCESS!", algo);
        }
        return sec_status_secure;
    }
    else
    {
        log_info("ERROR unrecognized MTL signatures algorithm %d", algo);
    }
    return LDNS_STATUS_CRYPTO_BOGUS;
}