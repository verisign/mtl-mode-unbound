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
#include "validator/val_pqc_algo.h"
#include "util/log.h"
#include "util/module.h"
#include "sldns/rrdef.h"
#include "sldns/keyraw.h"
#include "sldns/sbuffer.h"
#include "services/cache/ladder.h"

#include <mtllib/mtllib.h>
#include <oqs/sig.h>

/**
 * Check if the algorithm is a post-quantum algorithm
 * @param algo: DNSKEY algorithm.
 * @return 1 if it is and 0 if it is not
 */
uint8_t
pqalgo_is_post_quantum_algorithm(int algo)
{
    if(val_algo_id_props(algo) != NULL) {
        return 1;
    }
    return 0;
}

/**
 * Check if the algorithm is an algorithm (directly) from liboqs
 * @param algo: DNSKEY algorithm.
 * @return 1 if it is and 0 if it is not
 */
uint8_t
pqalgo_is_liboqs_algorithm(int algo)
{
    PQC_DNSSEC_ALGOS* alg = val_algo_id_props(algo);
    if ((alg != NULL) && (alg->library == ALGO_LIBOQS)) {
        return 1;
    }
    return 0;
}


/**
 * Check if the algorithm is a MTL mode algorithm
 * @param algo: DNSKEY algorithm.
 * @return 1 if it is and 0 if it is not
 */
uint8_t
pqalgo_is_mtl_mode_algorithm(int algo)
{
    PQC_DNSSEC_ALGOS* alg = val_algo_id_props(algo);
    if ((alg != NULL) && (alg->library == ALGO_MTLLIB)) {
        return 1;
    }
    return 0;
}

/**
 * Get the security parameter size
 * @param algo: DNSKEY algorithm.
 * @return 0 for invalid algorithm or size for a valid one
 */
uint16_t
pqalgo_get_mtl_sec_param(int algo)
{
    PQC_DNSSEC_ALGOS* alg = val_algo_id_props(algo);
    if ((alg != NULL) && (alg->library == ALGO_MTLLIB)) {
        return alg->sec_param;
    }
    return 0;
}

/**
 * Get the pqc key size
 * @param algo: DNSKEY algorithm.
 * @return 0 for invalid algorithm or size for a valid one
 */
size_t 
pqalgo_get_pqc_key_size(int algo)
{
    PQC_DNSSEC_ALGOS* alg = val_algo_id_props(algo);
    if ((alg != NULL) && (alg->library == ALGO_MTLLIB)) {
        return alg->raw_key_size;
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

#ifdef PQC_ALGO_MTL_ENABLED
/**
 * Extract the Signer's Name field from an rrsig
 */
struct domain_name * pqalgo_get_rrsig_signers_name(sldns_buffer * rrsig) {
    static size_t RRSET_SIGNERSNAME_OFFSET = 18; // Offset for parsing signer_name. Signer's Name field starts at byte 18 (zero-indexed).
    struct domain_name *signer_name;
    uint8_t label_length = 0;

    if (rrsig == NULL) {
        return NULL;
    }

    if ((signer_name = malloc(sizeof(struct domain_name))) == NULL) {
        return NULL;
    }

    signer_name->length = 0;
    while ((label_length = sldns_buffer_read_u8_at(rrsig, RRSET_SIGNERSNAME_OFFSET + signer_name->length)) != 0x00) { // Labels end with null terminator byte
        signer_name->length += label_length + 1; // +1 to also include the length byte
    }
    signer_name->length++; // Include Null terminator
    sldns_buffer_read_at(rrsig, RRSET_SIGNERSNAME_OFFSET, signer_name->labels, signer_name->length);
    
    return signer_name;
}

/**
 * Verify the raw mtl signature on the rrsig (e.g. condensed sig)
 * @param sig: Pointer to the signature buffer.
 * @param sig_len: Length of the signature buffer.
 * @param rrset: Pointer to the rrset buffer with the raw sig.
 * @param key: Pointer to the key buffer.
 * @param keylen: Length of the key buffer.
 * @param algo: Algorithm used to sign the rrsig.
 * @param env: The module environment the quere is running in.
 * @return LDNS_STATUS_OK if it verifies and error code if not
 */
uint8_t
pqalgo_verify_rrsig_mtl_raw(unsigned char *sig, size_t siglen,
                            sldns_buffer *rrset, unsigned char *key,
                            size_t keylen, uint8_t algo, struct module_env *env)
{
    MTLLIB_CTX *mtl_ctx = NULL;
    SERIESID sid;
    MTLLIB_BUFFER* auth_buffer = NULL;
    MTLLIB_STATUS result = MTLLIB_OK;
    MTLLIB_BUFFER* pubkey = NULL;
    MTLLIB_BUFFER* rrset_buff = NULL;


    if ((sig == NULL) || (siglen == 0) || (rrset == NULL) ||
        (key == NULL) || (keylen == 0) ||
        (!pqalgo_is_mtl_mode_algorithm(algo)))
    {
        return LDNS_STATUS_CRYPTO_BOGUS;
    }

    // Get the public key from the parameters
    PQC_DNSSEC_ALGOS* alg = val_algo_id_props(algo);
    if(alg == NULL) {
        return LDNS_STATUS_CRYPTO_BOGUS;
    }
    uint16_t hash_size = mtllib_sig_buffer_get_hash_size(alg->name);
    if(hash_size == 0) {
        return LDNS_STATUS_CRYPTO_BOGUS;
    }

    if (mtllib_buffer_initialize(&auth_buffer, siglen-1, &sig[1]) != MTLLIB_OK) {
        return LDNS_STATUS_MEM_ERR;
    }
    if (mtllib_sig_buffer_get_sid(auth_buffer, hash_size, &sid) != MTLLIB_OK) {
        return LDNS_STATUS_MEM_ERR;
    }
    if(mtllib_buffer_initialize(&pubkey, keylen, key) != MTLLIB_OK) {
        return LDNS_STATUS_CRYPTO_BOGUS;
    }        
    if (mtllib_pubkey_from_buffer(alg->name, &mtl_ctx, pubkey, sid.id) != MTLLIB_OK) 
    {
        mtllib_buffer_free(pubkey);
        return LDNS_STATUS_MEM_ERR;
    }
    mtllib_buffer_free(pubkey);

    // Look for a ladder in cache that may work
    struct domain_name *signer_name = pqalgo_get_rrsig_signers_name(rrset);
    MTLLIB_BUFFER* ladder = ladder_cache_find_ladder(env->ladder_cache, &sid, hash_size, signer_name);

    if(mtllib_buffer_initialize(&rrset_buff, sldns_buffer_limit(rrset), sldns_buffer_begin(rrset))) {
        mtllib_buffer_free(rrset_buff);
        mtllib_buffer_free(auth_buffer);
        free(signer_name);
        return LDNS_STATUS_MEM_ERR;
    }

    // Try to verify the signature
    result = mtllib_verify(mtl_ctx, rrset_buff, auth_buffer, ladder, NULL);        

    mtllib_buffer_free(rrset_buff);
    mtllib_buffer_free(auth_buffer);
    free(signer_name);

    if (result == MTLLIB_NO_LADDER) {
        return LDNS_STATUS_CRYPTO_EXTEND;
    } else if ((result == MTLLIB_OK) || (result == MTLLIB_OK_VALIDATED_LADDER)) {
         return LDNS_STATUS_OK;
    }
    return LDNS_STATUS_CRYPTO_BOGUS;
}
#endif

/**
 * Verify the mtl ladder with the underlying signature
 * @param sig: Pointer to the signature buffer.
 * @param sig_len: Length of the signature buffer.
 * @param key: Pointer to the key buffer.
 * @param keylen: Length of the key buffer.
 * @param algo: Algorithm used to sign the rrsig.
 * @param env: The module environment the quere is running in.
 * @return LDNS_STATUS_OK if it verifies and error code if not
 */
uint8_t
pqalgo_verify_rrsig_mtl_ladder(unsigned char *sig, size_t siglen,
                               unsigned char *key, size_t keylen,
                               uint8_t algo, struct module_env *env,
                               struct domain_name *signer_name)
{
    MTLLIB_CTX *mtl_ctx = NULL;
    size_t condensed_len = 0;
    SERIESID sid;
    MTLLIB_BUFFER* auth_buffer = NULL;
    MTLLIB_BUFFER* ladder_buffer = NULL;
    MTLLIB_BUFFER* key_buffer = NULL;

    if ((sig == NULL) || (siglen == 0) ||
        (key == NULL) || (keylen == 0) ||
        (!pqalgo_is_mtl_mode_algorithm(algo)))
    {
        return LDNS_STATUS_CRYPTO_BOGUS;
    }

    // Get the public key from the parameters
    PQC_DNSSEC_ALGOS* alg = val_algo_id_props(algo);
    if(alg == NULL) {
        return LDNS_STATUS_CRYPTO_BOGUS;
    }
    uint16_t hash_size = mtllib_sig_buffer_get_hash_size(alg->name);
    if(hash_size == 0) {
        return LDNS_STATUS_CRYPTO_BOGUS;
    }

    if (mtllib_buffer_initialize(&auth_buffer, siglen-1, &sig[1]) != MTLLIB_OK) {
        return LDNS_STATUS_MEM_ERR;
    }
    auth_buffer->buffer_position = siglen-1;
    if (mtllib_sig_buffer_get_sid(auth_buffer, hash_size, &sid) != MTLLIB_OK) {
        return LDNS_STATUS_MEM_ERR;
    }
    if (mtllib_buffer_initialize(&key_buffer, keylen, key) != MTLLIB_OK) {
        return LDNS_STATUS_MEM_ERR;
    }
    if (mtllib_pubkey_from_buffer(alg->name, &mtl_ctx, key_buffer, sid.id) != MTLLIB_OK) 
    {
        mtllib_buffer_free(key_buffer);
        return LDNS_STATUS_CRYPTO_BOGUS;
    }
    mtllib_buffer_free(key_buffer);

    condensed_len = mtllib_sig_buffer_condensed_sig_len(auth_buffer, hash_size);
    if(condensed_len == 0) {
        mtllib_buffer_free(auth_buffer);
        return LDNS_STATUS_CRYPTO_BOGUS;
    }

    // extend the mtllib_buffer to change the starting point
    mtllib_buffer_free(auth_buffer);
    
    size_t ladder_offset = 1+condensed_len;
    if (mtllib_buffer_initialize(&ladder_buffer, siglen-ladder_offset, &sig[ladder_offset]) != MTLLIB_OK) {
        return LDNS_STATUS_MEM_ERR;
    }

    // If the ladder is already cached, then we don't need to verify the signature again
    if (ladder_cache_ladder_exists(env->ladder_cache, ladder_buffer, hash_size, signer_name))
    {
        mtllib_key_free(mtl_ctx);
        mtllib_buffer_free(ladder_buffer);
        return LDNS_STATUS_OK;
    }

    // If the ladder is new/updated, verify the signature then update the cache
    if(mtllib_verify_signed_ladder(mtl_ctx, ladder_buffer) != MTLLIB_OK) {
        mtllib_buffer_free(ladder_buffer);    
        mtllib_key_free(mtl_ctx);        
        return LDNS_STATUS_CRYPTO_BOGUS;
    }

    ladder_cache_update(env->ladder_cache, ladder_buffer, hash_size, signer_name);
    mtllib_buffer_free(ladder_buffer);    
    mtllib_key_free(mtl_ctx);

    return LDNS_STATUS_OK;
}

/**
 * Verify the rrsig on a raw PQC signature from libOQS
 * @param sig: Pointer to the signature buffer.
 * @param sig_len: Length of the signature buffer.
 * @param rrset: Pointer to the rrset buffer with the raw sig.
 * @param key: Pointer to the key buffer.
 * @param keylen: Length of the key buffer.
 * @param algo: Algorithm used to sign the rrsig.
 * @return LDNS_STATUS_OK if it verifies,
 *         LDNS_STATUS_CRYPTO_BOGUS if not
 */
uint8_t pqalgo_verify_rrsig_oqs_raw(unsigned char* sig, size_t siglen,
                                    sldns_buffer* rrset,
                                    unsigned char* key, size_t keylen,
                                    uint8_t algo)
{
    (void) keylen;  //suppress unused param warning
                    //keylen only included for uniformity

    //first figure out the right oqs algorithm string (oqs_alg_id)
    char* oqs_alg_id = val_algo_get_oqs_str(algo);
    if(oqs_alg_id == NULL) {
        log_info("ERROR: Unrecognized algorithm id: %d", algo);
        return LDNS_STATUS_CRYPTO_BOGUS;        
    }

    OQS_SIG* oqs_sig = NULL;
    oqs_sig = OQS_SIG_new(oqs_alg_id);

    uint8_t result = LDNS_STATUS_CRYPTO_BOGUS; //unverified until proven verified
    if (OQS_SIG_verify( oqs_sig,
                        sldns_buffer_begin(rrset), sldns_buffer_limit(rrset),
                        sig, siglen, key) == OQS_SUCCESS) {
        result = LDNS_STATUS_OK;
    } else {
        result = LDNS_STATUS_CRYPTO_BOGUS;
    }

    OQS_SIG_free(oqs_sig);
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
 * @return sec_status_secure if it verifies,
 *         sec_status_extend if the condensed signature is ok
 *             but there is no ladder to validate it,
 *         sec_status_bogus if failed validatiion
 */
uint8_t pqalgo_verify_rrsig(sldns_buffer *buf, unsigned char *sig,
                            size_t siglen, unsigned char *key,
                            size_t keylen, uint8_t algo,
                            struct module_env *env)
{
    uint8_t status;
    struct domain_name *signer_name;

    if ((buf == NULL) || (sig == NULL) || (siglen == 0) || (key == NULL) || (keylen == 0))
    {
        return sec_status_bogus;
    }

    if (pqalgo_is_liboqs_algorithm(algo))
    {
        status = pqalgo_verify_rrsig_oqs_raw(sig, siglen,
                                             buf,
                                             key, keylen,
                                             algo);
        if (status == LDNS_STATUS_OK) {
            return sec_status_secure;
        } else {
            return sec_status_bogus;
        }
        
    }
    else if (pqalgo_is_mtl_mode_algorithm(algo))
    {
        #ifdef PQC_ALGO_MTL_ENABLED
            // If this is a full signature verify the ladder
            //    (if it is not already in cache) and cache it
            if (pqalgo_verify_mtl_full_signature(sig))
            {
                signer_name = pqalgo_get_rrsig_signers_name(buf);

                if (pqalgo_verify_rrsig_mtl_ladder(sig, siglen, key,
                                                keylen, algo, env, signer_name) != LDNS_STATUS_OK)
                {
                    log_info("MTL signature (%d) - Full Signature Verification FAILED!", algo);
                    free(signer_name);
                    return sec_status_bogus;
                }
                log_info("MTL signature (%d) - Full Signature Verification SUCCESS!", algo);
                free(signer_name);
            }
            else
            {
                log_info("MTL signature (%d) - No Full Signature", algo);
            }

            status = pqalgo_verify_rrsig_mtl_raw(sig, siglen, buf,
                                                    key, keylen, algo, env);

            if (status != LDNS_STATUS_OK)
            {
                if (status == LDNS_STATUS_CRYPTO_EXTEND)
                {
                    log_info("MTL signature (%d) - Condensed Signature Verification FAILED, insufficient information to validate.", algo);
                    return sec_status_extend;
                }
                log_info("MTL signature (%d) - Condensed Signature Verification FAILED, signature BOGUS.", algo);
                return sec_status_bogus;
            }
            else
            {
                log_info("MTL signature (%d) - Condensed Signature Verification SUCCESS!", algo);
            }
            return sec_status_secure;
        #else
            log_info("ERROR - MTL signatures are not enabled!");
            return sec_status_bogus;
        #endif
    }
    else
    {
        log_info("ERROR unrecognized signatures algorithm %d", algo);
    }

    return sec_status_bogus;
}