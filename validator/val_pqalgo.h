/*
 * validator/val_pqalgo.h - validator post-quantum security algorithm functions.
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
 * The functions help with NSEC checking, the different NSEC proofs
 * for denial of existence, and proofs for presence of types.
 */

#ifndef VALIDATOR_VAL_PQALGO_H
#define VALIDATOR_VAL_PQALGO_H
#include <mtllib/mtl.h>

#include "config.h"
/* packed_rrset on top to define enum types (forced by c99 standard) */
#include "util/data/packed_rrset.h"
#include "util/module.h"
#include "sldns/sbuffer.h"

/* Macros and value definitions */
#define BIG_ENDIAN_PLATFORM (!*(uint8_t *)&(uint16_t){1})
#define OID_LEN 6
#define LADDER_MAX_CACHE 128

#define LDNS_STATUS_OK 0
#define LDNS_STATUS_MEM_ERR 8
#define LDNS_STATUS_CRYPTO_BOGUS 35
#define LDNS_STATUS_CRYPTO_EXTEND 99

/* Function Prototypes */
uint8_t pqalgo_is_post_quantum_algorithm(int algo);
uint8_t pqalgo_is_mtl_mode_algorithm(int algo);

uint8_t pqalgo_verify_rrsig(sldns_buffer *buf, unsigned char *sig, size_t siglen,
                            unsigned char *key, size_t keylen, uint8_t algo,
                            struct module_env* env);

uint8_t pqalgo_verify_rrsig_mtl_raw(unsigned char *sig, size_t siglen,
                                    sldns_buffer *rrset, unsigned char *key,
                                    size_t keylen, uint8_t algo, struct module_env* env);
uint8_t pqalgo_verify_rrsig_mtl_ladder(unsigned char *sig, size_t siglen,
                               unsigned char *key, size_t keylen,
                               uint8_t algo, struct module_env* env);

void pqalgo_mtl_ladder_cache_clear(void);

/* Internal Functions that may be useful elsewhere */
size_t bytes_to_uint32(unsigned char *buffer, uint32_t *value);
uint8_t pqalgo_mtl_setup_params(uint8_t algo, uint16_t *seed_len,
                                size_t *oid_len, uint8_t **oid,
                                char *oqs_alg_id, uint16_t *key_len);
uint8_t pqalgo_verify_mtl_full_signature(unsigned char *sig);

#endif /* VALIDATOR_VAL_PQALGO_H */