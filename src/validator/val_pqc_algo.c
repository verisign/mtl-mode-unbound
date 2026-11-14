#include "val_pqc_algo.h"
#include <string.h>


PQC_DNSSEC_ALGOS unbound_pqc_val_algos[] = {
    {"ML-DSA-44",                         18, ALGO_LIBOQS, ENABLED, 1312, 16, "ML-DSA-44"},
    {"ML-DSA-65",                        100, ALGO_LIBOQS, ENABLED, 1952, 24, "ML-DSA-65"},
    {"ML-DSA-87",                        101, ALGO_LIBOQS, ENABLED, 2592, 32, "ML-DSA-87"},
    {"SLH-DSA-SHA2-128s",                102, ALGO_LIBOQS, ENABLED,  128, 16, "SLH_DSA_PURE_SHA2_128S"},
    {"SLH-DSA-SHAKE-128s",               103, ALGO_LIBOQS, ENABLED,  128, 16, "SLH_DSA_PURE_SHAKE_128S"},
    {"ML-DSA-44-MTL-SHAKE-128",          118, ALGO_MTLLIB, ENABLED, 1312, 16, "ML-DSA-44-MTL-SHAKE-128"},
    {"ML-DSA-65-MTL-SHAKE-192",          110, ALGO_MTLLIB, ENABLED, 1952, 24, "ML-DSA-65-MTL-SHAKE-192"},
    {"ML-DSA-87-MTL-SHAKE-256",          111, ALGO_MTLLIB, ENABLED, 2592, 32, "ML-DSA-87-MTL-SHAKE-256"},
    {"SLH-DSA-SHA2-128s-MTL-SHA2-128",   112, ALGO_MTLLIB, ENABLED,  128, 16, "SLH-DSA-SHA2-128s-MTL-SHA2-128"},
    {"SLH-DSA-SHAKE-128s-MTL-SHAKE-128", 113, ALGO_MTLLIB, ENABLED,  128, 16, "SLH-DSA-SHAKE-128s-MTL-SHAKE-128"},
    {NULL, 0, ALGO_NONE, DISABLED, 0, 0, NULL}};

/**
 * Get the PQC Algorithm properties by name
 * @param keystr Key string
 * @return PQC_DNSSEC_ALGOS Algorithm properties struct
 *                             (or NULL if not present)
 */
PQC_DNSSEC_ALGOS *val_algo_props(char *keystr)
{
    size_t algo_idx = 0;

    // Find the appropriate algorithm
    while (unbound_pqc_val_algos[algo_idx].name != NULL)
    {
        if ((strcmp(unbound_pqc_val_algos[algo_idx].name, (char *)keystr) == 0) && 
            (unbound_pqc_val_algos[algo_idx].enabled == ENABLED))
        {
            return &unbound_pqc_val_algos[algo_idx];
        }
        algo_idx++;
    }
    return NULL;
}

/**
 * Get the PQC Algorithm properties by ID
 * @param algo Algorithm ID
 * @return PQC_DNSSEC_ALGOS Algorithm properties struct
 *                             (or NULL if not present)
 */
PQC_DNSSEC_ALGOS *val_algo_id_props(uint8_t algo)
{
    size_t algo_idx = 0;

    // Find the appropriate algorithm
    while (unbound_pqc_val_algos[algo_idx].name != NULL)
    {
        if ((unbound_pqc_val_algos[algo_idx].number == algo) && 
            (unbound_pqc_val_algos[algo_idx].enabled == ENABLED))
        {
            return &unbound_pqc_val_algos[algo_idx];
        }
        algo_idx++;
    }
    return NULL;
}

/**
 * Get the PQC Algorithm properties by ID
 * @param algo Algorithm ID
 * @return 1 if is MTL algorithm or 0 if not
 */
int val_algo_is_mtl(uint8_t algo)
{
    size_t algo_idx = 0;

    // Find the appropriate algorithm
    while (unbound_pqc_val_algos[algo_idx].name != NULL)
    {
        if ((unbound_pqc_val_algos[algo_idx].number == algo) && 
            (unbound_pqc_val_algos[algo_idx].enabled == ENABLED) &&
            (unbound_pqc_val_algos[algo_idx].library == ALGO_MTLLIB))
        {
            return 1;
        }
        algo_idx++;
    }
    return 0;
}



/**
 * Get the PQC Algorithm String for LibOQS by ID
 * @param algo Algorithm ID
 * @return NULL if not valid, String if valid
 */
char* val_algo_get_oqs_str(uint8_t algo)
{
    size_t algo_idx = 0;

    // Find the appropriate algorithm
    while (unbound_pqc_val_algos[algo_idx].name != NULL)
    {
        if ((unbound_pqc_val_algos[algo_idx].number == algo) && 
            (unbound_pqc_val_algos[algo_idx].enabled == ENABLED) &&
            (unbound_pqc_val_algos[algo_idx].library == ALGO_LIBOQS))
        {
            return unbound_pqc_val_algos[algo_idx].algo_id_str;
        }
        algo_idx++;
    }
    return 0;
}

/**
 * Get the PQC Algorithm hash length value
 * @param algo Algorithm ID
 * @return size of hash in bytes
 */
size_t val_algo_get_hash_size(uint8_t algo) 
{
    PQC_DNSSEC_ALGOS* properties = val_algo_id_props(algo);

    if(properties) 
    {
        return properties->sec_param;
    }
    return 0;
}

/**
 * Get the PQC Algorithm condensed signature header offset
 * @param algo Algorithm ID
 * @return size of the header offset minus the sibiling hash size
 */
size_t val_algo_get_condensed_offset(uint8_t algo)
{
    uint16_t hash_size = val_algo_get_hash_size(algo);

    if (hash_size > 0) 
    {
        return (2 * hash_size) + 2 + hash_size + (MTL_INDEX_LEN * 3);
    }
    return 0;
}
