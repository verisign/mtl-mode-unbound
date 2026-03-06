#include "val_pqc_algo.h"
#include <string.h>


PQC_DNSSEC_ALGOS unbound_pqc_val_algos[] = {
    {"Falcon-padded-512-MTL-SHAKE-128",  128, ALGO_MTLLIB, ENABLED, 897, 16, NULL},
    {"ML-DSA-44-MTL-SHAKE-128",          129, ALGO_MTLLIB, ENABLED, 1312, 16, NULL},
    {"SLH-DSA-SHA2-128s-MTL-SHA2-128",   130, ALGO_MTLLIB, ENABLED, 128, 16, NULL},
    {"SLH-DSA-SHAKE-128s-MTL-SHAKE-128", 131, ALGO_MTLLIB, ENABLED, 128, 16, NULL},
    {"MAYO-1-MTL-SHAKE-128",             132, ALGO_MTLLIB, ENABLED, 1168, 16, NULL},
    {"MAYO-2-MTL-SHAKE-128",             133, ALGO_MTLLIB, ENABLED, 4912, 16, NULL},
    {"SNOVA_24_5_4-MTL-SHAKE-128",       134, ALGO_MTLLIB, ENABLED, 1016, 16, NULL},
    {"MAYO-1",                     230, ALGO_LIBOQS, ENABLED, 1168, 0, "MAYO-1"},
    {"MAYO-2",                     231, ALGO_LIBOQS, ENABLED, 4912, 0, "MAYO-2"},
    {"SNOVA_24_5_4",               232, ALGO_LIBOQS, ENABLED, 1016, 0, "SNOVA_24_5_4"},
    {"HAWK",                       234, ALGO_OTHER,  DISABLED, 0, 0, NULL}, 
    {"SQISIGN",                    233, ALGO_OTHER,  DISABLED, 0, 0, NULL},
    {"Falcon-padded-512",          244, ALGO_LIBOQS, ENABLED, 897, 0, "Falcon-512"},
    {"ML-DSA-44",                  245, ALGO_LIBOQS, ENABLED, 1312, 0, "ML-DSA-44"},
    {"SLH-DSA-SHA2-128s",          246, ALGO_LIBOQS, ENABLED, 128, 0, "SPHINCS+-SHA2-128s-simple"},
    {"SLH-DSA-SHAKE-128s",         247, ALGO_LIBOQS, ENABLED, 128, 0, "SPHINCS+-SHAKE-128s-simple"},
    {NULL, 0, ALGO_NONE, DISABLED}};


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
