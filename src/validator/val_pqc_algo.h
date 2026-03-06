#ifndef __VAL_PQC_ALGO__
#define __VAL_PQC_ALGO__

#include <stddef.h>
#include <stdint.h>

typedef enum DNSSEC_ALGO_TYPE
{
    ALGO_NONE,
    ALGO_OPENSSL,
    ALGO_LIBOQS,
    ALGO_MTLLIB,
    ALGO_OTHER,
} DNSSEC_ALGO_TYPE;

typedef enum DNSSEC_ALGO_STATE
{
    DISABLED = 0,
    ENABLED = 1,
} DNSSEC_ALGO_STATE;

typedef struct PQC_DNSSEC_ALGOS
{
    char *name;
    uint8_t number;
    DNSSEC_ALGO_TYPE library;
    DNSSEC_ALGO_STATE enabled;
    size_t raw_key_size;
    uint16_t sec_param;
    char* algo_id_str;
} PQC_DNSSEC_ALGOS;

#define MTL_INDEX_LEN 8

/**
 * Get the PQC Algorithm properties by name
 * @param keystr Key string
 * @return PQC_DNSSEC_ALGOS Algorithm properties struct
 *                             (or NULL if not present)
 */
PQC_DNSSEC_ALGOS *val_algo_props(char *keystr);

/**
 * Get the PQC Algorithm properties by ID
 * @param algo Algorithm ID
 * @return PQC_DNSSEC_ALGOS Algorithm properties struct
 *                             (or NULL if not present)
 */
PQC_DNSSEC_ALGOS *val_algo_id_props(uint8_t algo);

/**
 * Get the PQC Algorithm properties by ID
 * @param algo Algorithm ID
 * @return 1 if is MTL algorithm or 0 if not
 */
int val_algo_is_mtl(uint8_t algo);

/**
 * Get the PQC Algorithm String for LibOQS by ID
 * @param algo Algorithm ID
 * @return NULL if not valid, String if valid
 */
char* val_algo_get_oqs_str(uint8_t algo);

/**
 * Get the PQC Algorithm hash length value
 * @param algo Algorithm ID
 * @return size of hash in bytes
 */
size_t val_algo_get_hash_size(uint8_t algo);

/**
 * Get the PQC Algorithm condensed signature header offset
 * @param algo Algorithm ID
 * @return size of the header offset minus the sibiling hash size
 */
size_t val_algo_get_condensed_offset(uint8_t algo);


#endif // __VAL_PQC_ALGO__