#ifndef ENCODING_KEY_TYPES_H
#define ENCODING_KEY_TYPES_H

#include "tlv.h"
#include "encoder.h"
#include "decoder.h"
#include "block.h"
#include "name.h"
#include "ndn_constants.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * An ndn_KeyLocator holds the type of key locator and related data.
 */
typedef struct ndn_keylocator{
  uint32_t type;     /**< -1 for none */
  ndn_buffer_t keydigest;            /**< A Blob whose value is a pointer to a pre-allocated buffer for the key data as follows:
    * If type is ndn_KeyLocatorType_KEY_LOCATOR_DIGEST, the digest data.
    */
  ndn_name_t keyname;     /**< The key name (only used if type is ndn_KeyLocatorType_KEYNAME.) */
}ndn_keylocator_t;

/**
 * An ndn_ValidityPeriod is used in a Data packet's SignatureInfo and represents
 * the begin and end times of a certificate's validity period.
 */
typedef struct ndn_validityperiod {
  uint32_t notbefore; /**< DBL_MAX for none. */
  uint32_t notafter; /**< -DBL_MAX for none. */
}ndn_validityperiod_t;

#ifdef __cplusplus
}
#endif

#endif // ENCODING_NAME_H
