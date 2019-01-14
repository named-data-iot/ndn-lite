
#ifndef NRF_LOGGER_H
#define NRF_LOGGER_H

#include <stdio.h>
#include "nrf_log.h"

/**@brief Basic macro for logging, wraps printf function.
 */
#define NRF_APP_LOG(...) NRF_LOG_RAW_INFO(__VA_ARGS__)

/**@brief Print an array as a hex string.
 */
static void nrf_print_array(uint8_t const *p_string, size_t size) {
  size_t i;
  NRF_APP_LOG("    ");
  for (i = 0; i < size; i++) {
    NRF_APP_LOG("%02x", p_string[i]);
  }
}

/**@brief Macro to print a message along with an array as a hex string.
 */
#define NRF_APP_LOG_HEX(msg, res, len) \
  do {                             \
    NRF_APP_LOG(msg);                  \
    NRF_APP_LOG("\n");                 \
    nrf_print_array(res, len);         \
    NRF_APP_LOG("\n");                 \
  } while (0)

#endif // NRF_LOGGER_H