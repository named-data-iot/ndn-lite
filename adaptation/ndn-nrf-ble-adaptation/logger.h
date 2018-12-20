
#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include "nrf_log.h"

/**@brief Basic macro for logging, wraps printf function.
 */
#define APP_LOG(...) NRF_LOG_RAW_INFO(__VA_ARGS__)

/**@brief Print an array as a hex string.
 */
static void print_array(uint8_t const *p_string, size_t size) {
  size_t i;
  APP_LOG("    ");
  for (i = 0; i < size; i++) {
    APP_LOG("%02x", p_string[i]);
  }
}

/**@brief Macro to print a message along with an array as a hex string.
 */
#define APP_LOG_HEX(msg, res, len) \
  do {                             \
    APP_LOG(msg);                  \
    APP_LOG("\n");                 \
    print_array(res, len);         \
    APP_LOG("\n");                 \
  } while (0)

#endif // LOGGER_H