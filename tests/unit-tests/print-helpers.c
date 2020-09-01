#include "print-helpers.h"
#include <stdio.h>

void print_hex(const char *msg, uint8_t *val, uint32_t val_len) {
  printf("%s\n", msg);
  for (uint32_t i = 0; i < val_len; i++) {
    printf("%02x", (unsigned int) *val);
  }
  printf("\n");
}

void print_error(const char *test_name, const char *fnct_name, const char *funct_failed, int err_code) {
  printf("In %s test, within call to %s, call to %s failed, error code: %d\n", test_name, fnct_name, funct_failed, err_code);
}
