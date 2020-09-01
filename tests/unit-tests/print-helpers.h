#ifndef PRINT_HELPERS_H
#define PRINT_HELPERS_H

#include <stdint.h>

void print_hex(const char *msg, uint8_t* val, uint32_t val_len);

void print_error(const char *test_name, const char *fnct_name, const char *funct_failed, int err_code);

#endif // PRINT_HELPERS_H
