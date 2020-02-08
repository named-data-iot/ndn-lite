/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_TRUST_SCHEMA_COMMON_H
#define NDN_TRUST_SCHEMA_COMMON_H

static char _single_name_rgxp[] = "^<.+>$";
static char _single_wildcard_rgxp[] = "^<>$";
static char _multiple_wildcard_rgxp[] = "^<>\\*$";
static char _subpattern_index_rgxp[] = "^\\\\[0-9]$";
static char _function_ref_rgxp[] = "^\\[.+\\]$";
static char _rule_ref_rgxp[] = "^.+()$";
//static char _rule_ref_subpattern_index_rgxp[] = "\\\\[0-9]";
static int  TINY_REGEX_C_FAIL = -1;

#endif // NDN_TRUST_SCHEMA_COMMON_H
