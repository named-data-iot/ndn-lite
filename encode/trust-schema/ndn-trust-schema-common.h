
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
