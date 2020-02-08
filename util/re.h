/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

/*
 *
 * Mini regex-module inspired by Rob Pike's regex code described in:
 *
 * http://www.cs.princeton.edu/courses/archive/spr09/cos333/beautiful.html
 *
 *
 *
 * Supports:
 * ---------
 *   '.'        Dot, matches any character
 *   '^'        Start anchor, matches beginning of string
 *   '$'        End anchor, matches end of string
 *   '*'        Asterisk, match zero or more (greedy)
 *   '+'        Plus, match one or more (greedy)
 *   '?'        Question, match zero or one (non-greedy)
 *   '[abc]'    Character class, match if one of {'a', 'b', 'c'}
 *   '[^abc]'   Inverted class, match if NOT one of {'a', 'b', 'c'} -- NOTE: feature is currently broken!
 *   '[a-zA-Z]' Character ranges, the character set of the ranges { a-z | A-Z }
 *   '\s'       Whitespace, \t \f \r \n \v and spaces
 *   '\S'       Non-whitespace
 *   '\w'       Alphanumeric, [a-zA-Z0-9_]
 *   '\W'       Non-alphanumeric
 *   '\d'       Digits, [0-9]
 *   '\D'       Non-digits
 *
 *
 */
#ifndef RE_H
#define RE_H

#ifdef __cplusplus
extern "C"{
#endif

/**@defgroup NDNUtil
 */

/** @defgroup NDNUtilRe Regex
 * @ingroup NDNUtil
 *
 * Mini regex-module inspired by Rob Pike's regex code described in:
 * http://www.cs.princeton.edu/courses/archive/spr09/cos333/beautiful.html
 * @{
 */

/** Typedef'd pointer to get abstract datatype. */
typedef struct regex_t* re_t;

/** Compile regex string pattern to a regex_t-array. */
re_t re_compile(const char* pattern);

/** Find matches of the compiled pattern inside text. */
int  re_matchp(re_t pattern, const char* text);

/** Find matches of the txt pattern inside text (will compile automatically first). */
int  re_match(const char* pattern, const char* text);

/*@}*/

#ifdef __cplusplus
}
#endif

#endif // RE_H
