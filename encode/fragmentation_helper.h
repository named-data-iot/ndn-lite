/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * Reuse the ndn-riot fragmentation header
 *
 *    0           1           2
 *    0 1 2  3    8         15           23
 *    +-+-+--+----+----------------------+
 *    |1|X|MF|Seq#|    Identification    |
 *    +-+-+--+----+----------------------+
 *
 *    First bit: header bit, always 1 (indicating the fragmentation header)
 *    Second bit: reserved, always 0
 *    Third bit: MF bit
 *    4th to 8th bit: sequence number (5 bits, encoding up to 31)
 *    9th to 24th bit: identification (2-byte random number)
 */
