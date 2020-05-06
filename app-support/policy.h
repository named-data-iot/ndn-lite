/*
 * Copyright (C) 2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_APP_SUPPORT_POLICY_H
#define NDN_APP_SUPPORT_POLICY_H

#include "../encode/interest.h"
#include "../encode/data.h"
#include "../forwarder/forwarder.h"

/** Controller Only Command Policy
 */
#define cmd_controller_only_rule_data_name "(<>)<><CMD><>*"
#define cmd_controller_only_rule_key_name "\\0<KEY><>"

/** Same Room Only Command Policy
 */
#define cmd_same_room_rule_data_name "(<>)<><CMD>(<>)<>*"
#define cmd_same_room_rule_key_name "\\0<>\\1<><KEY><>"

/** Same Producer Content Policy
 */
#define content_same_producer_rule_data_name "(<>)(<>)<DATA>(<>)(<>)<>*"
#define content_same_producer_rule_key_name "\\0\\1\\2\\3<KEY><>"


/**
 * Add 'controller-only' policy and subscribe for 'default' policy
 * @param[in] interval in millisecond to issue subscribe interest
 */
void
ndn_policy_after_bootstrapping(uint32_t interval);

#endif // NDN_APP_SUPPORT_POLICY_H