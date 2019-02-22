/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NRF_ALARM_CONFIG_H_
#define NRF_ALARM_CONFIG_H_

/* Alarm */
#ifndef RTC_INSTANCE
#define RTC_INSTANCE NRF_RTC2
#endif

#ifndef RTC_IRQN
#define RTC_IRQN RTC2_IRQn
#endif

#ifndef RTC_IRQ_PRIOROTY
#define RTC_IRQ_PRIORITY 6
#endif

#ifndef RTC_IRQ_HANLDER
#define RTC_IRQ_HANDLER RTC2_IRQHandler
#endif

#endif // NRF_ALARM_CONFIG_H_
