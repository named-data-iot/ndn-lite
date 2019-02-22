/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "alarm.h"
#include "nrf-alarm-config.h"

#include "nrf.h"
#include "nrf_gpio.h"
#include "nrf_peripherals.h"
#include "nrf_rtc.h"
#include "nrf_drv_clock.h"
#include "nrf_802154_utils.h"
#include "nrf_802154_lp_timer.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define RTC_FREQUENCY       NRF_802154_RTC_FREQUENCY
#define US_PER_MS           1000ULL
#define US_PER_S            NRF_802154_US_PER_S
#define US_PER_OVERFLOW     (512UL * NRF_802154_US_PER_S)  ///< Time that has passed between overflow events. On full RTC speed, it occurs every 512 s.

#define MS_PER_S            1000UL

#define MIN_RTC_COMPARE_EVENT_TICKS  2                                                        ///< Minimum number of RTC ticks delay that guarantees that RTC compare event will fire.
#define MIN_RTC_COMPARE_EVENT_DT     (MIN_RTC_COMPARE_EVENT_TICKS * NRF_802154_US_PER_TICK)   ///< Minimum time delta from now before RTC compare event is guaranteed to fire.
#define EPOCH_32BIT_US               (1ULL << 32)
#define EPOCH_FROM_TIME(time)        ((time) & ((uint64_t)UINT32_MAX << 32))


typedef enum
{
    ms_timer,
    us_timer,
    m_802154_timer,
    m_802154_sync,
    num_timers
} alarm_index;

typedef struct
{
    volatile bool fire;  ///< Information for processing function, that alarm should fire.
    uint64_t      target; ///< Alarm fire time (in millisecond for ms_timer, in microsecond for UsTimer)
} alarm_data;

typedef struct
{
    uint32_t        channel_num;
    uint32_t        comp_event_mask;
    nrf_rtc_event_t comp_event;
    nrf_rtc_int_t   comp_int;
} alarm_channel_data;

static volatile uint32_t overflow_counter; ///< Counter of RTC overflowCounter, incremented by 2 on each OVERFLOW event.
static volatile uint8_t  mutex;           ///< Mutex for write access to @ref overflow_counter.
static volatile uint64_t time_offset = 0;  ///< Time overflowCounter to keep track of current time (in millisecond).
static volatile bool     event_pending;    ///< Timer fired and upper layer should be notified.
static alarm_data         timer_data[num_timers]; ///< Data of the timers.

static const alarm_channel_data channel_data[num_timers] = //
    {                                                    //
        [ms_timer] =
            {
                .channel_num    = 0,
                .comp_event_mask = RTC_EVTEN_COMPARE0_Msk,
                .comp_event     = NRF_RTC_EVENT_COMPARE_0,
                .comp_int       = NRF_RTC_INT_COMPARE0_MASK,
            },
        [us_timer] =
            {
                .channel_num    = 1,
                .comp_event_mask = RTC_EVTEN_COMPARE1_Msk,
                .comp_event     = NRF_RTC_EVENT_COMPARE_1,
                .comp_int       = NRF_RTC_INT_COMPARE1_MASK,
            },
        [m_802154_timer] =
            {
                .channel_num    = 2,
                .comp_event_mask = RTC_EVTEN_COMPARE2_Msk,
                .comp_event     = NRF_RTC_EVENT_COMPARE_2,
                .comp_int       = NRF_RTC_INT_COMPARE2_MASK,
            },
        [m_802154_sync] = {
            .channel_num    = 3,
            .comp_event_mask = RTC_EVTEN_COMPARE3_Msk,
            .comp_event     = NRF_RTC_EVENT_COMPARE_3,
            .comp_int       = NRF_RTC_INT_COMPARE3_MASK,
        }};

static inline bool mutex_get(void)
{
    do
    {
        volatile uint8_t mutex_value = __LDREXB(&mutex);

        if (mutex_value)
        {
            __CLREX();
            return false;
        }
    } while (__STREXB(1, &mutex));

    // Disable OVERFLOW interrupt to prevent lock-up in interrupt context while mutex is locked from lower priority
    // context and OVERFLOW event flag is stil up.
    nrf_rtc_int_disable(RTC_INSTANCE, NRF_RTC_INT_OVERFLOW_MASK);

    __DMB();

    return true;
}

static inline void mutex_release(void)
{
    // Re-enable OVERFLOW interrupt.
    nrf_rtc_int_enable(RTC_INSTANCE, NRF_RTC_INT_OVERFLOW_MASK);

    __DMB();
    mutex = 0;
}

static inline uint64_t time_to_ticks(uint64_t time, alarm_index index)
{
    if (index == ms_timer)
    {
        time *= US_PER_MS;
    }

    return NRF_802154_US_TO_RTC_TICKS(time);
}

static inline uint64_t ticks_to_time(uint64_t ticks, alarm_index index)
{
    uint64_t result = NRF_802154_RTC_TICKS_TO_US(ticks);

    if (index == ms_timer)
    {
        result /= US_PER_MS;
    }

    return result;
}

static inline bool alarm_shall_strike(uint64_t now, alarm_index index)
{
    return now >= timer_data[index].target;
}

static uint32_t get_over_counter(void)
{
    uint32_t overflowCounter;
    // Get mutual access for writing to overflow_counter variable.
    if (mutex_get())
    {
        bool increasing = false;

        // Check if interrupt was handled already.
        if (nrf_rtc_event_pending(RTC_INSTANCE, NRF_RTC_EVENT_OVERFLOW))
        {
            overflow_counter++;
            increasing = true;

            __DMB();

            // Mark that interrupt was handled.
            nrf_rtc_event_clear(RTC_INSTANCE, NRF_RTC_EVENT_OVERFLOW);

            // Result should be incremented. overflow_counter will be incremented after mutex is released.
        }
        else
        {
            // Either overflow handling is not needed OR we acquired the mutex just after it was released.
            // Overflow is handled after mutex is released, but it cannot be assured that overflow_counter
            // was incremented for the second time, so we increment the result here.
        }

        overflowCounter = (overflow_counter + 1) / 2;

        mutex_release();

        if (increasing)
        {
            // It's virtually impossible that overflow event is pending again before next instruction is performed. It
            // is an error condition.
            assert(overflow_counter & 0x01);

            // Increment the counter for the second time, to allow instructions from other context get correct value of
            // the counter.
            overflow_counter++;
        }
    }
    else
    {
        // Failed to acquire mutex.
        if (nrf_rtc_event_pending(RTC_INSTANCE, NRF_RTC_EVENT_OVERFLOW) || (overflow_counter & 0x01))
        {
            // Lower priority context is currently incrementing overflow_counter variable.
            overflowCounter = (overflow_counter + 2) / 2;
        }
        else
        {
            // Lower priority context has already incremented overflow_counter variable or incrementing is not needed
            // now.
            overflowCounter = overflow_counter / 2;
        }
    }

    return overflowCounter;
}

static uint32_t get_rtc_counter(void)
{
    return nrf_rtc_counter_get(RTC_INSTANCE);
}

static void get_offset_and_counter(uint32_t *offset, uint32_t *counter)
{
    uint32_t offset1 = get_over_counter();

    __DMB();

    uint32_t rtcValue1 = get_rtc_counter();

    __DMB();

    uint32_t offset2 = get_over_counter();

    *offset  = offset2;
    *counter = (offset1 == offset2) ? rtcValue1 : get_rtc_counter();
}

static uint64_t get_time(uint32_t offset, uint32_t counter, alarm_index index)
{
    uint64_t result = (uint64_t)offset * US_PER_OVERFLOW + ticks_to_time(counter, us_timer);

    if (index == ms_timer)
    {
        result /= US_PER_MS;
    }

    return result;
}

static uint64_t get_current_time(alarm_index index)
{
    uint32_t offset;
    uint32_t rtc_counter;

    get_offset_and_counter(&offset, &rtc_counter);

    return get_time(offset, rtc_counter, index);
}

static void handle_compare_match(alarm_index index, bool aSkipCheck)
{
    nrf_rtc_event_clear(RTC_INSTANCE, channel_data[index].comp_event);

    uint64_t now = get_current_time(index);

    // In case the target time was larger than single overflow,
    // we should only strike the timer on final compare event.
    if (aSkipCheck || alarm_shall_strike(now, index))
    {
        nrf_rtc_event_disable(RTC_INSTANCE, channel_data[index].comp_event_mask);
        nrf_rtc_int_disable(RTC_INSTANCE, channel_data[index].comp_int);

        switch (index)
        {
        case m_802154_timer:
//            nrf_802154_lp_timer_fired();
            break;

        case m_802154_sync:
//            nrf_802154_lp_timer_synchronized();
            break;

        case ms_timer:
        case us_timer:
            timer_data[index].fire = true;
            event_pending                 = true;
            break;

        default:
            assert(false);
        }
    }
}

static uint64_t convert_64bit_target(uint32_t start, uint32_t delta, const uint64_t *now)
{
    uint64_t m_now;
    m_now = *now;

    if (((uint32_t)m_now < start) && ((start - (uint32_t)m_now) > (UINT32_MAX / 2)))
    {
        m_now -= EPOCH_32BIT_US;
    }
    else if (((uint32_t)m_now > start) && (((uint32_t)m_now) - start > (UINT32_MAX / 2)))
    {
        m_now += EPOCH_32BIT_US;
    }

    return (EPOCH_FROM_TIME(m_now)) + start + delta;
}

static uint64_t round_up_ticks_multiply(uint64_t time, alarm_index index)
{
    uint64_t ticks  = time_to_ticks(time, index);
    uint64_t result = ticks_to_time(ticks, index);
    return result;
}

static void timer_start(uint32_t start, uint32_t delta, alarm_index index, const uint64_t *now)
{
    uint64_t targetCounter;
    uint64_t target_time;

    nrf_rtc_int_disable(RTC_INSTANCE, channel_data[index].comp_int);
    nrf_rtc_event_enable(RTC_INSTANCE, channel_data[index].comp_event_mask);

    target_time    = convert_64bit_target(start, delta, now);
    targetCounter = time_to_ticks(target_time, index) & RTC_CC_COMPARE_Msk;

    timer_data[index].target = round_up_ticks_multiply(target_time, index);

    nrf_rtc_cc_set(RTC_INSTANCE, channel_data[index].channel_num, targetCounter);
}

static void alarm_start(uint32_t start, uint32_t delta, alarm_index index)
{
    uint32_t offset;
    uint32_t rtc_value;
    uint64_t now;
    uint64_t now_rtc_protected;

    get_offset_and_counter(&offset, &rtc_value);
    now = get_time(offset, rtc_value, index);

    timer_start(start, delta, index, &now);

    if (rtc_value != get_rtc_counter())
    {
        get_offset_and_counter(&offset, &rtc_value);
    }

    now_rtc_protected = get_time(offset, rtc_value + MIN_RTC_COMPARE_EVENT_TICKS, index);

    if (alarm_shall_strike(now_rtc_protected, index))
    {
        handle_compare_match(index, true);

        /**
         * Normally ISR sets event flag automatically.
         * Here we are calling handle_compare_match explicitly and no ISR will be fired.
         * To prevent possible permanent sleep on next WFE we have to set event flag.
         */
        __SEV();
    }
    else
    {
        nrf_rtc_int_enable(RTC_INSTANCE, channel_data[index].comp_int);
    }
}

static void timer_sync_start(uint32_t start, uint32_t delta, const uint64_t *now)
{
    timer_start(start, delta, m_802154_sync, now);

    nrf_rtc_int_enable(RTC_INSTANCE, channel_data[m_802154_sync].comp_int);
}

static void alarm_stop(alarm_index index)
{
    nrf_rtc_event_disable(RTC_INSTANCE, channel_data[index].comp_event_mask);
    nrf_rtc_int_disable(RTC_INSTANCE, channel_data[index].comp_int);
    nrf_rtc_event_clear(RTC_INSTANCE, channel_data[index].comp_event);

    timer_data[index].fire = false;
}

void nrf5_alarm_init(void)
{
    memset(timer_data, 0, sizeof(timer_data));
    overflow_counter = 0;
    mutex           = 0;
    time_offset      = 0;

    // Setup low frequency clock.
    nrf_drv_clock_lfclk_request(NULL);

    while (!nrf_drv_clock_lfclk_is_running())
    {
    }

    // Setup RTC timer.
    NVIC_SetPriority(RTC_IRQN, RTC_IRQ_PRIORITY);
    NVIC_ClearPendingIRQ(RTC_IRQN);
    NVIC_EnableIRQ(RTC_IRQN);

    nrf_rtc_prescaler_set(RTC_INSTANCE, 0);

    nrf_rtc_event_clear(RTC_INSTANCE, NRF_RTC_EVENT_OVERFLOW);
    nrf_rtc_event_enable(RTC_INSTANCE, RTC_EVTEN_OVRFLW_Msk);
    nrf_rtc_int_enable(RTC_INSTANCE, NRF_RTC_INT_OVERFLOW_MASK);

    for (uint32_t i = 0; i < num_timers; i++)
    {
        nrf_rtc_event_clear(RTC_INSTANCE, channel_data[i].comp_event);
        nrf_rtc_event_disable(RTC_INSTANCE, channel_data[i].comp_event_mask);
        nrf_rtc_int_disable(RTC_INSTANCE, channel_data[i].comp_int);
    }

    nrf_rtc_task_trigger(RTC_INSTANCE, NRF_RTC_TASK_START);
}

void nrf5_alarm_deinit(void)
{
    nrf_rtc_task_trigger(RTC_INSTANCE, NRF_RTC_TASK_STOP);

    for (uint32_t i = 0; i < num_timers; i++)
    {
        nrf_rtc_event_clear(RTC_INSTANCE, channel_data[i].comp_event);
        nrf_rtc_event_disable(RTC_INSTANCE, channel_data[i].comp_event_mask);
        nrf_rtc_int_disable(RTC_INSTANCE, channel_data[i].comp_int);
    }

    nrf_rtc_int_disable(RTC_INSTANCE, NRF_RTC_INT_OVERFLOW_MASK);
    nrf_rtc_event_disable(RTC_INSTANCE, RTC_EVTEN_OVRFLW_Msk);
    nrf_rtc_event_clear(RTC_INSTANCE, NRF_RTC_EVENT_OVERFLOW);

    nrf_802154_lp_timer_sync_stop();

    NVIC_DisableIRQ(RTC_IRQN);
    NVIC_ClearPendingIRQ(RTC_IRQN);
    NVIC_SetPriority(RTC_IRQN, 0);

    nrf_drv_clock_lfclk_release();
}

void nrf5_alarm_process(void* instance)
{
    do
    {
        event_pending = false;
        if (timer_data[ms_timer].fire)
        {
            timer_data[ms_timer].fire = false;
            {
                ndn_platform_alarm_millis_fire(instance);
            }
        }

        if (timer_data[us_timer].fire)
        {
            timer_data[us_timer].fire = false;
//            ndn_platform_alarm_micros_fire(instance);
        }

    } while (event_pending);
}

void ndn_platform_alarm_process(void* instance) {
    nrf5_alarm_process(instance);
}

static inline uint64_t alarm_get_current_time(void)
{
    return get_current_time(us_timer);
}


/* APIs */
void ndn_platform_alarm_init(void)
{
  nrf5_alarm_init();
}

void ndn_platform_alarm_deinit(void)
{
  nrf5_alarm_deinit();
}

uint64_t ndn_platform_alarm_millis_get_now(void)
{
    return (get_current_time(us_timer)/ US_PER_MS);
}

uint64_t ndn_platform_alarm_micros_get_now(void)
{
    return get_current_time(us_timer);
}

void ndn_platform_alarm_millis_stop(void)
{
    alarm_stop(ms_timer);
}

void ndn_platform_alarm_millis_start(uint32_t start, uint32_t delta)
{
    alarm_start(start, delta, ms_timer);
}

/**
 * Radio driver timer abstraction API
 */

void nrf_802154_lp_timer_init(void)
{
    // Intentionally empty
}

void nrf_802154_lp_timer_deinit(void)
{
    // Intentionally empty
}

void nrf_802154_lp_timer_critical_section_enter(void)
{
    nrf_rtc_int_disable(RTC_INSTANCE, channel_data[m_802154_timer].comp_int);
    __DSB();
    __ISB();
}

void nrf_802154_lp_timer_critical_section_exit(void)
{
    nrf_rtc_int_enable(RTC_INSTANCE, channel_data[m_802154_timer].comp_int);
}

uint32_t nrf_802154_lp_timer_time_get(void)
{
    return (uint32_t)alarm_get_current_time();
}

uint32_t nrf_802154_lp_timer_granularity_get(void)
{
    return NRF_802154_US_PER_TICK;
}

void nrf_802154_lp_timer_start(uint32_t t0, uint32_t dt)
{
    alarm_start(t0, dt, m_802154_timer);
}

bool nrf_802154_lp_timer_is_running(void)
{
    return nrf_rtc_int_is_enabled(RTC_INSTANCE, channel_data[m_802154_timer].comp_int);
}

void nrf_802154_lp_timer_stop(void)
{
    alarm_stop(m_802154_timer);
}

void nrf_802154_lp_timer_sync_start_now(void)
{
    uint32_t counter;
    uint32_t offset;
    uint64_t now;

    do
    {
        get_offset_and_counter(&offset, &counter);
        now = get_time(offset, counter, m_802154_sync);
        timer_sync_start((uint32_t)now, MIN_RTC_COMPARE_EVENT_DT, &now);
    } while (get_rtc_counter() != counter);
}

void nrf_802154_lp_timer_sync_start_at(uint32_t t0, uint32_t dt)
{
    uint64_t now = get_current_time(m_802154_sync);

    timer_sync_start(t0, dt, &now);
}

void nrf_802154_lp_timer_sync_stop(void)
{
    alarm_stop(m_802154_sync);
}

uint32_t nrf_802154_lp_timer_sync_event_get(void)
{
    return (uint32_t)nrf_rtc_event_address_get(RTC_INSTANCE, channel_data[m_802154_sync].comp_event);
}

uint32_t nrf_802154_lp_timer_sync_time_get(void)
{
    return (uint32_t)timer_data[m_802154_sync].target;
}

/**
 * RTC IRQ handler
 */

void RTC_IRQ_HANDLER(void)
{
    // Handle overflow.
    if (nrf_rtc_event_pending(RTC_INSTANCE, NRF_RTC_EVENT_OVERFLOW))
    {
        // Disable OVERFLOW interrupt to prevent lock-up in interrupt context while mutex is locked from lower priority
        // context and OVERFLOW event flag is stil up. OVERFLOW interrupt will be re-enabled when mutex is released -
        // either from this handler, or from lower priority context, that locked the mutex.
        nrf_rtc_int_disable(RTC_INSTANCE, NRF_RTC_INT_OVERFLOW_MASK);

        // Handle OVERFLOW event by reading current value of overflow counter.
        (void)get_over_counter();
    }

    // Handle compare match.
    for (uint32_t i = 0; i < num_timers; i++)
    {
        if (nrf_rtc_int_is_enabled(RTC_INSTANCE, channel_data[i].comp_int) &&
            nrf_rtc_event_pending(RTC_INSTANCE, channel_data[i].comp_event))
        {
            handle_compare_match((alarm_index)i, false);
        }
    }
}

/**  @} */
