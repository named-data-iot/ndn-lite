/*
 * Copyright (C) 2016 Wentao Shang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_ndn    NDN packet processing
 * @ingroup     net
 * @brief       NDN packet sending and receiving.
 * @{
 *
 * @file
 * @brief   NDN sending and receiving interface.
 *
 * @author  Wentao Shang <wentaoshang@gmail.com>
 */
#ifndef NDN_H_
#define NDN_H_

#include <kernel_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   The PID to the NDN thread.
 *
 * @note    Use @ref ndn_init() to initialize. **Do not set by hand**.
 */
extern kernel_pid_t ndn_pid;

/*
 * @brief   Initialization of the NDN thread.
 *
 * @return  The PID to the NDN thread, on success.
 * @return  a negative errno on error.
 * @return  -EOVERFLOW, if there are too many threads running already
 * @return  -EEXIST, if NDN was already initialized.
 */
kernel_pid_t ndn_init(void);


#ifdef __cplusplus
}
#endif

#endif /* NDN_H_ */
/** @} */
