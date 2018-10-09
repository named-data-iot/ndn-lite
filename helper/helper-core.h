#ifndef HELPER_H_
#define HELPER_H_

#include <kernel_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   helper's PID 
 *
 * @note    Use @ref helper_init() to initialize. **Do not set by hand**.
 */
extern kernel_pid_t ndn_helper_pid;

/*
 * @brief   Initialization of the helper thread.
 *
 * @return  The PID to the helper thread, on success.
 * @return  a negative errno on error.
 * @return  -EOVERFLOW, if there are too many threads running already
 * @return  -EEXIST, if NDN was already initialized.
 */
kernel_pid_t ndn_helper_init(void);




#ifdef __cplusplus
}
#endif

#endif /* HELPER_H_ */
/** @} */
