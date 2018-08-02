#ifndef NFL_H_
#define NFL_H_

#include <kernel_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   NFL's PID 
 *
 * @note    Use @ref nfl_init() to initialize. **Do not set by hand**.
 */
extern kernel_pid_t nfl_pid;

/*
 * @brief   Initialization of the NFL thread.
 *
 * @return  The PID to the NFL thread, on success.
 * @return  a negative errno on error.
 * @return  -EOVERFLOW, if there are too many threads running already
 * @return  -EEXIST, if NDN was already initialized.
 */
kernel_pid_t nfl_init(void);




#ifdef __cplusplus
}
#endif

#endif /* NFL_H_ */
/** @} */
