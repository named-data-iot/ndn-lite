#include <time.h>
#include <unistd.h>
#include <ndn-lite/util/uniform-time.h>

ndn_time_ms_t ndn_time_now_ms(void){
  struct timespec time;
  clock_gettime(CLOCK_REALTIME, &time);
  return (uint64_t)time.tv_sec * 1000 + (uint64_t)time.tv_nsec / 1000000;
}

ndn_time_us_t ndn_time_now_us(void){
  struct timespec time;
  clock_gettime(CLOCK_REALTIME, &time);
  return (uint64_t)time.tv_sec * 1000000 + (uint64_t)time.tv_nsec / 1000;
}

void ndn_time_delay(ndn_time_ms_t delay){
  if(delay < 1000000){
    usleep(delay * 1000);
  }else{
    sleep(delay / 1000);
  }
}
