#include "ndn-lite.h"
#include "security/ndn-lite-rng-posix-crypto-impl.h"
#include <ndn-lite/security/ndn-lite-sec-config.h>

// Temporarily put the helper func here
void
ndn_lite_startup()
{
  register_platform_security_init(ndn_lite_posix_rng_load_backend);
  ndn_security_init();
  ndn_forwarder_init();
}
