set(DIR_UNITTESTS "${PROJECT_SOURCE_DIR}/unit-tests")

# Main files
target_sources(unittest PRIVATE
  "${DIR_UNITTESTS}/print-helpers.h"
  "${DIR_UNITTESTS}/print-helpers.c"
  "${DIR_UNITTESTS}/test-helpers.h"
  "${DIR_UNITTESTS}/test-helpers.c"
  "${DIR_UNITTESTS}/main.c"
)

# Well-named tests
set(LIST_TESTS
  # "access-control"
  "data"
  "encoder-decoder"
  "forwarder"
  "fragmentation-support"
  "interest"
  "metainfo"
  "name-encode-decode"
  "random"
  # "service-discovery"
  "signature"
  "util"
)
foreach(TESTNAME IN LISTS LIST_TESTS)
  target_sources(unittest PRIVATE
    "${DIR_UNITTESTS}/${TESTNAME}/${TESTNAME}-tests-def.h"
    "${DIR_UNITTESTS}/${TESTNAME}/${TESTNAME}-tests-def.c"
    "${DIR_UNITTESTS}/${TESTNAME}/${TESTNAME}-tests.h"
    "${DIR_UNITTESTS}/${TESTNAME}/${TESTNAME}-tests.c"
  )
endforeach()
unset(LIST_TESTS)

# Irregularly named tests
target_sources(unittest PRIVATE
  "${DIR_UNITTESTS}/sign-verify/sign-verify-tests.h"
  "${DIR_UNITTESTS}/sign-verify/sign-verify-tests.c"
  "${DIR_UNITTESTS}/hmac/hmac-tests.h"
  "${DIR_UNITTESTS}/hmac/hmac-tests.c"
  "${DIR_UNITTESTS}/aes/aes-tests.c"
  "${DIR_UNITTESTS}/aes/aes-tests.h"
)
set(LIST_SIGN_VERIFY_TESTS
  "asn-encode-decode-tests"
  "ecdsa-sign-verify-tests"
  "hmac-sign-verify-tests"
  "sha256-sign-verify-tests"
)
foreach(TESTNAME IN LISTS LIST_SIGN_VERIFY_TESTS)
  target_sources(unittest PRIVATE
    "${DIR_UNITTESTS}/sign-verify/${TESTNAME}/${TESTNAME}-def.h"
    "${DIR_UNITTESTS}/sign-verify/${TESTNAME}/${TESTNAME}-def.c"
    "${DIR_UNITTESTS}/sign-verify/${TESTNAME}/${TESTNAME}.h"
    "${DIR_UNITTESTS}/sign-verify/${TESTNAME}/${TESTNAME}.c"
  )
endforeach()
unset(LIST_SIGN_VERIFY_TESTS)
target_sources(unittest PRIVATE
  "${DIR_UNITTESTS}/sign-verify/ecdsa-sign-verify-tests/test-secp256r1-def.h"
  "${DIR_UNITTESTS}/sign-verify/ecdsa-sign-verify-tests/test-secp256r1-def.c"
)

target_sources(unittest PRIVATE
  "${DIR_UNITTESTS}/schematized-trust/trust-schema-tests.h"
  "${DIR_UNITTESTS}/schematized-trust/trust-schema-tests.c"
  "${DIR_UNITTESTS}/schematized-trust/trust-schema-tests-def.h"
  "${DIR_UNITTESTS}/schematized-trust/trust-schema-tests-def.c"
)