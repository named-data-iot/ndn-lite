target_sources(ndn-lite PUBLIC
  ${DIR_NDN_LITE}/ndn-constants.h
  ${DIR_NDN_LITE}/ndn-enums.h
  ${DIR_NDN_LITE}/ndn-error-code.h
  ${DIR_NDN_LITE}/ndn-services.h
  ${PROJECT_SOURCE_DIR}/ndn-lite.h
)
include(${DIR_CMAKEFILES}/app-support.cmake)
include(${DIR_CMAKEFILES}/encode.cmake)
include(${DIR_CMAKEFILES}/face.cmake)
include(${DIR_CMAKEFILES}/forwarder.cmake)
include(${DIR_CMAKEFILES}/util.cmake)
include(${DIR_CMAKEFILES}/security.cmake)
