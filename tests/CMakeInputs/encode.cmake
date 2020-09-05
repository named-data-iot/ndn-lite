set(DIR_ENCODE "${DIR_NDN_LITE}/encode")
set(DIR_TRUST_SCHEMA "${DIR_ENCODE}/trust-schema")
target_sources(ndn-lite PUBLIC
  ${DIR_ENCODE}/data.h
  ${DIR_ENCODE}/decoder.h
  ${DIR_ENCODE}/encoder.h
  ${DIR_ENCODE}/encrypted-payload.h
  ${DIR_ENCODE}/fragmentation-support.h
  ${DIR_ENCODE}/interest.h
  ${DIR_ENCODE}/key-storage.h
  ${DIR_ENCODE}/metainfo.h
  ${DIR_ENCODE}/name-component.h
  ${DIR_ENCODE}/name.h
  ${DIR_ENCODE}/signature.h
  ${DIR_ENCODE}/signed-interest.h
  ${DIR_ENCODE}/tlv.h
  ${DIR_ENCODE}/forwarder-helper.h
  ${DIR_ENCODE}/ndn-rule-storage.h
  ${DIR_ENCODE}/wrapper-api.h
  ${DIR_TRUST_SCHEMA}/ndn-trust-schema-common.h
  ${DIR_TRUST_SCHEMA}/ndn-trust-schema-pattern-component.h
  ${DIR_TRUST_SCHEMA}/ndn-trust-schema-pattern.h
  ${DIR_TRUST_SCHEMA}/ndn-trust-schema-rule.h
)
target_sources(ndn-lite PRIVATE
  ${DIR_ENCODE}/data.c
  ${DIR_ENCODE}/encrypted-payload.c
  ${DIR_ENCODE}/interest.c
  ${DIR_ENCODE}/key-storage.c
  ${DIR_ENCODE}/metainfo.c
  ${DIR_ENCODE}/name-component.c
  ${DIR_ENCODE}/name.c
  ${DIR_ENCODE}/signature.c
  ${DIR_ENCODE}/signed-interest.c
  ${DIR_ENCODE}/forwarder-helper.c
  ${DIR_ENCODE}/ndn-rule-storage.c
  ${DIR_ENCODE}/wrapper-api.c
  ${DIR_TRUST_SCHEMA}/ndn-trust-schema-pattern-component.c
  ${DIR_TRUST_SCHEMA}/ndn-trust-schema-pattern.c
  ${DIR_TRUST_SCHEMA}/ndn-trust-schema-rule.c
)
unset(DIR_TRUST_SCHEMA)
unset(DIR_ENCODE)
