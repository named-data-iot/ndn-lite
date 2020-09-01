target_sources(ndn-lite PUBLIC
  ${DIR_ADAPTATION}/adapt-consts.h
  ${DIR_ADAPTATION}/udp/udp-face.h
  ${DIR_ADAPTATION}/unix-socket/unix-face.h
  ${DIR_ADAPTATION}/security/ndn-lite-rng-posix-crypto-impl.h
)
target_sources(ndn-lite PRIVATE
  ${DIR_ADAPTATION}/uniform-time.c
  ${DIR_ADAPTATION}/udp/udp-face.c
  ${DIR_ADAPTATION}/unix-socket/unix-face.c
  ${DIR_ADAPTATION}/security/ndn-lite-rng-posix-crypto-impl.c
  ${DIR_ADAPTATION}/ndn-lite.c
)
