set(DIR_FORWARDER "${DIR_NDN_LITE}/forwarder")
target_sources(ndn-lite PUBLIC
  ${DIR_FORWARDER}/callback-funcs.h
  ${DIR_FORWARDER}/face-table.h
  ${DIR_FORWARDER}/face.h
  ${DIR_FORWARDER}/fib.h
  ${DIR_FORWARDER}/forwarder.h
  ${DIR_FORWARDER}/name-tree.h
  ${DIR_FORWARDER}/pit.h
)
target_sources(ndn-lite PRIVATE
  ${DIR_FORWARDER}/face-table.c
  ${DIR_FORWARDER}/fib.c
  ${DIR_FORWARDER}/forwarder.c
  ${DIR_FORWARDER}/name-tree.c
  ${DIR_FORWARDER}/pit.c
)
unset(DIR_FORWARDER)
