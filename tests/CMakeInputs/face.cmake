set(DIR_FACE "${DIR_NDN_LITE}/face")
target_sources(ndn-lite PUBLIC
  ${DIR_FACE}/dummy-face.h
)
target_sources(ndn-lite PRIVATE
  ${DIR_FACE}/dummy-face.c
)
unset(DIR_FACE)
