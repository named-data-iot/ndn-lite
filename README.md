Issues:
1. currently we have lots of header file included problems, please fix them (already done)
2. may be we should include the whole ndn-riot pkg into this folder? (already done)
3. output compatibility with DPRINT and DEBUG (maybe we should use DEBUG, aligning with ndn thread? 
   the newst thought is to use DPRINT for app framework function and DEBUG for core part) (already done)
4. maybe firstly we should try a hard code key pair in the bootstrap file, or pass a key pair into nfl? (prefer the          latter)
5. by now we do pass the key pair into bootstrap function, but we void the ptr in bootstrap.c (so we use the hard code       key pair actually)
6. perhaps we don't need a init() for every services?

TODO:
8/1 configure riot pkg with local lib (failed, use github instead)
    adjust the struct to include m_host (delayed, implement functionality first)
    try to run the demo? (already done)
    auto init is in RIOT/sys/auto_init/auto_init.c