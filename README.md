Description:
NFL is an pkg which includes the original ndn-riot as ndn functionality core (e.g., creating face table, pending interest table), but extends the ndn-riot with advanced feature of security and services supports in NDNoT scenerio. Previously, ndn thread automatically initiated upon the devices (lets say, boards) initiated. NFL runs in a similar way, automatically run before the user defined application actucally start execution.
Under current ndn-riot framework, bootstrapping and other advanced features seem need to register on ndn core thread as applications with their thread pids being face_ids. Therefore, NFL works like a application registeration helper for these advanced features (e.g., bootstrapping, self-learning, service discovery). Take bootstrapping as a example, user defined application send request START_BOOTSTRAP to NFL thread via IPC tunnel, NFL regsiters the bootstrapping thread on ndn core thread with bootstrapping pid as its face_id. Then bootstrapping thread performs its functionality with remote controller, with a bootstrap_tuple struct pointer which contains necessary info of bootstrapping result (e.g., anchor certificate, m_certificate, home prefix) sent back to NFL thread via IPC tunnel. NFL will maintain the bootstrap tuple, waiting for user defined application send request EXTRACT_BOOTSTRAP_TUPLE to retrieve the tuple (just to avoid confusion, after retrieve, NFL thread keep maintain the tuple) also via IPC tunnel. Consequently, the user defined application won't touch the detail of these thread operation but the result.
Future, contributors will try to merge NFL to original ndn core thread.

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