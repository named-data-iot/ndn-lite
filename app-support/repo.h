/*
 * Copyright (C) 2020 Tianyuan
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */
/*
 * This file-tranfer-client works with file-transfer-server.
 * Launch the file-transfer-server, input local port, client ip, client port and name.
 * Launch the file-transfer-client, input local port, server ip, server port, name and the file name.
 * The server will then return the requested file to the client. (if the file exists in the directory)
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "security-bootstrapping.h"
#include "../encode/name.h"
#include "../encode/data.h"
#include "../encode/interest.h"
#include "../app-support/security-bootstrapping.h"
#include "../encode/key-storage.h"


/*
 * The Repo command by default publish insertion command.
 * This implementation follows latest ndn-python-repo's pub-sub fashion
 * This implementation assumes repo's routable prefix is /<home-prefix>/repo
 * Actual on_interest() cb should be maintained by callers.
 * Example is test-repo.c in POSIX package.
 * TODO: Other repo commands.
 * By default, all optional fields are omitted.
 *        1. No start_block_id nor end_block_id
 *        2. No register prefix
 *        3. No status check
 */
typedef struct nonce_to_msg {
  uint32_t nonce;
  uint8_t msg[500];
  uint32_t msg_size;
  uint8_t service;
} nonce_to_msg_t;



typedef struct repo_state {
  nonce_to_msg_t dict[10];
} repo_state_t;


void
ndn_repo_init();

void
ndn_repo_publish_cmd_param(ndn_name_t* expected_name, uint8_t service);



