/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "dummy-face-with-mtu.h"
#include "ndn-lite/encode/data.h"
#include "ndn-lite/encode/fragmentation-support.h"
#include "ndn-lite/forwarder/forwarder.h"
#include <stdio.h>
#include <stdlib.h>

/************************************************************/
/*  Inherit Face Interfaces                                 */
/************************************************************/
static packet_t buf[MAX_PACKETS_IN_BUFFER];
static uint8_t buf_counter = 0;

int next_packet_index()
{
  if (buf_counter == MAX_PACKETS_IN_BUFFER)
  {
    buf_counter = 0;
  }
  return buf_counter++;
}

int ndn_dummy_face_up(struct ndn_face_intf *self)
{
  self->state = NDN_FACE_STATE_UP;
  printf("Dummy Face [%u] Up\n", self->face_id);
  return NDN_SUCCESS;
}

int ndn_dummy_face_send(struct ndn_face_intf *self,
                        const uint8_t *packet, uint32_t size)
{
  uint32_t i = 0;

  if (self->state != NDN_FACE_STATE_UP)
  {
    printf("Dummy face [%u] unable to send the packet.\n", self->face_id);
    return NDN_FWD_FACE_DOWN;
  }
  printf("Dummy Face [%u] send packet (%d bytes):", self->face_id, size);
  for (i = 0; i < size; i++)
  {
    printf(" %02X", packet[i]);
  }
  printf("\n");

  return NDN_SUCCESS;
}

int ndn_dummy_face_send_with_fragmenter(struct ndn_face_intf *self,
                                        const uint8_t *packet, uint32_t size)
{
  printf("\n --- BEGIN ORIGINAL %d BYTES ---\n", size);
  for (int i = 0; i < size; i++)
  {
    printf(" %02X", packet[i]);
  }
  printf("\n --- END ORIGINAL ---\n");
  // fragment oversized packet
  ndn_fragmenter_t fragmenter;
  ndn_fragmenter_init(&fragmenter, packet, size, MTU, 123);
  int ret_val = 0;
  printf("Big Packet: %d bytes, %d fragments\n\n --- BEGIN SEND FRAGMENTS --- \n", size, fragmenter.total_frag_num);
  while (fragmenter.counter < fragmenter.total_frag_num)
  {
    int prev_offset = fragmenter.offset;
    packet_t *next_packet = &buf[next_packet_index()];
    ret_val += ndn_fragmenter_fragment(&fragmenter, next_packet->block_value);
    next_packet->size = fragmenter.offset - prev_offset;
    ndn_dummy_face_send(self, next_packet->block_value, 3+next_packet->size);
  }
  printf(" --- END SEND FRAGMENTS --- \n\n");
  if (ret_val > 0) {
    return 1;
  }
  return 0;
}

int ndn_dummy_face_down(struct ndn_face_intf *self)
{
  self->state = NDN_FACE_STATE_DOWN;
  printf("Dummy Face [%u] Down\n", self->face_id);
  return NDN_SUCCESS;
}

void ndn_dummy_face_destroy(struct ndn_face_intf *self)
{
  self->state = NDN_FACE_STATE_DESTROYED;
  printf("Dummy Face [%u] Destroyed\n", self->face_id);

  ndn_forwarder_unregister_face(self);
  free(container_of(self, ndn_dummy_face_with_mtu_t, intf));
  for (int i = 0; i < MAX_PACKETS_IN_BUFFER; i++)
  {
    if (buf[i].block_value != NULL)
    {
      free(buf[i].block_value);
    }
  }
}

ndn_dummy_face_with_mtu_t *
ndn_dummy_face_construct()
{
  ndn_dummy_face_with_mtu_t *face;

  face = malloc(sizeof(ndn_dummy_face_with_mtu_t));
  if (face == NULL)
    return NULL;

  for (int i = 0; i < MAX_PACKETS_IN_BUFFER; i++)
  {
    buf[i].block_value = malloc(sizeof(uint8_t) * MTU);
    buf[i].size = 0;
  }
  face->intf.up = ndn_dummy_face_up;
  face->intf.send = ndn_dummy_face_send;
  face->intf.down = ndn_dummy_face_down;
  face->intf.destroy = ndn_dummy_face_destroy;
  face->intf.face_id = NDN_INVALID_ID;
  face->intf.state = NDN_FACE_STATE_UP;
  face->intf.type = NDN_FACE_TYPE_NET;

  if (ndn_forwarder_register_face(&face->intf) != NDN_SUCCESS)
  {
    free(face);
    return NULL;
  }

  printf("Dummy Face [%u] Constructed\n", face->intf.face_id);

  return face;
}

/*
 * Assemble fragments and put assembled data packet to forwarder
 * Assume fragment starts in buf[0] in order and buf does not roll over
 */
void recv_from_face(ndn_dummy_face_with_mtu_t* self) {
  uint8_t original[MTU*MAX_PACKETS_IN_BUFFER];
  ndn_frag_assembler_t assembler;
  ndn_frag_assembler_init(&assembler, original, MTU * MAX_PACKETS_IN_BUFFER);
  uint32_t original_len = 0;
  for (int i = 0; i < MAX_PACKETS_IN_BUFFER; i++) {
    if (buf[i].size < 1) {
      break;
    }
    original_len += buf[i].size;
    for (int j = 0; j < buf[i].size; j++) {
      printf(" %02X", buf[i].block_value[j]);
    }
    printf("\n");
    int ret_val = ndn_frag_assembler_assemble_frag(&assembler, buf[i].block_value, MTU);
    if (ret_val != 0) {
      printf("Assembler error: %d\n", ret_val);
      return;
    } 
  }
  printf("\n\n --- BEGIN ASSEMBLED %d BYTES ---\n", original_len);
  for (int i = 0; i < original_len; i++)
  {
    printf(" %02X", original[i]);
  }
  printf("\n --- END ASSEMBLED ---\n");
  ndn_forwarder_receive(&self->intf, original, original_len);
}