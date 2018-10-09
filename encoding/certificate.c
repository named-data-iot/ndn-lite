/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     net_ndn_encoding
 * @{
 *
 * @file
 *
 * @author  Zhiyi Zhang <zhiyi@cs.ucla.edu>
 */

#include "certificate.h"
#include "name.h"

int
ndn_cert_is_certificate_name(ndn_name_t* cert_name)
{
  if (cert_name == NULL || cert_name->comps == NULL || cert_name->size <= 0) {
    return -1;
  }
  ndn_name_component_t component;
  ndn_name_get_component(cert_name, -4, &component);

  if (component.len != 3) return 0;
  if (component.buf[0] != 'K'
      || component.buf[1] != 'E'
      || component.buf[2] != 'Y') return 0;
  return 1;
}

int
ndn_cert_get_identity_name(ndn_name_t* cert_name, ndn_name_t* identity_name)
{
  if (cert_name == NULL || cert_name->comps == NULL || cert_name->size <= 0) {
    return -1;
  }

  identity_name->size = cert_name->size - 4;
  identity_name->comps = malloc(identity_name->size * sizeof(ndn_name_component_t));

  for (int i = 0; i < identity_name->size; ++i) {
    identity_name->comps[i] = cert_name->comps[i];
  }
  return 0;
}

int
ndn_cert_get_key_name(ndn_name_t* cert_name, ndn_name_t* key_name)
{
  if (cert_name == NULL || cert_name->comps == NULL || cert_name->size <= 0) {
    return -1;
  }

  key_name->size = cert_name->size - 2;
  key_name->comps = malloc(key_name->size * sizeof(ndn_name_component_t));

  for (int i = 0; i < key_name->size; ++i) {
    key_name->comps[i] = cert_name->comps[i];
  }
  return 0;
}