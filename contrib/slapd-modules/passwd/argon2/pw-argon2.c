/* pw-argon2.c - Password module for argon2 */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2017 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#define _GNU_SOURCE

#include "portable.h"
#include "ac/string.h"
#include "lber_pvt.h"
#include "lutil.h"

#include <sodium.h>
#include <stdint.h>
#include <stdlib.h>

/*
 * For now, we hardcode the default values from the libsodium "INTERACTIVE" values
 */
#define SLAPD_ARGON2_ITERATIONS crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE
#define SLAPD_ARGON2_MEMORY crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE

const struct berval slapd_argon2_scheme = BER_BVC("{ARGON2}");

static int slapd_argon2_hash(
  const struct berval *scheme,
  const struct berval *passwd,
  struct berval *hash,
  const char **text) {

  /*
   * Duplicate these values here so future code which allows
   * configuration has an easier time.
   */
  uint32_t iterations = SLAPD_ARGON2_ITERATIONS;
  uint32_t memory = SLAPD_ARGON2_MEMORY;

  size_t encoded_length = crypto_pwhash_argon2i_strbytes();

  struct berval encoded;
  encoded.bv_len = encoded_length;
  encoded.bv_val = ber_memalloc(encoded.bv_len);

  int rc = crypto_pwhash_argon2i_str(encoded.bv_val, passwd->bv_val, passwd->bv_len,
            iterations, memory);

  if(rc) {
    ber_memfree(encoded.bv_val);
    return LUTIL_PASSWD_ERR;
  }

  hash->bv_len = scheme->bv_len + encoded_length;
  hash->bv_val = ber_memalloc(hash->bv_len);

  AC_MEMCPY(hash->bv_val, scheme->bv_val, scheme->bv_len);
  AC_MEMCPY(hash->bv_val + scheme->bv_len, encoded.bv_val, encoded.bv_len);

  ber_memfree(encoded.bv_val);

  return LUTIL_PASSWD_OK;
}

static int slapd_argon2_verify(
  const struct berval *scheme,
  const struct berval *passwd,
  const struct berval *cred,
  const char **text) {

  int rc = crypto_pwhash_argon2i_str_verify(passwd->bv_val, cred->bv_val, cred->bv_len);

  if (rc) {
    return LUTIL_PASSWD_ERR;
  }
  return LUTIL_PASSWD_OK;
}

int init_module(int argc, char *argv[]) {
  int rc = sodium_init();
  if (rc == -1) {
    return -1;
  }
  return lutil_passwd_add((struct berval *)&slapd_argon2_scheme,
              slapd_argon2_verify, slapd_argon2_hash);
}
