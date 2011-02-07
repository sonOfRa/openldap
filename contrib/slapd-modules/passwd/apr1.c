/*
 * This file is derived from OpenLDAP Software. All of the modifications to
 * OpenLDAP Software represented in the following file were developed by
 * Devin J. Pohly <djpohly@gmail.com>. I have not assigned rights and/or
 * interest in this work to any party. 
 *
 * The extensions to OpenLDAP Software herein are subject to the following
 * notice:
 *
 * Copyright 2011 Devin J. Pohly
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP Public
 * License. 
 *
 * A portion of this code is used in accordance with the Beer-ware License,
 * revision 42, as noted.
 */
#include <lber.h>
#include <lber_pvt.h>
#include "lutil.h"
#include "lutil_md5.h"
#include <ac/string.h>

#include <assert.h>

static LUTIL_PASSWD_CHK_FUNC chk_apr1;
static LUTIL_PASSWD_HASH_FUNC hash_apr1;
static const struct berval scheme = BER_BVC("{APR1}");

static const unsigned char apr64[] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#define APR_SALT_SIZE	8

/* The algorithm implemented in this function was created by Poul-Henning
 * Kamp and released under the following license:
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@FreeBSD.ORG> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 */
static void do_apr_hash(
	const struct berval *passwd,
	const struct berval *salt,
	unsigned char *digest)
{
	lutil_MD5_CTX ctx, ctx1;
	int n;

	/* Start hashing */
	lutil_MD5Init(&ctx);
	lutil_MD5Update(&ctx, (const unsigned char *) passwd->bv_val, passwd->bv_len);
	lutil_MD5Update(&ctx, "$apr1$", 6);
	lutil_MD5Update(&ctx, (const unsigned char *) salt->bv_val, salt->bv_len);
	/* Inner hash */
	lutil_MD5Init(&ctx1);
	lutil_MD5Update(&ctx1, (const unsigned char *) passwd->bv_val, passwd->bv_len);
	lutil_MD5Update(&ctx1, (const unsigned char *) salt->bv_val, salt->bv_len);
	lutil_MD5Update(&ctx1, (const unsigned char *) passwd->bv_val, passwd->bv_len);
	lutil_MD5Final(digest, &ctx1);
	/* Nom start mixing things up */
	for (n = passwd->bv_len; n > 0; n -= LUTIL_MD5_BYTES)
		lutil_MD5Update(&ctx, digest,
				(n > LUTIL_MD5_BYTES ? LUTIL_MD5_BYTES : n));
	memset(digest, 0, LUTIL_MD5_BYTES);
	/* Curiouser and curiouser... */
	for (n = passwd->bv_len; n; n >>= 1)
		if (n & 1)
			lutil_MD5Update(&ctx, digest, 1);
		else
			lutil_MD5Update(&ctx, (const unsigned char *) passwd->bv_val, 1);
	lutil_MD5Final(digest, &ctx);
	/*
	 * Repeatedly hash things into the final value. This was originally
	 * intended to slow the algorithm down.
	 */
	for (n = 0; n < 1000; n++) {
		lutil_MD5Init(&ctx1);
		if (n & 1)
			lutil_MD5Update(&ctx1,
				(const unsigned char *) passwd->bv_val, passwd->bv_len);
		else
			lutil_MD5Update(&ctx1, digest, LUTIL_MD5_BYTES);

		if (n % 3)
			lutil_MD5Update(&ctx1,
				(const unsigned char *) salt->bv_val, salt->bv_len);
		if (n % 7)
			lutil_MD5Update(&ctx1,
				(const unsigned char *) passwd->bv_val, passwd->bv_len);

		if (n & 1)
			lutil_MD5Update(&ctx1, digest, LUTIL_MD5_BYTES);
		else
			lutil_MD5Update(&ctx1,
				(const unsigned char *) passwd->bv_val, passwd->bv_len);
		lutil_MD5Final(digest, &ctx1);
	}
}

static int chk_apr1(
	const struct berval *scheme,
	const struct berval *passwd,
	const struct berval *cred,
	const char **text)
{
	unsigned char digest[LUTIL_MD5_BYTES];
	unsigned char *orig_pass;
	int rc, n;
	struct berval salt;

	/* safety check */
	n = LUTIL_BASE64_DECODE_LEN(passwd->bv_len);
	if (n <= sizeof(digest))
		return LUTIL_PASSWD_ERR;

	/* base64 un-encode password hash */
	orig_pass = (unsigned char *) ber_memalloc((size_t) (n + 1));

	if (orig_pass == NULL)
		return LUTIL_PASSWD_ERR;

	rc = lutil_b64_pton(passwd->bv_val, orig_pass, passwd->bv_len);

	if (rc <= (int) sizeof(digest)) {
		ber_memfree(orig_pass);
		return LUTIL_PASSWD_ERR;
	}

	salt.bv_val = (char *) &orig_pass[sizeof(digest)];
	salt.bv_len = rc - sizeof(digest);

	/* the only difference between this and straight PHK is the magic */
	do_apr_hash(cred, &salt, digest);

	if (text)
		*text = NULL;

	/* compare */
	rc = memcmp((char *) orig_pass, (char *) digest, sizeof(digest));
	ber_memfree(orig_pass);
	return rc ?  LUTIL_PASSWD_ERR : LUTIL_PASSWD_OK;
}

static int hash_apr1(
	const struct berval *scheme,
	const struct berval *passwd,
	struct berval *hash,
	const char **text)
{
	unsigned char digest_buf[LUTIL_MD5_BYTES];
	char salt_buf[APR_SALT_SIZE];
	struct berval digest;
	struct berval salt;
	int n;

	digest.bv_val = (char *) digest_buf;
	digest.bv_len = sizeof(digest_buf);
	salt.bv_val = salt_buf;
	salt.bv_len = APR_SALT_SIZE;

	/* generate random salt */
	if (lutil_entropy( (unsigned char *) salt.bv_val, salt.bv_len) < 0)
		return LUTIL_PASSWD_ERR; 
	/* limit it to characters in the 64-char set */
	for (n = 0; n < salt.bv_len; n++)
		salt.bv_val[n] = apr64[salt.bv_val[n] % (sizeof(apr64) - 1)];

	/* the only difference between this and straight PHK is the magic */
	do_apr_hash(passwd, &salt, digest_buf);

	if (text)
		*text = NULL;

	return lutil_passwd_string64(scheme, &digest, hash, &salt);
}

int init_module(int argc, char *argv[]) {
	return lutil_passwd_add((struct berval *) &scheme, chk_apr1, hash_apr1);
}