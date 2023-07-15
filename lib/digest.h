/**
 * \file lib/digest.h
 *
 * \brief Header for the fwknop digest.c.
 */

/*  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *****************************************************************************
*/
#ifndef DIGEST_H
#define DIGEST_H 1

#include "md5.h"
#include "sha1.h"
#include "sha2.h"
#include "sha3.h"

/* Size calculation macros
*/
#define MD_HEX_SIZE(x) x * 2

void md5(unsigned char* out, unsigned char* in, size_t size);
void md5_base64(char* out, unsigned char* in, size_t size);
void sha1(unsigned char* out, unsigned char* in, size_t size);
void sha1_base64(char* out, unsigned char* in, size_t size);
void sha256(unsigned char* out, unsigned char* in, size_t size);
void sha256_base64(char* out, unsigned char* in, size_t size);
void sha384(unsigned char* out, unsigned char* in, size_t size);
void sha384_base64(char* out, unsigned char* in, size_t size);
void sha512(unsigned char* out, unsigned char* in, size_t size);
void sha512_base64(char* out, unsigned char* in, size_t size);
void sha3_256(unsigned char* out, unsigned char* in, size_t size);
void sha3_256_base64(char* out, unsigned char* in, size_t size);
void sha3_512(unsigned char* out, unsigned char* in, size_t size);
void sha3_512_base64(char* out, unsigned char* in, size_t size);

#endif /* DIGEST_H */

/***EOF***/
