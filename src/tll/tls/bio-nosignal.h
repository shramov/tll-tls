// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Pavel Shramov <shramov@mexmat.net>

#ifndef _TLL_TLS_BIO_NOSIGNAL_H
#define _TLL_TLS_BIO_NOSIGNAL_H

#include <openssl/bio.h>

#ifdef __cplusplus
extern "C" {
#endif

BIO_METHOD * tll_tls_bio_nosignal();

#ifdef __cplusplus
} // extern "C"
#endif

#endif//_TLL_TLS_BIO_NOSIGNAL_H
