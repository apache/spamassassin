/* <@LICENSE>
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at:
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * </@LICENSE>
 */

#ifndef UTILS_H
#define UTILS_H

#define UNUSED_VARIABLE(v)	((void)(v))

#include <stddef.h>

extern int libspamc_timeout;	/* default timeout in seconds */
extern int libspamc_connect_timeout;	/* Sep 8, 2008 mrgus: default connect timeout in seconds */

#ifdef SPAMC_SSL
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#else
typedef int SSL;		/* fake type to avoid conditional compilation */
typedef int SSL_CTX;
typedef int SSL_METHOD;
#endif

#ifdef _WIN32
#include <winsock.h>
/*
 * BSD-compatible socket error codes for Win32
 */
#undef  EWOULDBLOCK      /* override definition in errno.h */
#define EWOULDBLOCK             WSAEWOULDBLOCK
#undef  EINPROGRESS      /* override definition in errno.h */
#define EINPROGRESS             WSAEINPROGRESS
#undef  EALREADY         /* override definition in errno.h */
#define EALREADY                WSAEALREADY
#undef  ENOTSOCK         /* override definition in errno.h */
#define ENOTSOCK                WSAENOTSOCK
#undef  EDESTADDRREQ     /* override definition in errno.h */
#define EDESTADDRREQ            WSAEDESTADDRREQ
#undef  EMSGSIZE         /* override definition in errno.h */
#define EMSGSIZE                WSAEMSGSIZE
#undef  EPROTOTYPE       /* override definition in errno.h */
#define EPROTOTYPE              WSAEPROTOTYPE
#undef  ENOPROTOOPT      /* override definition in errno.h */
#define ENOPROTOOPT             WSAENOPROTOOPT
#undef  EPROTONOSUPPORT  /* override definition in errno.h */
#define EPROTONOSUPPORT         WSAEPROTONOSUPPORT
#undef  ESOCKTNOSUPPORT  /* override definition in errno.h */
#define ESOCKTNOSUPPORT         WSAESOCKTNOSUPPORT
#undef  EOPNOTSUPP       /* override definition in errno.h */
#define EOPNOTSUPP              WSAEOPNOTSUPP
#undef  EPFNOSUPPORT     /* override definition in errno.h */
#define EPFNOSUPPORT            WSAEPFNOSUPPORT
#undef  EAFNOSUPPORT     /* override definition in errno.h */
#define EAFNOSUPPORT            WSAEAFNOSUPPORT
#undef  EADDRINUSE       /* override definition in errno.h */
#define EADDRINUSE              WSAEADDRINUSE
#undef  EADDRNOTAVAIL    /* override definition in errno.h */
#define EADDRNOTAVAIL           WSAEADDRNOTAVAIL
#undef  ENETDOWN         /* override definition in errno.h */
#define ENETDOWN                WSAENETDOWN
#undef  ENETUNREACH      /* override definition in errno.h */
#define ENETUNREACH             WSAENETUNREACH
#undef  ENETRESET        /* override definition in errno.h */
#define ENETRESET               WSAENETRESET
#undef  ECONNABORTED     /* override definition in errno.h */
#define ECONNABORTED            WSAECONNABORTED
#undef  ECONNRESET       /* override definition in errno.h */
#define ECONNRESET              WSAECONNRESET
#undef  ENOBUFS          /* override definition in errno.h */
#define ENOBUFS                 WSAENOBUFS
#undef  EISCONN          /* override definition in errno.h */
#define EISCONN                 WSAEISCONN
#undef  ENOTCONN         /* override definition in errno.h */
#define ENOTCONN                WSAENOTCONN
#undef  ESHUTDOWN        /* override definition in errno.h */
#define ESHUTDOWN               WSAESHUTDOWN
#undef  ETOOMANYREFS     /* override definition in errno.h */
#define ETOOMANYREFS            WSAETOOMANYREFS
#undef  ETIMEDOUT        /* override definition in errno.h */
#define ETIMEDOUT               WSAETIMEDOUT
#undef  ECONNREFUSED     /* override definition in errno.h */
#define ECONNREFUSED            WSAECONNREFUSED
#undef  ELOOP            /* override definition in errno.h */
#define ELOOP                   WSAELOOP
/* #define ENAMETOOLONG            WSAENAMETOOLONG */
#define EHOSTDOWN               WSAEHOSTDOWN
#undef  EHOSTUNREACH     /* override definition in errno.h */
#define EHOSTUNREACH            WSAEHOSTUNREACH
/* #define ENOTEMPTY               WSAENOTEMPTY */
#define EPROCLIM                WSAEPROCLIM
#define EUSERS                  WSAEUSERS
#define EDQUOT                  WSAEDQUOT
#define ESTALE                  WSAESTALE
#define EREMOTE                 WSAEREMOTE

/* NOTE: these are not errno constants in UNIX! */
#define HOST_NOT_FOUND          WSAHOST_NOT_FOUND
#define TRY_AGAIN               WSATRY_AGAIN
#define NO_RECOVERY             WSANO_RECOVERY
#define NO_DATA                 WSANO_DATA

#endif

int fd_timeout_read(int fd, char fdflag, void *, size_t);
int ssl_timeout_read(SSL * ssl, void *, int);

/* uses size_t instead of socket_t because socket_t not defined on some platforms */
int timeout_connect (int sockfd, const struct sockaddr *serv_addr, size_t addrlen);

/* these are fd-only, no SSL support */
int full_read(int fd, char fdflag, void *buf, int min, int len);
int full_read_ssl(SSL * ssl, unsigned char *buf, int min, int len);
int full_write(int fd, char fdflag, const void *buf, int len);

#endif
