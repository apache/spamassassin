/*
 * <@LICENSE>
 * ====================================================================
 * The Apache Software License, Version 1.1
 * 
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
 * reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 * 
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 * 
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 * 
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 * 
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 * </@LICENSE>
 */

#ifndef UTILS_H
#define UTILS_H

#define UNUSED_VARIABLE(v)	((void)(v))

extern int libspamc_timeout;  /* default timeout in seconds */

#ifdef SPAMC_SSL
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#else
typedef int	SSL;	/* fake type to avoid conditional compilation */
typedef int	SSL_CTX;
typedef int	SSL_METHOD;
#endif
#ifdef _WIN32
#include <winsock.h>
typedef int ssize_t;
//
// BSD-compatible socket error codes for Win32
//

#define EWOULDBLOCK             WSAEWOULDBLOCK 
#define EINPROGRESS             WSAEINPROGRESS 
#define EALREADY                WSAEALREADY 
#define ENOTSOCK                WSAENOTSOCK 
#define EDESTADDRREQ            WSAEDESTADDRREQ 
#define EMSGSIZE                WSAEMSGSIZE 
#define EPROTOTYPE              WSAEPROTOTYPE 
#define ENOPROTOOPT             WSAENOPROTOOPT 
#define EPROTONOSUPPORT         WSAEPROTONOSUPPORT 
#define ESOCKTNOSUPPORT         WSAESOCKTNOSUPPORT 
#define EOPNOTSUPP              WSAEOPNOTSUPP 
#define EPFNOSUPPORT            WSAEPFNOSUPPORT 
#define EAFNOSUPPORT            WSAEAFNOSUPPORT 
#define EADDRINUSE              WSAEADDRINUSE 
#define EADDRNOTAVAIL           WSAEADDRNOTAVAIL 
#define ENETDOWN                WSAENETDOWN 
#define ENETUNREACH             WSAENETUNREACH 
#define ENETRESET               WSAENETRESET 
#define ECONNABORTED            WSAECONNABORTED 
#define ECONNRESET              WSAECONNRESET 
#define ENOBUFS                 WSAENOBUFS 
#define EISCONN                 WSAEISCONN 
#define ENOTCONN                WSAENOTCONN 
#define ESHUTDOWN               WSAESHUTDOWN 
#define ETOOMANYREFS            WSAETOOMANYREFS 
#define ETIMEDOUT               WSAETIMEDOUT 
#define ECONNREFUSED            WSAECONNREFUSED 
#define ELOOP                   WSAELOOP 
// #define ENAMETOOLONG            WSAENAMETOOLONG
#define EHOSTDOWN               WSAEHOSTDOWN 
#define EHOSTUNREACH            WSAEHOSTUNREACH 
// #define ENOTEMPTY               WSAENOTEMPTY
#define EPROCLIM                WSAEPROCLIM 
#define EUSERS                  WSAEUSERS 
#define EDQUOT                  WSAEDQUOT 
#define ESTALE                  WSAESTALE 
#define EREMOTE                 WSAEREMOTE 

// NOTE: these are not errno constants in UNIX!
#define HOST_NOT_FOUND          WSAHOST_NOT_FOUND 
#define TRY_AGAIN               WSATRY_AGAIN 
#define NO_RECOVERY             WSANO_RECOVERY 
#define NO_DATA                 WSANO_DATA 

#endif

ssize_t fd_timeout_read (int fd, char fdflag, void *, size_t );  
int ssl_timeout_read (SSL *ssl, void *, int );  

/* these are fd-only, no SSL support */
int full_read(int fd, char fdflag, void *buf, int min, int len);
int full_read_ssl(SSL *ssl, unsigned char *buf, int min, int len);
int full_write(int fd, char fdflag, const void *buf, int len);

#endif
