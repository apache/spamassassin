/*
 * @LICENSE
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
