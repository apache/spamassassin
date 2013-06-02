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

/* 
  Compile with extra warnings -- gcc only, not suitable for use as default:

  gcc -Wextra -Wdeclaration-after-statement -Wall -g -O2 spamc/spamc.c \
  spamc/getopt.c spamc/libspamc.c spamc/utils.c -o spamc/spamc -ldl -lz
 */

#include "config.h"
#include "libspamc.h"

#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#define strcasecmp stricmp
#define sleep Sleep
#include <io.h>
#else
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#define closesocket(x) close(x)
#endif

#ifdef HAVE_SYSEXITS_H
#include <sysexits.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_SYS_ERRNO_H
#include <sys/errno.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

/* must load *after* errno.h, Bug 6697 */
#include "utils.h"

/* RedHat 5.2 doesn't define Shutdown 2nd Parameter Constants */
/* KAM 12-4-01 */
/* SJF 2003/04/25 - now test for macros directly */
#ifndef SHUT_RD
#  define SHUT_RD 0		/* no more receptions */
#endif
#ifndef SHUT_WR
#  define SHUT_WR 1		/* no more transmissions */
#endif
#ifndef SHUT_RDWR
#  define SHUT_RDWR 2		/* no more receptions or transmissions */
#endif

#ifndef HAVE_H_ERRNO
#define h_errno errno
#endif

#ifdef _WIN32
#define spamc_get_errno()   WSAGetLastError()
#else
#define spamc_get_errno()   errno
#endif

#ifndef HAVE_OPTARG
extern char *optarg;
#endif

#ifndef HAVE_INADDR_NONE
#define INADDR_NONE             ((in_addr_t) 0xffffffff)
#endif

/* jm: turned off for now, it should not be necessary. */
#undef USE_TCP_NODELAY

#ifndef HAVE_EX__MAX
/* jm: very conservative figure, should be well out of range on almost all NIXes */
#define EX__MAX 200
#endif

#undef DO_CONNECT_DEBUG_SYSLOGS
/*
#define DO_CONNECT_DEBUG_SYSLOGS 1
#define CONNECT_DEBUG_LEVEL LOG_DEBUG
*/

/* bug 4477 comment 14 */
#ifdef NI_MAXHOST
#define SPAMC_MAXHOST NI_MAXHOST
#else
#define SPAMC_MAXHOST 256
#endif

#ifdef NI_MAXSERV
#define SPAMC_MAXSERV NI_MAXSERV
#else
#define SPAMC_MAXSERV 256
#endif

/* static const int ESC_PASSTHROUGHRAW = EX__MAX + 666;  No longer seems to be used */

/* set EXPANSION_ALLOWANCE to something more than might be
   added to a message in X-headers and the report template */
static const int EXPANSION_ALLOWANCE = 16384;

/* set NUM_CHECK_BYTES to number of bytes that have to match at beginning and end
   of the data streams before and after processing by spamd 
   Aug  7 2002 jm: no longer seems to be used
   static const int NUM_CHECK_BYTES = 32;
 */

/* Set the protocol version that this spamc speaks */
static const char *PROTOCOL_VERSION = "SPAMC/1.5";

/* "private" part of struct message.
 * we use this instead of the struct message directly, so that we
 * can add new members without affecting the ABI.
 */
struct libspamc_private_message
{
    int flags;			/* copied from "flags" arg to message_read() */
    int alloced_size;           /* allocated space for the "out" buffer */

    void (*spamc_header_callback)(struct message *m, int flags, char *buf, int len);
    void (*spamd_header_callback)(struct message *m, int flags, const char *buf, int len);
};

void (*libspamc_log_callback)(int flags, int level, char *msg, va_list args) = NULL;

int libspamc_timeout = 0;
int libspamc_connect_timeout = 0;	/* Sep 8, 2008 mrgus: separate connect timeout */

/*
 * translate_connect_errno()
 *
 *	Given a UNIX error number obtained (probably) from "connect(2)",
 *	translate this to a failure code. This module is shared by both
 *	transport modules - UNIX and TCP.
 *
 *	This should ONLY be called when there is an error.
 */
static int _translate_connect_errno(int err)
{
    switch (err) {
    case EBADF:
    case EFAULT:
    case ENOTSOCK:
    case EISCONN:
    case EADDRINUSE:
    case EINPROGRESS:
    case EALREADY:
    case EAFNOSUPPORT:
	return EX_SOFTWARE;

    case ECONNREFUSED:
    case ETIMEDOUT:
    case ENETUNREACH:
	return EX_UNAVAILABLE;

    case EACCES:
	return EX_NOPERM;

    default:
	return EX_SOFTWARE;
    }
}

/*
 * opensocket()
 *
 *	Given a socket family (PF_INET or PF_INET6 or PF_UNIX), try to
 *	create this socket and store the FD in the pointed-to place.
 *	If it's successful, do any other setup required to make the socket
 *	ready to use, such as setting TCP_NODELAY mode, and in any case
 *      we return EX_OK if all is well.
 *
 *	Upon failure we return one of the other EX_??? error codes.
 */
#ifdef SPAMC_HAS_ADDRINFO
static int _opensocket(int flags, struct addrinfo *res, int *psock)
{
#else
static int _opensocket(int flags, int type, int *psock)
{
    int proto = 0;
#endif
    const char *typename;
    int origerr;
#ifdef _WIN32
    int socktout;
#endif

    assert(psock != 0);

	/*----------------------------------------------------------------
	 * Create a few induction variables that are implied by the socket
	 * type given by the user. The typename is strictly used for debug
	 * reporting.
	 */
#ifdef SPAMC_HAS_ADDRINFO
    switch(res->ai_family) {
       case PF_UNIX:
          typename = "PF_UNIX";
          break;
       case PF_INET:
          typename = "PF_INET";
          break;
       case PF_INET6:
          typename = "PF_INET6";
          break;
       default:
          typename = "Unknown";
          break;
    }
#else
    if (type == PF_UNIX) {
	typename = "PF_UNIX";
    }
    else {
	typename = "PF_INET";
	proto = IPPROTO_TCP;
    }
#endif

#ifdef DO_CONNECT_DEBUG_SYSLOGS
    libspamc_log(flags, CONNECT_DEBUG_LEVEL, "dbg: create socket(%s)", typename);
#endif

#ifdef SPAMC_HAS_ADDRINFO
    if ((*psock = socket(res->ai_family, res->ai_socktype, res->ai_protocol))
#else
    if ((*psock = socket(type, SOCK_STREAM, proto))
#endif
#ifndef _WIN32
	< 0
#else
	== INVALID_SOCKET
#endif
	) {

		/*--------------------------------------------------------
		 * At this point we had a failure creating the socket, and
		 * this is pretty much fatal. Translate the error reason
		 * into something the user can understand.
		 */
	origerr = spamc_get_errno();
#ifndef _WIN32
	libspamc_log(flags, LOG_ERR, "socket(%s) to spamd failed: %s", typename, strerror(origerr));
#else
	libspamc_log(flags, LOG_ERR, "socket(%s) to spamd failed: %d", typename, origerr);
#endif

	switch (origerr) {
	case EPROTONOSUPPORT:
	case EINVAL:
	    return EX_SOFTWARE;

	case EACCES:
	    return EX_NOPERM;

	case ENFILE:
	case EMFILE:
	case ENOBUFS:
	case ENOMEM:
	    return EX_OSERR;

	default:
	    return EX_SOFTWARE;
	}
    }

#ifdef _WIN32
    /* bug 4344: makes timeout functional on Win32 */
    socktout = libspamc_timeout * 1000;
    if (type == PF_INET
        && setsockopt(*psock, SOL_SOCKET, SO_RCVTIMEO, (char *)&socktout, sizeof(socktout)) != 0)
    {

        origerr = spamc_get_errno();
        switch (origerr)
        {
        case EBADF:
        case ENOTSOCK:
        case ENOPROTOOPT:
        case EFAULT:
            libspamc_log(flags, LOG_ERR, "setsockopt(SO_RCVTIMEO) failed: %d", origerr);
            closesocket(*psock);
            return EX_SOFTWARE;

        default:
            break;		/* ignored */
        }
    }
#endif

	/*----------------------------------------------------------------
	 * Do a bit of setup on the TCP socket if required. Notes above
	 * suggest this is probably not set
	 */
#ifdef USE_TCP_NODELAY
    {
	int one = 1;

	if ( (   type == PF_INET
#ifdef PF_INET6
              || type == PF_INET6
#endif
             ) && setsockopt(*psock, 0, TCP_NODELAY, &one, sizeof one) != 0) {
	    origerr = spamc_get_errno();
	    switch (origerr) {
	    case EBADF:
	    case ENOTSOCK:
	    case ENOPROTOOPT:
	    case EFAULT:
		libspamc_log(flags, LOG_ERR,
#ifndef _WIN32
		       "setsockopt(TCP_NODELAY) failed: %s", strerror(origerr));
#else
		       "setsockopt(TCP_NODELAY) failed: %d", origerr);
#endif
		closesocket(*psock);
		return EX_SOFTWARE;

	    default:
		break;		/* ignored */
	    }
	}
    }
#endif /* USE_TCP_NODELAY */

    return EX_OK;		/* all is well */
}

/*
 * try_to_connect_unix()
 *
 *	Given a transport handle that implies using a UNIX domain
 *	socket, try to make a connection to it and store the resulting
 *	file descriptor in *sockptr. Return is EX_OK if we did it,
 *	and some other error code otherwise.
 */
static int _try_to_connect_unix(struct transport *tp, int *sockptr)
{
#ifndef _WIN32
    int mysock, status, origerr;
    struct sockaddr_un addrbuf;
#ifdef SPAMC_HAS_ADDRINFO
    struct addrinfo hints, *res;
#else
    int res = PF_UNIX;
#endif
    int ret;

    assert(tp != 0);
    assert(sockptr != 0);
    assert(tp->socketpath != 0);

#ifdef SPAMC_HAS_ADDRINFO
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNIX;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    res = &hints;
#endif
	/*----------------------------------------------------------------
	 * If the socket itself can't be created, this is a fatal error.
	 */
    if ((ret = _opensocket(tp->flags, res, &mysock)) != EX_OK)
	return ret;

    /* set up the UNIX domain socket */
    memset(&addrbuf, 0, sizeof addrbuf);
    addrbuf.sun_family = AF_UNIX;
    strncpy(addrbuf.sun_path, tp->socketpath, sizeof addrbuf.sun_path - 1);
    addrbuf.sun_path[sizeof addrbuf.sun_path - 1] = '\0';

#ifdef DO_CONNECT_DEBUG_SYSLOGS
    libspamc_log(tp->flags, CONNECT_DEBUG_LEVEL, "dbg: connect(AF_UNIX) to spamd at %s",
	   addrbuf.sun_path);
#endif

    status = timeout_connect(mysock, (struct sockaddr *) &addrbuf, sizeof(addrbuf));

    origerr = errno;

    if (status >= 0) {
#ifdef DO_CONNECT_DEBUG_SYSLOGS
	libspamc_log(tp->flags, CONNECT_DEBUG_LEVEL, "dbg: connect(AF_UNIX) ok");
#endif

	*sockptr = mysock;

	return EX_OK;
    }

    libspamc_log(tp->flags, LOG_ERR, "connect(AF_UNIX) to spamd using --socket='%s' failed: %s",
	   addrbuf.sun_path, strerror(origerr));
    closesocket(mysock);

    return _translate_connect_errno(origerr);
#else
    (void) tp; /* not used. suppress compiler warning */
    (void) sockptr; /* not used. suppress compiler warning */
    return EX_OSERR;
#endif
}

/*
 * try_to_connect_tcp()
 *
 *	Given a transport that implies a TCP connection, either to
 *	localhost or a list of IP addresses, attempt to connect. The
 *	list of IP addresses has already been randomized (if requested)
 *	and limited to just one if fallback has been enabled.
 */
static int _try_to_connect_tcp(const struct transport *tp, int *sockptr)
{
    int numloops;
    int origerr = 0;
    int ret;
#ifdef SPAMC_HAS_ADDRINFO
    struct addrinfo *res = NULL;
    char port[SPAMC_MAXSERV-1]; /* port, for logging */
#else
    int res = PF_INET;
#endif
    char host[SPAMC_MAXHOST-1]; /* hostname, for logging */
    int connect_retries, retry_sleep;

    assert(tp != 0);
    assert(sockptr != 0);
    assert(tp->nhosts > 0);

    /* default values */
    retry_sleep = tp->retry_sleep;
    connect_retries = tp->connect_retries;
    if (connect_retries == 0) {
      connect_retries = 3;
    }
    if (retry_sleep < 0) {
      retry_sleep = 1;
    }

    for (numloops = 0; numloops < connect_retries; numloops++) {
        const int hostix = numloops % tp->nhosts;
        int status, mysock;
        int innocent = 0;

                /*--------------------------------------------------------
                * We always start by creating the socket, as we get only
                * one attempt to connect() on each one. If this fails,
                * we're done.
                */

#ifdef SPAMC_HAS_ADDRINFO
        res = tp->hosts[hostix];
        while(res) {
            char *family = NULL;
            switch(res->ai_family) {
            case AF_INET:
                family = "AF_INET";
                break;
            case AF_INET6:
                family = "AF_INET6";
                break;
            default:
                family = "Unknown";
                break;
            }

            if ((ret = _opensocket(tp->flags, res, &mysock)) != EX_OK) {
                res = res->ai_next;
                continue;
            }

            getnameinfo(res->ai_addr, res->ai_addrlen,
                  host, sizeof(host),
                  port, sizeof(port),
                  NI_NUMERICHOST|NI_NUMERICSERV);

#ifdef DO_CONNECT_DEBUG_SYSLOGS
            libspamc_log(tp->flags, CONNECT_DEBUG_LEVEL,
              "dbg: connect(%s) to spamd (host %s, port %s) (try #%d of %d)",
                      family, host, port, numloops + 1, connect_retries);
#endif

            /* this is special-cased so that we have an address we can
             * safely use as an "always fail" test case */
            if (!strcmp(host, "255.255.255.255")) {
              libspamc_log(tp->flags, LOG_ERR,
                          "connect to spamd on %s failed, broadcast addr",
                          host);
              status = -1;
            }
            else {
              status = timeout_connect(mysock, res->ai_addr, res->ai_addrlen);
              if (status != 0) origerr = spamc_get_errno();
            }

#else
	    struct sockaddr_in addrbuf;
	    const char *ipaddr;
	    const char* family="AF_INET";
	    if ((ret = _opensocket(tp->flags, PF_INET, &mysock)) != EX_OK)
	      return ret;
	    
	    memset(&addrbuf, 0, sizeof(addrbuf));
	    
	    addrbuf.sin_family = AF_INET;
	    addrbuf.sin_port = htons(tp->port);
	    addrbuf.sin_addr = tp->hosts[hostix];
	    
	    ipaddr = inet_ntoa(addrbuf.sin_addr);

            /* make a copy in host, for logging (bug 5577) */
            strncpy (host, ipaddr, sizeof(host) - 1);

#ifdef DO_CONNECT_DEBUG_SYSLOGS
	    libspamc_log(tp->flags, LOG_DEBUG,
			 "dbg: connect(AF_INET) to spamd at %s (try #%d of %d)",
			 ipaddr, numloops + 1, connect_retries);
#endif

            /* this is special-cased so that we have an address we can
             * safely use as an "always fail" test case */
            if (!strcmp(ipaddr, "255.255.255.255")) {
              libspamc_log(tp->flags, LOG_ERR,
                          "connect to spamd on %s failed, broadcast addr",
                          ipaddr);
              status = -1;
            }
            else {
              status = timeout_connect(mysock, (struct sockaddr *) &addrbuf,
                        sizeof(addrbuf));
              if (status != 0) origerr = spamc_get_errno();
            }

#endif

            if (status != 0) {
                  closesocket(mysock);

                  innocent = origerr == ECONNREFUSED && numloops+1 < tp->nhosts;
                  libspamc_log(tp->flags, innocent ? LOG_DEBUG : LOG_ERR,
                      "connect to spamd on %s failed, retrying (#%d of %d): %s",
                      host, numloops+1, connect_retries,
#ifdef _WIN32
                      origerr
#else
                      strerror(origerr)
#endif
                  );

            } else {
#ifdef DO_CONNECT_DEBUG_SYSLOGS
                  libspamc_log(tp->flags, CONNECT_DEBUG_LEVEL,
                          "dbg: connect(%s) to spamd done",family);
#endif
                  *sockptr = mysock;

                  return EX_OK;
            }
#ifdef SPAMC_HAS_ADDRINFO
            res = res->ai_next;
        }
#endif
        if (numloops+1 < connect_retries && !innocent) sleep(retry_sleep);
    } /* for(numloops...) */

    libspamc_log(tp->flags, LOG_ERR,
              "connection attempt to spamd aborted after %d retries",
              connect_retries);

    return _translate_connect_errno(origerr);
}

/* Aug 14, 2002 bj: Reworked things. Now we have message_read, message_write,
 * message_dump, lookup_host, message_filter, and message_process, and a bunch
 * of helper functions.
 */

static void _clear_message(struct message *m)
{
    m->type = MESSAGE_NONE;
    m->raw = NULL;
    m->raw_len = 0;
    m->pre = NULL;
    m->pre_len = 0;
    m->msg = NULL;
    m->msg_len = 0;
    m->post = NULL;
    m->post_len = 0;
    m->is_spam = EX_TOOBIG;
    m->score = 0.0;
    m->threshold = 0.0;
    m->outbuf = NULL;
    m->out = NULL;
    m->out_len = 0;
    m->content_length = -1;
}

static void _free_zlib_buffer(unsigned char **zlib_buf, int *zlib_bufsiz)
{
	if(*zlib_buf) {
	free(*zlib_buf);
	*zlib_buf=NULL;
	}
	*zlib_bufsiz=0;
}

static void _use_msg_for_out(struct message *m)
{
    if (m->outbuf)
	free(m->outbuf);
    m->outbuf = NULL;
    m->out = m->msg;
    m->out_len = m->msg_len;
}

static int _message_read_raw(int fd, struct message *m)
{
    _clear_message(m);
    if ((m->raw = malloc(m->max_len + 1)) == NULL)
	return EX_OSERR;
    m->raw_len = full_read(fd, 1, m->raw, m->max_len + 1, m->max_len + 1);
    if (m->raw_len <= 0) {
	free(m->raw);
	m->raw = NULL;
	m->raw_len = 0;
	return EX_IOERR;
    }
    m->type = MESSAGE_ERROR;
    if (m->raw_len > (int) m->max_len)
    {
        libspamc_log(m->priv->flags, LOG_NOTICE,
                "skipped message, greater than max message size (%d bytes)",
                m->max_len);
	return EX_TOOBIG;
    }
    m->type = MESSAGE_RAW;
    m->msg = m->raw;
    m->msg_len = m->raw_len;
    m->out = m->msg;
    m->out_len = m->msg_len;
    return EX_OK;
}

static int _message_read_bsmtp(int fd, struct message *m)
{
    unsigned int i, j, p_len;
    char prev;
    char* p;

    _clear_message(m);
    if ((m->raw = malloc(m->max_len + 1)) == NULL)
	return EX_OSERR;

    /* Find the DATA line */
    m->raw_len = full_read(fd, 1, m->raw, m->max_len + 1, m->max_len + 1);
    if (m->raw_len <= 0) {
	free(m->raw);
	m->raw = NULL;
	m->raw_len = 0;
	return EX_IOERR;
    }
    m->type = MESSAGE_ERROR;
    if (m->raw_len > (int) m->max_len)
	return EX_TOOBIG;
    p = m->pre = m->raw;
    /* Search for \nDATA\n which marks start of actual message */
    while ((p_len = (m->raw_len - (p - m->raw))) > 8) { /* leave room for at least \nDATA\n.\n */
      char* q = memchr(p, '\n', p_len - 8);  /* find next \n then see if start of \nDATA\n */
      if (q == NULL) break;
      q++;
      if (((q[0]|0x20) == 'd') && /* case-insensitive ASCII comparison */
	  ((q[1]|0x20) == 'a') &&
	  ((q[2]|0x20) == 't') &&
	  ((q[3]|0x20) == 'a')) {
	q+=4;
	if (q[0] == '\r') ++q;
	if (*(q++) == '\n') {  /* leave q at start of message if we found it */
	  m->msg = q;
	  m->pre_len = q - m->raw;
	  m->msg_len = m->raw_len - m->pre_len;
	  break;
	}
      }
      p = q; /* the above code ensures no other '\n' comes before q */
    }
    if (m->msg == NULL)
	return EX_DATAERR;

    /* ensure this is >= 0 */
    if (m->msg_len < 0) {
	return EX_SOFTWARE;
    }

    /* Find the end-of-DATA line */
    prev = '\n';
    for (i = j = 0; i < (unsigned int) m->msg_len; i++) {
	if (prev == '\n' && m->msg[i] == '.') {
	    /* Dot at the beginning of a line */
            if (((int) (i+1) == m->msg_len)
                || ((int) (i+1) < m->msg_len && m->msg[i + 1] == '\n')
                || ((int) (i+2) < m->msg_len && m->msg[i + 1] == '\r' && m->msg[i + 2] == '\n')) {
		/* Lone dot! That's all, folks */
		m->post = m->msg + i;
		m->post_len = m->msg_len - i;
		m->msg_len = j;
		break;
	    }
	    else if ((int) (i+1) < m->msg_len && m->msg[i + 1] == '.') {
		/* Escaping dot, eliminate. */
		prev = '.';
		continue;
	    }			/* Else an ordinary dot, drop down to ordinary char handler */
	}
	prev = m->msg[i];
	m->msg[j++] = m->msg[i];
    }

    /* if bad format with no end "\n.\n", error out */
    if (m->post == NULL)
	return EX_DATAERR;
    m->type = MESSAGE_BSMTP;
    m->out = m->msg;
    m->out_len = m->msg_len;
    return EX_OK;
}

int message_read(int fd, int flags, struct message *m)
{
    assert(m != NULL);

    libspamc_timeout = 0;

    /* create the "private" part of the struct message */
    m->priv = malloc(sizeof(struct libspamc_private_message));
    if (m->priv == NULL) {
	libspamc_log(flags, LOG_ERR, "message_read: malloc failed");
	return EX_OSERR;
    }
    m->priv->flags = flags;
    m->priv->alloced_size = 0;
    m->priv->spamc_header_callback = 0;
    m->priv->spamd_header_callback = 0;

    if (flags & SPAMC_PING) {
      _clear_message(m);
      return EX_OK;
    }

    switch (flags & SPAMC_MODE_MASK) {
    case SPAMC_RAW_MODE:
	return _message_read_raw(fd, m);

    case SPAMC_BSMTP_MODE:
	return _message_read_bsmtp(fd, m);

    default:
	libspamc_log(flags, LOG_ERR, "message_read: Unknown mode %d",
		flags & SPAMC_MODE_MASK);
	return EX_USAGE;
    }
}

long message_write(int fd, struct message *m)
{
    long total = 0;
    off_t i, j;
    off_t jlimit;
    char buffer[1024];

    assert(m != NULL);

    if (m->priv->flags & (SPAMC_CHECK_ONLY|SPAMC_PING)) {
	if (m->is_spam == EX_ISSPAM || m->is_spam == EX_NOTSPAM) {
	    return full_write(fd, 1, m->out, m->out_len);

	}
	else {
	    libspamc_log(m->priv->flags, LOG_ERR, "oops! SPAMC_CHECK_ONLY is_spam: %d",
                        m->is_spam);
	    return -1;
	}
    }

    /* else we're not in CHECK_ONLY mode */
    switch (m->type) {
    case MESSAGE_NONE:
	libspamc_log(m->priv->flags, LOG_ERR, "Cannot write this message, it's MESSAGE_NONE!");
	return -1;

    case MESSAGE_ERROR:
	return full_write(fd, 1, m->raw, m->raw_len);

    case MESSAGE_RAW:
	return full_write(fd, 1, m->out, m->out_len);

    case MESSAGE_BSMTP:
	total = full_write(fd, 1, m->pre, m->pre_len);
	for (i = 0; i < m->out_len;) {
	    jlimit = (off_t) (sizeof(buffer) / sizeof(*buffer) - 4);
	    for (j = 0; i < (off_t) m->out_len && j < jlimit;) {
		if (i + 1 < m->out_len && m->out[i] == '\n'
		    && m->out[i + 1] == '.') {
		    if (j > jlimit - 4) {
			break;	/* avoid overflow */
		    }
		    buffer[j++] = m->out[i++];
		    buffer[j++] = m->out[i++];
		    buffer[j++] = '.';
		}
		else {
		    buffer[j++] = m->out[i++];
		}
	    }
	    total += full_write(fd, 1, buffer, j);
	}
	return total + full_write(fd, 1, m->post, m->post_len);

    default:
	libspamc_log(m->priv->flags, LOG_ERR, "Unknown message type %d", m->type);
	return -1;
    }
}

void message_dump(int in_fd, int out_fd, struct message *m, int flags)
{
    char buf[8196];
    int bytes;

    if (m == NULL) {
	libspamc_log(flags, LOG_ERR, "oops! message_dump called with NULL message");
	return;
    }

    if (m->type != MESSAGE_NONE) {
	message_write(out_fd, m);
    }

    while ((bytes = full_read(in_fd, 1, buf, 8192, 8192)) > 0) {
	if (bytes != full_write(out_fd, 1, buf, bytes)) {
	    libspamc_log(flags, LOG_ERR, "oops! message_dump of %d returned different",
		   bytes);
	}
    }
}

static int
_spamc_read_full_line(struct message *m, int flags, SSL * ssl, int sock,
		      char *buf, size_t *lenp, size_t bufsiz)
{
    int failureval;
    int bytesread = 0;
    size_t len;

    UNUSED_VARIABLE(m);

    *lenp = 0;
    /* Now, read from spamd */
    for (len = 0; len < bufsiz - 1; len++) {
	if (flags & SPAMC_USE_SSL) {
	    bytesread = ssl_timeout_read(ssl, buf + len, 1);
	}
	else {
	    bytesread = fd_timeout_read(sock, 0, buf + len, 1);
	}

	if (bytesread <= 0) {
	    failureval = EX_IOERR;
	    goto failure;
	}

	if (buf[len] == '\n') {
	    buf[len] = '\0';
	    if (len > 0 && buf[len - 1] == '\r') {
		len--;
		buf[len] = '\0';
	    }
	    *lenp = len;
	    return EX_OK;
	}
    }

    libspamc_log(flags, LOG_ERR, "spamd responded with line of %d bytes, dying", len);
    failureval = EX_TOOBIG;

  failure:
    return failureval;
}

/*
 * May  7 2003 jm: using %f is bad where LC_NUMERIC is "," in the locale.
 * work around using our own locale-independent float-parser code.
 */
static float _locale_safe_string_to_float(char *buf, int siz)
{
    int is_neg;
    char *cp, *dot;
    int divider;
    float ret, postdot;

    buf[siz - 1] = '\0';	/* ensure termination */

    /* ok, let's illustrate using "100.033" as an example... */

    is_neg = 0;
    if (*buf == '-') {
	is_neg = 1;
    }

    ret = (float) (strtol(buf, &dot, 10));
    if (dot == NULL) {
	return 0.0;
    }
    if (dot != NULL && *dot != '.') {
	return ret;
    }

    /* ex: ret == 100.0 */

    cp = (dot + 1);
    postdot = (float) (strtol(cp, NULL, 10));
    /* note: don't compare floats == 0.0, it's unsafe.  use a range */
    if (postdot >= -0.00001 && postdot <= 0.00001) {
	return ret;
    }

    /* ex: postdot == 33.0, cp="033" */

    /* now count the number of decimal places and figure out what power of 10 to use */
    divider = 1;
    while (*cp != '\0') {
	divider *= 10;
	cp++;
    }

    /* ex:
     * cp="033", divider=1
     * cp="33", divider=10
     * cp="3", divider=100
     * cp="", divider=1000
     */

    if (is_neg) {
	ret -= (postdot / ((float) divider));
    }
    else {
	ret += (postdot / ((float) divider));
    }
    /* ex: ret == 100.033, tada! ... hopefully */

    return ret;
}

static int
_handle_spamd_header(struct message *m, int flags, char *buf, int len,
		     unsigned int *didtellflags)
{
    char is_spam[6];
    char s_str[21], t_str[21];
    char didset_ret[15];
    char didremove_ret[15];

    UNUSED_VARIABLE(len);

    /* Feb 12 2003 jm: actually, I think sccanf is working fine here ;)
     * let's stick with it for this parser.
     * May  7 2003 jm: using %f is bad where LC_NUMERIC is "," in the locale.
     * work around using our own locale-independent float-parser code.
     */
    if (sscanf(buf, "Spam: %5s ; %20s / %20s", is_spam, s_str, t_str) == 3) {
	m->score = _locale_safe_string_to_float(s_str, 20);
	m->threshold = _locale_safe_string_to_float(t_str, 20);

	/* set bounds on these to ensure no buffer overflow in the sprintf */
	if (m->score > 1e10)
	    m->score = 1e10;
	else if (m->score < -1e10)
	    m->score = -1e10;
	if (m->threshold > 1e10)
	    m->threshold = 1e10;
	else if (m->threshold < -1e10)
	    m->threshold = -1e10;

	/* Format is "Spam: x; y / x" */
	m->is_spam =
	    strcasecmp("true", is_spam) == 0 ? EX_ISSPAM : EX_NOTSPAM;

	if (flags & SPAMC_CHECK_ONLY) {
	    m->out_len = sprintf(m->out,
				 "%.1f/%.1f\n", m->score, m->threshold);
	}
	else if ((flags & SPAMC_REPORT_IFSPAM && m->is_spam == EX_ISSPAM)
		 || (flags & SPAMC_REPORT)) {
	    m->out_len = sprintf(m->out,
				 "%.1f/%.1f\n", m->score, m->threshold);
	}
	return EX_OK;

    }
    else if (sscanf(buf, "Content-length: %d", &m->content_length) == 1) {
	if (m->content_length < 0) {
	    libspamc_log(flags, LOG_ERR, "spamd responded with bad Content-length '%s'",
		   buf);
	    return EX_PROTOCOL;
	}
	return EX_OK;
    }
    else if (sscanf(buf, "DidSet: %14s", didset_ret) == 1) {
      if (strstr(didset_ret, "local")) {
	  *didtellflags |= SPAMC_SET_LOCAL;
	}
	if (strstr(didset_ret, "remote")) {
	  *didtellflags |= SPAMC_SET_REMOTE;
	}
    }
    else if (sscanf(buf, "DidRemove: %14s", didremove_ret) == 1) {
        if (strstr(didremove_ret, "local")) {
	  *didtellflags |= SPAMC_REMOVE_LOCAL;
	}
	if (strstr(didremove_ret, "remote")) {
	  *didtellflags |= SPAMC_REMOVE_REMOTE;
	}
    }
    else if (m->priv->spamd_header_callback != NULL)
      m->priv->spamd_header_callback(m, flags, buf, len);

    return EX_OK;
}

static int
_zlib_compress (char *m_msg, int m_msg_len,
        unsigned char **zlib_buf, int *zlib_bufsiz, int flags)
{
    int rc;
    int len, totallen;

#ifndef HAVE_LIBZ

    UNUSED_VARIABLE(m_msg);
    UNUSED_VARIABLE(m_msg_len);
    UNUSED_VARIABLE(zlib_buf);
    UNUSED_VARIABLE(zlib_bufsiz);
    UNUSED_VARIABLE(rc);
    UNUSED_VARIABLE(len);
    UNUSED_VARIABLE(totallen);
    libspamc_log(flags, LOG_ERR, "spamc not built with zlib support");
    return EX_SOFTWARE;

#else
    z_stream strm;

    UNUSED_VARIABLE(flags);

    /* worst-case, according to http://www.zlib.org/zlib_tech.html ;
      * same as input, plus 5 bytes per 16k, plus 6 bytes.  this should
      * be plenty */
    *zlib_bufsiz = (int) (m_msg_len * 1.0005) + 1024;
    *zlib_buf = (unsigned char *) malloc (*zlib_bufsiz);
    if (*zlib_buf == NULL) {
        return EX_OSERR;
    }

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    rc = deflateInit(&strm, 3);
    if (rc != Z_OK) {
        return EX_OSERR;
    }

    strm.avail_in = m_msg_len;
    strm.next_in = (unsigned char *) m_msg;
    strm.avail_out = *zlib_bufsiz;
    strm.next_out = (unsigned char *) *zlib_buf;

    totallen = 0;
    do {
        rc = deflate(&strm, Z_FINISH);
        assert(rc != Z_STREAM_ERROR);
        len = (size_t) (*zlib_bufsiz - strm.avail_out);
        strm.next_out += len;
        totallen += len;
    } while (strm.avail_out == 0);

    *zlib_bufsiz = totallen;
    return EX_OK;

#endif
}

int
_append_original_body (struct message *m, int flags)
{
    char *cp, *cpend, *bodystart;
    int bodylen, outspaceleft, towrite;

    /* at this stage, m->out now contains the rewritten headers.
     * find and append the raw message's body, up to m->priv->alloced_size
     * bytes.
     */

#define CRNLCRNL        "\r\n\r\n"
#define CRNLCRNL_LEN    4
#define NLNL            "\n\n"
#define NLNL_LEN        2

    cpend = m->raw + m->raw_len;
    bodystart = NULL;

    for (cp = m->raw; cp < cpend; cp++) {
        if (*cp == '\r' && cpend - cp >= CRNLCRNL_LEN && 
                            !strncmp(cp, CRNLCRNL, CRNLCRNL_LEN))
        {
            bodystart = cp + CRNLCRNL_LEN;
            break;
        }
        else if (*cp == '\n' && cpend - cp >= NLNL_LEN && 
                           !strncmp(cp, NLNL, NLNL_LEN))
        {
            bodystart = cp + NLNL_LEN;
            break;
        }
    }

    if (bodystart == NULL) {
        libspamc_log(flags, LOG_ERR, "failed to find end-of-headers");
        return EX_SOFTWARE;
    }

    bodylen = cpend - bodystart;
    outspaceleft = (m->priv->alloced_size-1) - m->out_len;
    towrite = (bodylen < outspaceleft ? bodylen : outspaceleft);

    /* copy in the body; careful not to overflow */
    strncpy (m->out + m->out_len, bodystart, towrite);
    m->out_len += towrite;
    return EX_OK;
}

int message_filter(struct transport *tp, const char *username,
                   int flags, struct message *m)
{
    char buf[8192];
    size_t bufsiz = (sizeof(buf) / sizeof(*buf)) - 4; /* bit of breathing room */
    size_t len;
    int sock = -1;
    int rc;
    char versbuf[20];
    float version;
    int response;
    int failureval = EX_SOFTWARE;
    unsigned int throwaway;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL_METHOD *meth;
    char zlib_on = 0;
    unsigned char *zlib_buf = NULL;
    int zlib_bufsiz = 0;
    unsigned char *towrite_buf;
    int towrite_len;
    int filter_retry_count;
    int filter_retry_sleep;
    int filter_retries;
    #ifdef SPAMC_HAS_ADDRINFO
        struct addrinfo *tmphost;
    #else
        struct in_addr tmphost;
    #endif
    int nhost_counter;

    assert(tp != NULL);
    assert(m != NULL);

    if ((flags & SPAMC_USE_ZLIB) != 0) {
      zlib_on = 1;
    }

    if (flags & SPAMC_USE_SSL) {
#ifdef SPAMC_SSL
	SSLeay_add_ssl_algorithms();
	if (flags & SPAMC_TLSV1) {
	    meth = TLSv1_client_method();
	} else {
	    meth = SSLv3_client_method(); /* default */
	}
	SSL_load_error_strings();
	ctx = SSL_CTX_new(meth);
#else
	UNUSED_VARIABLE(ssl);
	UNUSED_VARIABLE(meth);
	UNUSED_VARIABLE(ctx);
	libspamc_log(flags, LOG_ERR, "spamc not built with SSL support");
	return EX_SOFTWARE;
#endif
    }

    m->is_spam = EX_TOOBIG;

    if (m->outbuf != NULL)
        free(m->outbuf);
    m->priv->alloced_size = m->max_len + EXPANSION_ALLOWANCE + 1;
    if ((m->outbuf = malloc(m->priv->alloced_size)) == NULL) {
	failureval = EX_OSERR;
	goto failure;
    }
    m->out = m->outbuf;
    m->out_len = 0;

    /* If the spamd filter takes too long and we timeout, then
     * retry again.  This gets us around a hung child thread 
     * in spamd or a problem on a spamd host in a multi-host
     * setup.  If there is more than one destination host
     * we move to the next host on each attempt.
     */

    /* default values */
    filter_retry_sleep = tp->filter_retry_sleep;
    filter_retries = tp->filter_retries;
    if (filter_retries == 0) {
        filter_retries = 1;
    }
    if (filter_retry_sleep < 0) {
        filter_retry_sleep = 1;
    }

    /* filterloop - Ensure that we run through this at least
     * once, and again if there are errors 
     */
    filter_retry_count = 0;
    while ((filter_retry_count==0) || 
                ((filter_retry_count<tp->filter_retries) && (failureval == EX_IOERR)))
    {
        if (filter_retry_count != 0){
            /* Ensure that the old socket gets closed */
            if (sock != -1) {
                closesocket(sock);
                sock=-1;
            }

            /* Move to the next host in the list, if nhosts>1 */
            if (tp->nhosts > 1) {
                tmphost = tp->hosts[0];

                /* TODO: free using freeaddrinfo() */
                for (nhost_counter = 1; nhost_counter < tp->nhosts; nhost_counter++) {
                    tp->hosts[nhost_counter - 1] = tp->hosts[nhost_counter];
                }
        
                tp->hosts[nhost_counter - 1] = tmphost;
            }

            /* Now sleep the requested amount */
            sleep(filter_retry_sleep);
        }

        filter_retry_count++;
    
        /* Build spamd protocol header */
        if (flags & SPAMC_CHECK_ONLY)
          strcpy(buf, "CHECK ");
        else if (flags & SPAMC_REPORT_IFSPAM)
          strcpy(buf, "REPORT_IFSPAM ");
        else if (flags & SPAMC_REPORT)
          strcpy(buf, "REPORT ");
        else if (flags & SPAMC_SYMBOLS)
          strcpy(buf, "SYMBOLS ");
        else if (flags & SPAMC_PING)
          strcpy(buf, "PING ");
        else if (flags & SPAMC_HEADERS)
          strcpy(buf, "HEADERS ");
        else
          strcpy(buf, "PROCESS ");
    
        len = strlen(buf);
        if (len + strlen(PROTOCOL_VERSION) + 2 >= bufsiz) {
            _use_msg_for_out(m);
            return EX_OSERR;
        }
    
        strcat(buf, PROTOCOL_VERSION);
        strcat(buf, "\r\n");
        len = strlen(buf);
    
        towrite_buf = (unsigned char *) m->msg;
        towrite_len = (int) m->msg_len;
        if (zlib_on) {
            if (_zlib_compress(m->msg, m->msg_len, &zlib_buf, &zlib_bufsiz, flags) != EX_OK)
            {
                _free_zlib_buffer(&zlib_buf, &zlib_bufsiz);
                return EX_OSERR;
            }
            towrite_buf = zlib_buf;
            towrite_len = zlib_bufsiz;
        }
    
        if (!(flags & SPAMC_PING)) {
          if (username != NULL) {
              if (strlen(username) + 8 >= (bufsiz - len)) {
                  _use_msg_for_out(m);
                  if (zlib_on) {
                      _free_zlib_buffer(&zlib_buf, &zlib_bufsiz);
                  }
                  return EX_OSERR;
              }
              strcpy(buf + len, "User: ");
              strcat(buf + len, username);
              strcat(buf + len, "\r\n");
              len += strlen(buf + len);
          }
          if (zlib_on) {
              len += snprintf(buf + len, 8192-len, "Compress: zlib\r\n");
          }
          if ((m->msg_len > SPAMC_MAX_MESSAGE_LEN) || ((len + 27) >= (bufsiz - len))) {
              _use_msg_for_out(m);
              if (zlib_on) {
                  _free_zlib_buffer(&zlib_buf, &zlib_bufsiz);
              }
              return EX_DATAERR;
          }
          len += snprintf(buf + len, 8192-len, "Content-length: %d\r\n", (int) towrite_len);
        }
        /* bug 6187, PING needs empty line too, bumps protocol version to 1.5 */
        len += snprintf(buf + len, 8192-len, "\r\n");
    
        libspamc_timeout = m->timeout;
        libspamc_connect_timeout = m->connect_timeout;	/* Sep 8, 2008 mrgus: separate connect timeout */

        if (tp->socketpath)
          rc = _try_to_connect_unix(tp, &sock);
        else
          rc = _try_to_connect_tcp(tp, &sock);
    
        if (rc != EX_OK) {
          _use_msg_for_out(m);
          if (zlib_on) {
              _free_zlib_buffer(&zlib_buf, &zlib_bufsiz);
          }
          return rc;      /* use the error code try_to_connect_*() gave us. */
        }
    
        if (flags & SPAMC_USE_SSL) {
#ifdef SPAMC_SSL
            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, sock);
            SSL_connect(ssl);
#endif
        }
    
        /* Send to spamd */
        if (flags & SPAMC_USE_SSL) {
#ifdef SPAMC_SSL
            SSL_write(ssl, buf, len);
            SSL_write(ssl, towrite_buf, towrite_len);
#endif
        }
        else {
            full_write(sock, 0, buf, len);
            full_write(sock, 0, towrite_buf, towrite_len);
            shutdown(sock, SHUT_WR);
        }

        /* free zlib buffer
        * bug 6025: zlib buffer not freed if compression is used
        */
        if (zlib_on) {
            _free_zlib_buffer(&zlib_buf, &zlib_bufsiz);
        }
    
        /* ok, now read and parse it.  SPAMD/1.2 line first... */
        failureval =
                _spamc_read_full_line(m, flags, ssl, sock, buf, &len, bufsiz);
    } /* end of filterloop */

    if (failureval != EX_OK) {
        goto failure;
    }

    if (sscanf(buf, "SPAMD/%18s %d %*s", versbuf, &response) != 2) {
	libspamc_log(flags, LOG_ERR, "spamd responded with bad string '%s'", buf);
	failureval = EX_PROTOCOL;
	goto failure;
    }

    versbuf[19] = '\0';
    version = _locale_safe_string_to_float(versbuf, 20);
    if (version < 1.0) {
	libspamc_log(flags, LOG_ERR, "spamd responded with bad version string '%s'",
	       versbuf);
	failureval = EX_PROTOCOL;
	goto failure;
    }

    if (flags & SPAMC_PING) {
	closesocket(sock);
	sock = -1;
        m->out_len = sprintf(m->out, "SPAMD/%s %d\n", versbuf, response);
        m->is_spam = EX_NOTSPAM;
        return EX_OK;
    }

    m->score = 0;
    m->threshold = 0;
    m->is_spam = EX_TOOBIG;
    while (1) {
	failureval =
	    _spamc_read_full_line(m, flags, ssl, sock, buf, &len, bufsiz);
	if (failureval != EX_OK) {
	    goto failure;
	}

	if (len == 0 && buf[0] == '\0') {
	    break;		/* end of headers */
	}

	if (_handle_spamd_header(m, flags, buf, len, &throwaway) < 0) {
	    failureval = EX_PROTOCOL;
	    goto failure;
	}
    }

    len = 0;			/* overwrite those headers */

    if (flags & SPAMC_CHECK_ONLY) {
	closesocket(sock);
	sock = -1;
	if (m->is_spam == EX_TOOBIG) {
	    /* We should have gotten headers back... Damnit. */
	    failureval = EX_PROTOCOL;
	    goto failure;
	}
	return EX_OK;
    }
    else {
	if (m->content_length < 0) {
	    /* should have got a length too. */
	    failureval = EX_PROTOCOL;
	    goto failure;
	}

	/* have we already got something in the buffer (e.g. REPORT and
	 * REPORT_IFSPAM both create a line from the "Spam:" hdr)?  If
	 * so, add the size of that so our sanity check passes.
	 */
	if (m->out_len > 0) {
	    m->content_length += m->out_len;
	}

	if (flags & SPAMC_USE_SSL) {
	    len = full_read_ssl(ssl, (unsigned char *) m->out + m->out_len,
				m->priv->alloced_size - m->out_len,
				m->priv->alloced_size - m->out_len);
	}
	else {
	    len = full_read(sock, 0, m->out + m->out_len,
			    m->priv->alloced_size - m->out_len,
			    m->priv->alloced_size - m->out_len);
	}


	if ((int) len + (int) m->out_len > (m->priv->alloced_size - 1)) {
	    failureval = EX_TOOBIG;
	    goto failure;
	}
	m->out_len += len;

	shutdown(sock, SHUT_RD);
	closesocket(sock);
	sock = -1;
    }
    libspamc_timeout = 0;

    if (m->out_len != m->content_length) {
	libspamc_log(flags, LOG_ERR,
	       "failed sanity check, %d bytes claimed, %d bytes seen",
	       m->content_length, m->out_len);
	failureval = EX_PROTOCOL;
	goto failure;
    }

    if (flags & SPAMC_HEADERS) {
        if (_append_original_body(m, flags) != EX_OK) {
            goto failure;
        }
    }

    return EX_OK;

  failure:
	_use_msg_for_out(m);
    if (sock != -1) {
	closesocket(sock);
    }
    libspamc_timeout = 0;

    if (flags & SPAMC_USE_SSL) {
#ifdef SPAMC_SSL
	SSL_free(ssl);
	SSL_CTX_free(ctx);
#endif
    }
    return failureval;
}

int message_process(struct transport *trans, char *username, int max_size,
		    int in_fd, int out_fd, const int flags)
{
    int ret;
    struct message m;

    assert(trans != NULL);

    m.type = MESSAGE_NONE;

    /* enforce max_size being unsigned, therefore >= 0 */
    if (max_size < 0) {
	ret = EX_SOFTWARE;
        goto FAIL;
    }
    m.max_len = (unsigned int) max_size;

    ret = message_read(in_fd, flags, &m);
    if (ret != EX_OK)
        goto FAIL;
    ret = message_filter(trans, username, flags, &m);
    if (ret != EX_OK)
        goto FAIL;
    if (message_write(out_fd, &m) < 0)
        goto FAIL;
    if (m.is_spam != EX_TOOBIG) {
        message_cleanup(&m);
        return m.is_spam;
    }
    message_cleanup(&m);
    return ret;

  FAIL:
    if (flags & SPAMC_CHECK_ONLY) {
        full_write(out_fd, 1, "0/0\n", 4);
        message_cleanup(&m);
        return EX_NOTSPAM;
    }
    else {
        message_dump(in_fd, out_fd, &m, flags);
        message_cleanup(&m);
        return ret;
    }
}

int message_tell(struct transport *tp, const char *username, int flags,
		 struct message *m, int msg_class,
		 unsigned int tellflags, unsigned int *didtellflags)
{
    char buf[8192];
    size_t bufsiz = (sizeof(buf) / sizeof(*buf)) - 4; /* bit of breathing room */
    size_t len;
    int sock = -1;
    int rc;
    char versbuf[20];
    float version;
    int response;
    int failureval;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL_METHOD *meth;

    assert(tp != NULL);
    assert(m != NULL);

    if (flags & SPAMC_USE_SSL) {
#ifdef SPAMC_SSL
	SSLeay_add_ssl_algorithms();
	meth = SSLv3_client_method();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(meth);
#else
	UNUSED_VARIABLE(ssl);
	UNUSED_VARIABLE(meth);
	UNUSED_VARIABLE(ctx);
	libspamc_log(flags, LOG_ERR, "spamc not built with SSL support");
	return EX_SOFTWARE;
#endif
    }

    m->is_spam = EX_TOOBIG;

    if (m->outbuf != NULL)
        free(m->outbuf);
    m->priv->alloced_size = m->max_len + EXPANSION_ALLOWANCE + 1;
    if ((m->outbuf = malloc(m->priv->alloced_size)) == NULL) {
	failureval = EX_OSERR;
	goto failure;
    }
    m->out = m->outbuf;
    m->out_len = 0;

    /* Build spamd protocol header */
    strcpy(buf, "TELL ");

    len = strlen(buf);
    if (len + strlen(PROTOCOL_VERSION) + 2 >= bufsiz) {
	_use_msg_for_out(m);
	return EX_OSERR;
    }

    strcat(buf, PROTOCOL_VERSION);
    strcat(buf, "\r\n");
    len = strlen(buf);

    if (msg_class != 0) {
      strcpy(buf + len, "Message-class: ");
      if (msg_class == SPAMC_MESSAGE_CLASS_SPAM) {
	strcat(buf + len, "spam\r\n");
      }
      else {
	strcat(buf + len, "ham\r\n");
      }
      len += strlen(buf + len);
    }

    if ((tellflags & SPAMC_SET_LOCAL) || (tellflags & SPAMC_SET_REMOTE)) {
      int needs_comma_p = 0;
      strcat(buf + len, "Set: ");
      if (tellflags & SPAMC_SET_LOCAL) {
	strcat(buf + len, "local");
	needs_comma_p = 1;
      }
      if (tellflags & SPAMC_SET_REMOTE) {
	if (needs_comma_p == 1) {
	  strcat(buf + len, ",");
	}
	strcat(buf + len, "remote");
      }
      strcat(buf + len, "\r\n");
      len += strlen(buf + len);
    }

    if ((tellflags & SPAMC_REMOVE_LOCAL) || (tellflags & SPAMC_REMOVE_REMOTE)) {
      int needs_comma_p = 0;
      strcat(buf + len, "Remove: ");
      if (tellflags & SPAMC_REMOVE_LOCAL) {
	strcat(buf + len, "local");
	needs_comma_p = 1;
      }
      if (tellflags & SPAMC_REMOVE_REMOTE) {
	if (needs_comma_p == 1) {
	  strcat(buf + len, ",");
	}
	strcat(buf + len, "remote");
      }
      strcat(buf + len, "\r\n");
      len += strlen(buf + len);
    }

    if (username != NULL) {
	if (strlen(username) + 8 >= (bufsiz - len)) {
	    _use_msg_for_out(m);
	    return EX_OSERR;
	}
	strcpy(buf + len, "User: ");
	strcat(buf + len, username);
	strcat(buf + len, "\r\n");
	len += strlen(buf + len);
    }
    if ((m->msg_len > SPAMC_MAX_MESSAGE_LEN) || ((len + 27) >= (bufsiz - len))) {
	_use_msg_for_out(m);
	return EX_DATAERR;
    }
    len += sprintf(buf + len, "Content-length: %d\r\n\r\n", (int) m->msg_len);

    if (m->priv->spamc_header_callback != NULL) {
      char buf2[1024];
      m->priv->spamc_header_callback(m, flags, buf2, 1024);
      strncat(buf, buf2, bufsiz - len);
    }

    libspamc_timeout = m->timeout;
    libspamc_connect_timeout = m->connect_timeout;	/* Sep 8, 2008 mrgus: separate connect timeout */

    if (tp->socketpath)
	rc = _try_to_connect_unix(tp, &sock);
    else
	rc = _try_to_connect_tcp(tp, &sock);

    if (rc != EX_OK) {
	_use_msg_for_out(m);
	return rc;      /* use the error code try_to_connect_*() gave us. */
    }

    if (flags & SPAMC_USE_SSL) {
#ifdef SPAMC_SSL
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sock);
	SSL_connect(ssl);
#endif
    }

    /* Send to spamd */
    if (flags & SPAMC_USE_SSL) {
#ifdef SPAMC_SSL
	SSL_write(ssl, buf, len);
	SSL_write(ssl, m->msg, m->msg_len);
#endif
    }
    else {
	full_write(sock, 0, buf, len);
	full_write(sock, 0, m->msg, m->msg_len);
	shutdown(sock, SHUT_WR);
    }

    /* ok, now read and parse it.  SPAMD/1.2 line first... */
    failureval =
	_spamc_read_full_line(m, flags, ssl, sock, buf, &len, bufsiz);
    if (failureval != EX_OK) {
	goto failure;
    }

    if (sscanf(buf, "SPAMD/%18s %d %*s", versbuf, &response) != 2) {
	libspamc_log(flags, LOG_ERR, "spamd responded with bad string '%s'", buf);
	failureval = EX_PROTOCOL;
	goto failure;
    }

    versbuf[19] = '\0';
    version = _locale_safe_string_to_float(versbuf, 20);
    if (version < 1.0) {
	libspamc_log(flags, LOG_ERR, "spamd responded with bad version string '%s'",
	       versbuf);
	failureval = EX_PROTOCOL;
	goto failure;
    }

    m->score = 0;
    m->threshold = 0;
    m->is_spam = EX_TOOBIG;
    while (1) {
	failureval =
	    _spamc_read_full_line(m, flags, ssl, sock, buf, &len, bufsiz);
	if (failureval != EX_OK) {
	    goto failure;
	}

	if (len == 0 && buf[0] == '\0') {
	    break;		/* end of headers */
	}

	if (_handle_spamd_header(m, flags, buf, len, didtellflags) < 0) {
	    failureval = EX_PROTOCOL;
	    goto failure;
	}
    }

    len = 0;			/* overwrite those headers */

    shutdown(sock, SHUT_RD);
    closesocket(sock);
    sock = -1;

    libspamc_timeout = 0;

    return EX_OK;

  failure:
    _use_msg_for_out(m);
    if (sock != -1) {
        closesocket(sock);
    }
    libspamc_timeout = 0;

    if (flags & SPAMC_USE_SSL) {
#ifdef SPAMC_SSL
	SSL_free(ssl);
	SSL_CTX_free(ctx);
#endif
    }
    return failureval;
}

void message_cleanup(struct message *m)
{
    assert(m != NULL);
    if (m->outbuf != NULL)
        free(m->outbuf);
    if (m->raw != NULL)
        free(m->raw);
    if (m->priv != NULL)
        free(m->priv);
    _clear_message(m);
}

/* Aug 14, 2002 bj: Obsolete! */
int process_message(struct transport *tp, char *username, int max_size,
		    int in_fd, int out_fd, const int my_check_only,
		    const int my_safe_fallback)
{
    int flags;

    flags = SPAMC_RAW_MODE;
    if (my_check_only)
        flags |= SPAMC_CHECK_ONLY;
    if (my_safe_fallback)
        flags |= SPAMC_SAFE_FALLBACK;

    return message_process(tp, username, max_size, in_fd, out_fd, flags);
}

/*
* init_transport()
*
*	Given a pointer to a transport structure, set it to "all empty".
*	The default is a localhost connection.
*/
void transport_init(struct transport *tp)
{
    assert(tp != 0);

    memset(tp, 0, sizeof *tp);

    tp->type = TRANSPORT_LOCALHOST;
    tp->port = 783;
    tp->flags = 0;
    tp->retry_sleep = -1;
}

/*
* randomize_hosts()
*
*	Given the transport object that contains one or more IP addresses
*	in this "hosts" list, rotate it by a random number of shifts to
*	randomize them - this is a kind of load balancing. It's possible
*	that the random number will be 0, which says not to touch. We don't
*	do anything unless 
*/

static void _randomize_hosts(struct transport *tp)
{
#ifdef SPAMC_HAS_ADDRINFO
    struct addrinfo *tmp;
#else
    struct in_addr tmp;
#endif
    int i;
    int rnum;

    assert(tp != 0);

    if (tp->nhosts <= 1)
        return;

    rnum = rand() % tp->nhosts;

    while (rnum-- > 0) {
        tmp = tp->hosts[0];

        for (i = 1; i < tp->nhosts; i++)
            tp->hosts[i - 1] = tp->hosts[i];

        tp->hosts[i - 1] = tmp;
    }
}

/*
* transport_setup()
*
*	Given a "transport" object that says how we're to connect to the
*	spam daemon, perform all the initial setup required to make the
*	connection process a smooth one. The main work is to do the host
*	name lookup and copy over all the IP addresses to make a local copy
*	so they're not kept in the resolver's static state.
*
*	Here we also manage quasi-load balancing and failover: if we're
*	doing load balancing, we randomly "rotate" the list to put it in
*	a different order, and then if we're not doing failover we limit
*	the hosts to just one. This way *all* connections are done with
*	the intention of failover - makes the code a bit more clear.
*/
int transport_setup(struct transport *tp, int flags)
{
#ifdef SPAMC_HAS_ADDRINFO
    struct addrinfo hints, *res, *addrp;
    char port[6];
    int origerr;
#else
    struct hostent *hp;
    char **addrp;
#endif
    char *hostlist, *hostname;
    int errbits;

#ifdef _WIN32
    /* Start Winsock up */
    WSADATA wsaData;
    int nCode;
    if ((nCode = WSAStartup(MAKEWORD(1, 1), &wsaData)) != 0) {
        printf("WSAStartup() returned error code %d\n", nCode);
        return EX_OSERR;
    }

#endif

    assert(tp != NULL);
    tp->flags = flags;

#ifdef SPAMC_HAS_ADDRINFO
    snprintf(port, 6, "%d", tp->port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = 0;
    hints.ai_socktype = SOCK_STREAM;

    if (       (flags & SPAMC_USE_INET4) && !(flags & SPAMC_USE_INET6)) {
      hints.ai_family = PF_INET;
#ifdef PF_INET6
    } else if ((flags & SPAMC_USE_INET6) && !(flags & SPAMC_USE_INET4)) {
      hints.ai_family = PF_INET6;
#endif
    } else {
      hints.ai_family = PF_UNSPEC;
    }
#endif

    switch (tp->type) {
#ifndef _WIN32
    case TRANSPORT_UNIX:
        assert(tp->socketpath != 0);
        return EX_OK;
#endif
    case TRANSPORT_LOCALHOST:
#ifdef SPAMC_HAS_ADDRINFO
        /* getaddrinfo(NULL) will look up the loopback address.
         * See also bug 5057,  ::1 will be tried before 127.0.0.1
         * unless overridden (through hints) by a command line option -4
         */
        if ((origerr = getaddrinfo(NULL, port, &hints, &res)) != 0) {
            libspamc_log(flags, LOG_ERR, 
                  "getaddrinfo for a loopback address failed: %s",
                  gai_strerror(origerr));
            return EX_OSERR;
        }
        tp->hosts[0] = res;
#else
        tp->hosts[0].s_addr = inet_addr("127.0.0.1");
#endif
        tp->nhosts = 1;
        return EX_OK;

    case TRANSPORT_TCP:
        if ((hostlist = strdup(tp->hostname)) == NULL)
            return EX_OSERR;

        /* We want to return the least permanent error, in this bitmask we
         * record the errors seen with:
         *  0: no error
         *  1: EX_TEMPFAIL
         *  2: EX_NOHOST
         * EX_OSERR will return immediately.
         * Bits aren't reset so a check against nhosts is needed to determine
         * if something went wrong.
         */
        errbits = 0;
        tp->nhosts = 0;
        /* Start with char offset in front of the string because we'll add 
         * one in the loop
         */
        hostname = hostlist - 1;
        do {
            char *hostend;
            
            hostname += 1;
            hostend = strchr(hostname, ',');
            if (hostend != NULL) {
                *hostend = '\0';
            }
#ifdef SPAMC_HAS_ADDRINFO            
            if ((origerr = getaddrinfo(hostname, port, &hints, &res))) {
                libspamc_log(flags, LOG_DEBUG, 
                      "getaddrinfo(%s) failed: %s",
                      hostname, gai_strerror(origerr));
                switch (origerr) { 
                case EAI_AGAIN:
                    errbits |= 1;
                    break;
                case EAI_FAMILY: /*address family not supported*/
                case EAI_SOCKTYPE: /*socket type not supported*/
                case EAI_BADFLAGS: /*ai_flags is invalid*/
                case EAI_NONAME: /*node or service unknown*/
                case EAI_SERVICE: /*service not available*/
/* work around Cygwin IPv6 patch - err codes not defined in Windows aren't in patch */
#ifdef HAVE_EAI_ADDRFAMILY
                case EAI_ADDRFAMILY: /*no addresses in requested family*/
#endif
#ifdef HAVE_EAI_SYSTEM
                case EAI_SYSTEM: /*system error, check errno*/
#endif
#ifdef HAVE_EAI_NODATA
                case EAI_NODATA: /*address exists, but no data*/
#endif
                case EAI_MEMORY: /*out of memory*/
                case EAI_FAIL: /*name server returned permanent error*/
                    errbits |= 2;
                    break;
                default:
                    /* should not happen, all errors are checked above */
                    free(hostlist);
                    return EX_OSERR;
                }
                goto nexthost; /* try next host in list */
            }
#else
            if ((hp = gethostbyname(hostname)) == NULL) {
                int origerr = h_errno; /* take a copy before syslog() */
                libspamc_log(flags, LOG_DEBUG, "gethostbyname(%s) failed: h_errno=%d",
                    hostname, origerr);
                switch (origerr) {
                case TRY_AGAIN:
                    errbits |= 1;
                    break;
                case HOST_NOT_FOUND:
                case NO_ADDRESS:
                case NO_RECOVERY:
                    errbits |= 2;
                    break;
                default:
                    /* should not happen, all errors are checked above */
                    free(hostlist);
                    return EX_OSERR;
                }
                goto nexthost; /* try next host in list */
            }
#endif
            
            /* If we have no hosts at all */
#ifdef SPAMC_HAS_ADDRINFO
            if(res == NULL)
#else
            if (hp->h_addr_list[0] == NULL
             || hp->h_length != sizeof tp->hosts[0]
             || hp->h_addrtype != AF_INET)
                /* no hosts/bad size/wrong family */
#endif
            {
                errbits |= 1;
                goto nexthost; /* try next host in list */
            }

            /* Copy all the IP addresses into our private structure.
             * This gets them out of the resolver's static area and
             * means we won't ever walk all over the list with other
             * calls.
             */
#ifdef SPAMC_HAS_ADDRINFO
            if(tp->nhosts == TRANSPORT_MAX_HOSTS) {
               libspamc_log(flags, LOG_NOTICE, 
                     "hit limit of %d hosts, ignoring remainder",
                     TRANSPORT_MAX_HOSTS);
               break;
            }

            /* treat all A or AAAA records of each host as one entry */
            tp->hosts[tp->nhosts++] = res;

            /* alternatively, treat multiple A or AAAA records
               of one host as individual entries */
/*          for (addrp = res; addrp != NULL; ) {
 *              tp->hosts[tp->nhosts] = addrp;
 *              addrp = addrp->ai_next;     /-* before NULLing ai_next *-/
 *              tp->hosts[tp->nhosts]->ai_next = NULL;
 *              tp->nhosts++;
 *          }
 */

#else
            for (addrp = hp->h_addr_list; *addrp; addrp++) {
                if (tp->nhosts == TRANSPORT_MAX_HOSTS) {
                    libspamc_log(flags, LOG_NOTICE, "hit limit of %d hosts, ignoring remainder",
                        TRANSPORT_MAX_HOSTS);
                    break;
                }
                memcpy(&tp->hosts[tp->nhosts], *addrp, hp->h_length);
                tp->nhosts++;
            }
#endif            
nexthost:
            hostname = hostend;
        } while (hostname != NULL);
        free(hostlist);
        
        if (tp->nhosts == 0) {
            if (errbits & 1) {
                libspamc_log(flags, LOG_ERR, "could not resolve any hosts (%s): a temporary error occurred",
                    tp->hostname); 
                return EX_TEMPFAIL;
            }
            else {
                libspamc_log(flags, LOG_ERR, "could not resolve any hosts (%s): no such host",
                    tp->hostname); 
                return EX_NOHOST;
            }
        }
        
        /* QUASI-LOAD-BALANCING
         *
         * If the user wants to do quasi load balancing, "rotate"
         * the list by a random amount based on the current time.
         * This may later be truncated to a single item. This is
         * meaningful only if we have more than one host.
	 */

        if ((flags & SPAMC_RANDOMIZE_HOSTS) && tp->nhosts > 1) {
            _randomize_hosts(tp);
        }

        /* If the user wants no fallback, simply truncate the host
         * list to just one - this pretends that this is the extent
         * of our connection list - then it's not a special case.
         */
        if (!(flags & SPAMC_SAFE_FALLBACK) && tp->nhosts > 1) {
            /* truncating list */
            tp->nhosts = 1;
        }
        
        return EX_OK;
    }
    
    /* oops, unknown transport type */
    return EX_OSERR;
}

/*
* transport_cleanup()
*
*	Given a "transport" object that says how we're to connect to the
*	spam daemon, delete and free any buffers allocated so that it
*       can be discarded without causing a memory leak.
*/
void transport_cleanup(struct transport *tp)
{

#ifdef SPAMC_HAS_ADDRINFO
  int i;

  for(i=0;i<tp->nhosts;i++) {
      if (tp->hosts[i] != NULL) {
          freeaddrinfo(tp->hosts[i]);
          tp->hosts[i] = NULL;
      }
  }
#endif

}

/*
* register_libspamc_log_callback()
*
* Register a callback handler for libspamc_log to replace the default behaviour.
*/

void register_libspamc_log_callback(void (*function)(int flags, int level, char *msg, va_list args)) {
  libspamc_log_callback = function;
}

/*
* register_spamc_header_callback()
*
* Register a callback handler to generate spamc headers for a given message
*/

void register_spamc_header_callback(const struct message *m, void (*func)(struct message *m, int flags, char *buf, int len)) {
  m->priv->spamc_header_callback = func;
}

/*
* register_spamd_header_callback()
*
* Register a callback handler to generate spamd headers for a given message
*/

void register_spamd_header_callback(const struct message *m, void (*func)(struct message *m, int flags, const char *buf, int len)) {
  m->priv->spamd_header_callback = func;
}

/* --------------------------------------------------------------------------- */

#define LOG_BUFSIZ      1023

void
libspamc_log (int flags, int level, char *msg, ...)
{
    va_list ap;
    char buf[LOG_BUFSIZ+1];
    int len = 0;

    va_start(ap, msg);

    if ((flags & SPAMC_LOG_TO_CALLBACK) != 0 && libspamc_log_callback != NULL) {
      libspamc_log_callback(flags, level, msg, ap);
    }
    else if ((flags & SPAMC_LOG_TO_STDERR) != 0) {
        /* create a log-line buffer */
        len = snprintf(buf, LOG_BUFSIZ, "spamc: ");
        len += vsnprintf(buf+len, LOG_BUFSIZ-len, msg, ap);

        /* avoid buffer overflow */
        if (len > (LOG_BUFSIZ-2)) { len = (LOG_BUFSIZ-3); }

        len += snprintf(buf+len, LOG_BUFSIZ-len, "\n");
        buf[LOG_BUFSIZ] = '\0';     /* ensure termination */
        (void) write (2, buf, len);

    } else {
        vsnprintf(buf, LOG_BUFSIZ, msg, ap);
        buf[LOG_BUFSIZ] = '\0';     /* ensure termination */
#ifndef _WIN32
        syslog (level, "%s", buf);
#else
        (void) level;  /* not used. suppress compiler warning */
        fprintf (stderr, "%s\n", buf);
#endif
    }

    va_end(ap);
}

/* --------------------------------------------------------------------------- */

/*
* Unit tests.  Must be built externally, e.g.:
*
* gcc -g -DLIBSPAMC_UNIT_TESTS spamd/spamc.c spamd/libspamc.c spamd/utils.c -o libspamctest
* ./libspamctest
*
*/
#ifdef LIBSPAMC_UNIT_TESTS

static void _test_locale_safe_string_to_float_val(float input)
{
    char inputstr[99], cmpbuf1[99], cmpbuf2[99];
    float output;

    /* sprintf instead of snprintf is safe here because it is only a controlled test */
    sprintf(inputstr, "%f", input);
    output = _locale_safe_string_to_float(inputstr, 99);
    if (input == output) {
        return;
    }

    /* could be a rounding error.  print as string and compare those */
    sprintf(cmpbuf1, "%f", input);
    sprintf(cmpbuf2, "%f", output);
    if (!strcmp(cmpbuf1, cmpbuf2)) {
        return;
    }

    printf("FAIL: input=%f != output=%f\n", input, output);
}

static void unit_test_locale_safe_string_to_float(void)
{
    float statictestset[] = {	/* will try both +ve and -ve */
        0.1, 0.01, 0.001, 0.0001, 0.00001, 0.000001,
        9.1, 9.91, 9.991, 9.9991, 9.99991, 9.999991,
        0.0			/* end of set constant */
    };
    float num;
    int i;

    printf("starting unit_test_locale_safe_string_to_float\n");
    /* tests of precision */
    for (i = 0; statictestset[i] != 0.0; i++) {
        _test_locale_safe_string_to_float_val(statictestset[i]);
        _test_locale_safe_string_to_float_val(-statictestset[i]);
        _test_locale_safe_string_to_float_val(1 - statictestset[i]);
        _test_locale_safe_string_to_float_val(1 + statictestset[i]);
    }
    /* now exhaustive, in steps of 0.01 */
    for (num = -1000.0; num < 1000.0; num += 0.01) {
        _test_locale_safe_string_to_float_val(num);
    }
    printf("finished unit_test_locale_safe_string_to_float\n");
}

void do_libspamc_unit_tests(void)
{
    unit_test_locale_safe_string_to_float();
    exit(0);
}

#endif /* LIBSPAMC_UNIT_TESTS */
