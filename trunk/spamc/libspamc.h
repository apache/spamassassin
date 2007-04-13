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
#ifndef LIBSPAMC_H
#define LIBSPAMC_H 1

#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#ifdef _WIN32
#ifdef _MSC_VER
/* ignore MSVC++ warnings that are annoying and hard to remove:
 4115 named type definition in parentheses
 4127 conditional expression is constant
 4514 unreferenced inline function removed
 4996 deprecated "unsafe" functions (bug 4855)
 */
#pragma warning( disable : 4115 4127 4514 )
#if (_MSC_VER >= 1400)  /* VC8+ */
#pragma warning( disable : 4996 )
#endif

#endif
#include <winsock.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
/* some platforms (Cygwin) don't implement getaddrinfo */
#ifdef EAI_AGAIN
#define SPAMC_HAS_ADDRINFO 1
#endif
#endif

#if (defined(_WIN32) || !defined(_SYSEXITS_H))
/* FIXME: This stuff has to go somewhere else */

#define EX_OK           0
#define EX_USAGE        64
#define EX_DATAERR      65
#define EX_NOINPUT      66
#define EX_NOUSER       67
#define EX_NOHOST       68
#define EX_UNAVAILABLE  69
#define EX_SOFTWARE     70
#define EX_OSERR        71
#define EX_OSFILE       72
#define EX_CANTCREAT    73
#define EX_IOERR        74
#define EX_TEMPFAIL     75
#define EX_PROTOCOL     76
#define EX_NOPERM       77
#define EX_CONFIG       78

#define STDIN_FILENO 0
#define STDOUT_FILENO 1

/* FIXME: This doesn't belong here either */
#define LOG_EMERG       0       /* system is unusable */
#define LOG_ALERT       1       /* action must be taken immediately */
#define LOG_CRIT        2       /* critical conditions */
#define LOG_ERR         3       /* error conditions */
#define LOG_WARNING     4       /* warning conditions */
#define LOG_NOTICE      5       /* normal but significant condition */
#define LOG_INFO        6       /* informational */
#define LOG_DEBUG       7       /* debug-level messages */

#endif

#define EX_NOTSPAM		  0
#define EX_ISSPAM		  1
#define EX_TOOBIG		866

/* Aug 14, 2002 bj: Bitflags instead of lots of bool parameters */
#define SPAMC_MODE_MASK      1
#define SPAMC_RAW_MODE       0
#define SPAMC_BSMTP_MODE     1

#define SPAMC_USE_SSL	      (1<<27)
#define SPAMC_SAFE_FALLBACK   (1<<28)
#define SPAMC_CHECK_ONLY      (1<<29)

/* Jan 30, 2003 ym: added reporting options */
#define SPAMC_REPORT          (1<<26)
#define SPAMC_REPORT_IFSPAM   (1<<25)

/* Feb  1 2003 jm: might as well fix bug 191 as well */
#define SPAMC_SYMBOLS         (1<<24)

/* 2003/04/16 SJF: randomize hostname order (quasi load balancing) */
#define SPAMC_RANDOMIZE_HOSTS (1<<23)

/* log to stderr */
#define SPAMC_LOG_TO_STDERR   (1<<22)

/* Nov 24, 2004 NP: added learning support */
#define SPAMC_LEARN	      (1<<21)

/* May 5, 2005 NP: added list reporting support */
#define SPAMC_REPORT_MSG      (1<<20)

/* Oct 21, 2005 sidney: added ping test */
#define SPAMC_PING      (1<<19)

/* Jan 1, 2007 sidney: added SSL protocol versions */
/* no flags means use default of SSL_v23 */
/* Set both flags to specify TSL_v1 */
#define SPAMC_SSLV2 (1<<18)
#define SPAMC_SSLV3 (1<<17)

/* Nov 30, 2006 jm: add -z, zlib support */
#define SPAMC_USE_ZLIB        (1<<16)

/* Jan 16, 2007 jm: get markup headers from spamd */
#define SPAMC_HEADERS         (1<<15)

#define SPAMC_MESSAGE_CLASS_SPAM 1
#define SPAMC_MESSAGE_CLASS_HAM  2

#define SPAMC_SET_LOCAL          1
#define SPAMC_SET_REMOTE         2

#define SPAMC_REMOVE_LOCAL       4
#define SPAMC_REMOVE_REMOTE      8

#define SPAMC_MAX_MESSAGE_LEN     (256 * 1024 * 1024)     /* see bug 4928 */

/* Aug 14, 2002 bj: A struct for storing a message-in-progress */
typedef enum
{
    MESSAGE_NONE,
    MESSAGE_ERROR,
    MESSAGE_RAW,
    MESSAGE_BSMTP,
    MAX_MESSAGE_TYPE
} message_type_t;

struct libspamc_private_message;

struct message
{
    /* Set before passing the struct on! */
    unsigned int max_len; /* messages larger than this will return EX_TOOBIG */
    int timeout;		/* timeout for read() system calls */

    /* Filled in by message_read */
    message_type_t type;
    char *raw;
    int raw_len;		/* Raw message buffer */
    /* note: do not make "raw_len" in particular unsigned! see bug 4593 */
    char *pre;
    int pre_len;		/* Pre-message data (e.g. SMTP commands) */
    char *msg;
    int msg_len;		/* The message */
    char *post;
    int post_len;		/* Post-message data (e.g. SMTP commands) */
    int content_length;

    /* Filled in by filter_message */
    int is_spam;		/* EX_ISSPAM if the message is spam, EX_NOTSPAM
				   if not */
    float score, threshold;	/* score and threshold */
    char *outbuf;		/* Buffer for output from spamd */
    char *out;
    int out_len;		/* Output from spamd. Either the filtered
				   message, or the check-only response. Or else,
				   a pointer to msg above. */

    /* these members added in SpamAssassin version 2.60: */
    struct libspamc_private_message *priv;
};

/*------------------------------------------------------------------------
 * TRANSPORT (2004/04/16 - SJF)
 *
 * The code to connect with the daemon has gotten more complicated: support
 * for SSL, fallback to multiple hosts, and using UNIX domain sockets. The
 * code has gotten ugly with way too many parameters being passed all around.
 *
 * So we've created this object to hold all the info required to connect with
 * the remote site, including a self-contained list of all the IP addresses
 * in the event this is using TCP sockets. These multiple IPs can be obtained
 * only from DNS returning more than one A record for a single name, and
 * this allows for fallback.
 *
 * We also allow a kind of quasi-load balancing, where we take the list of
 * A records from DNS and randomize them before starting out - this lets
 * us spread the load out among multiple servers if desired. The idea for
 * load balancing goes to Jeremy Zawodny.
 *
 * By putting all our data here, we remove "fallback" from being a special
 * case. We may find ourselves with several IP addresses, but if the user
 * disables fallback, we set the IP address count to one. Now the connect
 * code just loops over that same address.
 */
#define TRANSPORT_LOCALHOST 0x01	/* TCP to localhost only */
#define	TRANSPORT_TCP	    0x02	/* standard TCP socket   */
#define TRANSPORT_UNIX	    0x03	/* UNIX domain socket    */

#define TRANSPORT_MAX_HOSTS 256	/* max hosts we can failover between */

struct transport
{
    int type;

    const char *socketpath;	/* for UNIX dommain socket      */
    const char *hostname;	/* for TCP sockets              */

    unsigned short port;	/* for TCP sockets              */

#ifdef SPAMC_HAS_ADDRINFO
    struct addrinfo *hosts[TRANSPORT_MAX_HOSTS];
#else
    struct in_addr hosts[TRANSPORT_MAX_HOSTS];
#endif
    int nhosts;
    int flags;

    /* added in SpamAssassin 3.2.0 */
    int connect_retries;
    int retry_sleep;
};

extern void transport_init(struct transport *tp);
extern int transport_setup(struct transport *tp, int flags);

/* Aug 14, 2002 bj: New interface functions */

/* Read in a message from the fd, with the mode specified in the flags.
 * Returns EX_OK on success, EX_otherwise on failure. On failure, m may be
 * either MESSAGE_NONE or MESSAGE_ERROR. */
int message_read(int in_fd, int flags, struct message *m);

/* Write out a message to the fd, as specified by m->type. Note that
 * MESSAGE_NONE messages have nothing to write. Also note that if you ran the
 * message through message_filter with SPAMC_CHECK_ONLY, it will only output
 * the "score/threshold" line. */
long message_write(int out_fd, struct message *m);

/* Process the message through the spamd filter, making as many connection
 * attempts as are implied by the transport structure. To make this do
 * failover, more than one host is defined, but if there is only one there,
 * no failover is done.
 */
int message_filter(struct transport *tp, const char *username,
		   int flags, struct message *m);

/* Process the message through the spamd tell command, making as many
 * connection attempts as are implied by the transport structure. To make
 * this do failover, more than one host is defined, but if there is only
 * one there, no failover is done.
 */
int message_tell(struct transport *tp, const char *username, int flags,
		 struct message *m, int msg_class,
		 unsigned int tellflags, unsigned int *didtellflags);

/* Dump the message. If there is any data in the message (typically, m->type
 * will be MESSAGE_ERROR) it will be message_writed. Then, fd_in will be piped
 * to fd_out intol EOF. This is particularly useful if you get back an
 * EX_TOOBIG. */
void message_dump(int in_fd, int out_fd, struct message *m);

/* Do a message_read->message_filter->message_write sequence, handling errors
 * appropriately with dump_message or appropriate CHECK_ONLY output. Returns
 * EX_OK or EX_ISSPAM/EX_NOTSPAM on success, some error EX on error. */
int message_process(struct transport *trans, char *username, int max_size,
		    int in_fd, int out_fd, const int flags);

/* Cleanup the resources we allocated for storing the message. Call after
 * you're done processing. */
void message_cleanup(struct message *m);

/* Aug 14, 2002 bj: This is now legacy, don't use it. */
int process_message(struct transport *tp, char *username,
		    int max_size, int in_fd, int out_fd,
		    const int check_only, const int safe_fallback);

void libspamc_log(int flags, int level, char *msg, ...);

#endif
