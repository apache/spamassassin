/*
 * This code is copyright 2001 by Craig Hughes
 * Portions copyright 2002 by Brad Jorsch
 * It is licensed under the same license as Perl itself.  The text of this
 * license is included in the SpamAssassin distribution in the file named
 * "License".
 */

#include "../config.h"
#include "libspamc.h"
#include "utils.h"

#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

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

#define MAX_CONNECT_RETRIES 3
#define CONNECT_RETRY_SLEEP 1

/* RedHat 5.2 doesn't define Shutdown 2nd Parameter Constants */
/* KAM 12-4-01 */
/* SJF 2003/04/25 - now test for macros directly */
#ifndef SHUT_RD
#  define SHUT_RD 0	/* no more receptions */
#endif
#ifndef SHUT_WR
#  define SHUT_WR 1	/* no more transmissions */
#endif
#ifndef SHUT_RDWR
#  define SHUT_RDWR 2	/* no more receptions or transmissions */
#endif

#ifndef HAVE_H_ERRNO
#define h_errno errno
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
/* or #define DO_CONNECT_DEBUG_SYSLOGS 1 */

static const int ESC_PASSTHROUGHRAW = EX__MAX+666;

/* set EXPANSION_ALLOWANCE to something more than might be
   added to a message in X-headers and the report template */
static const int EXPANSION_ALLOWANCE = 16384;

/* set NUM_CHECK_BYTES to number of bytes that have to match at beginning and end
   of the data streams before and after processing by spamd 
   Aug  7 2002 jm: no longer seems to be used
   static const int NUM_CHECK_BYTES = 32;
 */

/* Set the protocol version that this spamc speaks */
static const char *PROTOCOL_VERSION="SPAMC/1.3";

/* "private" part of struct message.
 * we use this instead of the struct message directly, so that we
 * can add new members without affecting the ABI.
 */
struct libspamc_private_message {
  int flags;	/* copied from "flags" arg to message_read() */
};

int libspamc_timeout = 0;

/*
 * translate_connect_errno()
 *
 *	Given a UNIX error number obtained (probably) from "connect(2)",
 *	translate this to a failure code. This module is shared by both
 *	transport modules - UNIX and TCP.
 *
 *	This should ONLY be called when there is an error.
 */
static int
translate_connect_errno(int err)
{
	switch (err)
	{
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
 *	Given a socket type (PF_INET or PF_UNIX), try to create this socket
 *	and store the FD in the pointed-to place. If it's successful, do any
 *	other setup required to make the socket ready to use, such as setting
 *	TCP_NODELAY mode, and in any case we return EX_OK if all is well.
 *
 *	Upon failure we return one of the other EX_??? error codes.
 */
static int opensocket(int type, int *psock)
{
const char *typename;
int	    proto = 0;

	assert(psock != 0);

	/*----------------------------------------------------------------
	 * Create a few induction variables that are implied by the socket
	 * type given by the user. The typename is strictly used for debug
	 * reporting.
	 */
	if ( type == PF_UNIX )
	{
		typename = "PF_UNIX";
	}
	else
	{
		typename = "PF_INET";
		proto    = IPPROTO_TCP;
	}

#ifdef DO_CONNECT_DEBUG_SYSLOGS
	syslog (DEBUG_LEVEL, "dbg: create socket(%s)", typename);
#endif

	if ( (*psock = socket(type, SOCK_STREAM, proto)) < 0 )
	{
	int	origerr;

		/*--------------------------------------------------------
		 * At this point we had a failure creating the socket, and
		 * this is pretty much fatal. Translate the error reason
		 * into something the user can understand.
		 */
		origerr = errno;    /* take a copy before syslog() */

		syslog (LOG_ERR, "socket(%s) to spamd failed: %m", typename);

		switch (origerr)
		{
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


	/*----------------------------------------------------------------
	 * Do a bit of setup on the TCP socket if required. Notes above
	 * suggest this is probably not set
	 */
#ifdef USE_TCP_NODELAY
	{
		int one = 1;

		if ( type == PF_INET
		 &&  setsockopt(*psock, 0, TCP_NODELAY, &one, sizeof one) != 0 )
		{
			switch(errno)
			{
			  case EBADF:
			  case ENOTSOCK:
			  case ENOPROTOOPT:
			  case EFAULT:
				syslog(LOG_ERR,
				   "setsockopt(TCP_NODELAY) failed: %m");
				close (*psock);
				return EX_SOFTWARE;

			  default:
				break;            /* ignored */
			}
		}
	}
#endif /* USE_TCP_NODELAY */

	return EX_OK;	/* all is well */
}

/*
 * try_to_connect_unix()
 *
 *	Given a transport handle that implies using a UNIX domain
 *	socket, try to make a connection to it and store the resulting
 *	file descriptor in *sockptr. Return is EX_OK if we did it,
 *	and some other error code otherwise.
 */
static int
try_to_connect_unix (struct transport *tp, int *sockptr)
{
int mysock, status, origerr;
struct sockaddr_un addrbuf;
int ret;

	assert(tp             != 0);
	assert(sockptr        != 0);
	assert(tp->socketpath != 0);

	/*----------------------------------------------------------------
	 * If the socket itself can't be created, this is a fatal error.
	 */
	if ( (ret = opensocket(PF_UNIX, &mysock)) != EX_OK )
		return ret;

	/* set up the UNIX domain socket */
	memset(&addrbuf, 0, sizeof addrbuf);
	addrbuf.sun_family = AF_UNIX;
	strncpy(addrbuf.sun_path, tp->socketpath, sizeof addrbuf.sun_path - 1);

#ifdef DO_CONNECT_DEBUG_SYSLOGS
	syslog (DEBUG_LEVEL, "dbg: connect(AF_UNIX) to spamd at %s",
		addrbuf.sun_path);
#endif

	status = connect(mysock, (struct sockaddr *) &addrbuf, sizeof(addrbuf));

	origerr = errno;

	if ( status >= 0 )
	{
#ifdef DO_CONNECT_DEBUG_SYSLOGS
		syslog(DEBUG_LEVEL, "dbg: connect(AF_UNIX) ok");
#endif

		*sockptr = mysock;

		return EX_OK;
	}

	syslog(LOG_ERR, "connect(AF_UNIX) to spamd %s failed: %m",
		addrbuf.sun_path);

	close(mysock);

	return translate_connect_errno(origerr);
}

/*
 * try_to_connect_tcp()
 *
 *	Given a transport that implies a TCP connection, either to
 *	localhost or a list of IP addresses, attempt to connect. The
 *	list of IP addresses has already been randomized (if requested)
 *	and limited to just one if fallback has been enabled.
 */
static int
try_to_connect_tcp (const struct transport *tp, int *sockptr)
{
int	numloops;
int	origerr = 0;
int	ret;

	assert(tp        != 0);
	assert(sockptr   != 0);
	assert(tp->nhosts > 0);

#ifdef DO_CONNECT_DEBUG_SYSLOGS
	for (numloops = 0; numloops < tp->nhosts; numloops++)
	{
		syslog(LOG_ERR, "dbg: %d/%d: %s",
			numloops+1, tp->nhosts, inet_ntoa(tp->hosts[numloops]));
	}
#endif

	for (numloops = 0; numloops < MAX_CONNECT_RETRIES; numloops++)
	{
	struct sockaddr_in addrbuf;
	const int          hostix = numloops % tp->nhosts;
	int                status, mysock;
	const char	 * ipaddr;

		/*--------------------------------------------------------
		 * We always start by creating the socket, as we get only
		 * one attempt to connect() on each one. If this fails,
		 * we're done.
		 */
		if ( (ret = opensocket(PF_INET, &mysock)) != EX_OK )
			return ret;

		memset(&addrbuf, 0, sizeof(addrbuf));

		addrbuf.sin_family = AF_INET;
		addrbuf.sin_port   = htons(tp->port);
		addrbuf.sin_addr   = tp->hosts[hostix];

		ipaddr = inet_ntoa(addrbuf.sin_addr);

#ifdef DO_CONNECT_DEBUG_SYSLOGS
		syslog (DEBUG_LEVEL,
			"dbg: connect(AF_INET) to spamd at %s (try #%d of %d)",
			ipaddr,
			numloops+1,
			MAX_CONNECT_RETRIES);
#endif

		status = connect(mysock, (struct sockaddr *)&addrbuf, sizeof(addrbuf));

		if (status != 0)
		{
			syslog (LOG_ERR,
			"connect(AF_INET) to spamd at %s failed, retrying (#%d of %d): %m",
				ipaddr, numloops+1, MAX_CONNECT_RETRIES);

			close(mysock);

			sleep(CONNECT_RETRY_SLEEP);
		}
		else
		{
#ifdef DO_CONNECT_DEBUG_SYSLOGS
			syslog(DEBUG_LEVEL,
				"dbg: connect(AF_INET) to spamd at %s done",
				ipaddr);
#endif
			*sockptr = mysock;

			return EX_OK;
		}
	}

	syslog (LOG_ERR, "connection attempt to spamd aborted after %d retries",
		MAX_CONNECT_RETRIES);

	return translate_connect_errno(origerr);
}

#if 0
static int
try_to_connect (const struct sockaddr *argaddr, struct hostent *hent,
                int hent_port, int *sockptr)
{
#ifdef USE_TCP_NODELAY
  int value;
#endif
  int mysock = -1;
  int status = -1;
  int origerr;
  int numloops;
  int hostnum = 0;
  struct sockaddr_in addrbuf, *addr;
  struct in_addr inaddrlist[256];

#ifdef DO_CONNECT_DEBUG_SYSLOGS
  int dbgiter; char dbgbuf[2048]; int dbgbuflen = 0;
#endif

  /* NOTE: do not call syslog() (unless you are about to return) before
   * we take a copy of the h_addr_list.
   */

  /* only one set of connection targets can be used.  assert this */
  if (argaddr == NULL && hent == NULL) {
      syslog (LOG_ERR, "oops! both NULL in try_to_connect");
      return EX_SOFTWARE;
  } else if (argaddr != NULL && hent != NULL) {
      syslog (LOG_ERR, "oops! both non-NULL in try_to_connect");
      return EX_SOFTWARE;
  }

  /* take a copy of the h_addr_list part of the struct hostent */
  if (hent != NULL) {
    memset (inaddrlist, 0, sizeof(inaddrlist));

    for (hostnum=0; hent->h_addr_list[hostnum] != 0; hostnum++) {

#ifdef DO_CONNECT_DEBUG_SYSLOGS
      dbgbuflen += snprintf (dbgbuf+dbgbuflen, 2047-dbgbuflen,
	          "[%d %lx: %d.%d.%d.%d]",
		  hostnum, hent->h_addr_list[hostnum],
		  hent->h_addr_list[hostnum][0],
		  hent->h_addr_list[hostnum][1],
		  hent->h_addr_list[hostnum][2],
		  hent->h_addr_list[hostnum][3]);
#endif

      if (hostnum > 255) {
	syslog (LOG_ERR, "too many address in hostent (%d), ignoring others",
	                    hostnum);
	break;
      }

      if (hent->h_addr_list[hostnum] == NULL) {
	/* shouldn't happen */
	syslog (LOG_ERR, "hent->h_addr_list[hostnum] == NULL! foo!");
	return EX_SOFTWARE;
      }

#ifdef DO_CONNECT_DEBUG_SYSLOGS
      dbgbuflen += snprintf (dbgbuf+dbgbuflen, 2047-dbgbuflen,
		  "[%d: %d.%d.%d.%d] ", sizeof (struct in_addr),
		  hent->h_addr_list[hostnum][0],
		  hent->h_addr_list[hostnum][1],
		  hent->h_addr_list[hostnum][2],
		  hent->h_addr_list[hostnum][3]);
#endif

      memcpy ((void *) &(inaddrlist[hostnum]),
		(void *) hent->h_addr_list[hostnum],
		sizeof (struct in_addr));
    }

#ifdef DO_CONNECT_DEBUG_SYSLOGS
      syslog (LOG_DEBUG, "dbg: %d %s", hostnum, dbgbuf); dbgbuflen = 0;
#endif
  }


#ifdef DO_CONNECT_DEBUG_SYSLOGS
    for (dbgiter = 0; dbgiter < hostnum; dbgiter++) {
      syslog (LOG_DEBUG, "dbg: host addr %d/%d = %lx at %lx", dbgiter, hostnum,
		  inaddrlist[dbgiter].s_addr, &(inaddrlist[dbgiter]));
    }
#endif

  hent = NULL; /* cannot use hent after this point, syslog() may overwrite it */

#ifdef DO_CONNECT_DEBUG_SYSLOGS
  syslog (LOG_DEBUG, "dbg: socket");
#endif

  if(-1 == (mysock = socket(PF_INET,SOCK_STREAM,0)))
  {
    origerr = errno;    /* take a copy before syslog() */
    syslog (LOG_ERR, "socket() to spamd failed: %m");
    switch(origerr)
    {
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

#ifdef USE_TCP_NODELAY
  /* TODO: should this be up above the connect()? */
  value = 1;		/* make this explicit! */
  if(-1 == setsockopt(mysock,0,TCP_NODELAY,&value,sizeof(value)))
  {
    switch(errno)
    {
    case EBADF:
    case ENOTSOCK:
    case ENOPROTOOPT:
    case EFAULT:
      syslog (LOG_ERR, "setsockopt() to spamd failed: %m");
      close (mysock);
      return EX_SOFTWARE;

    default:
      break;		/* ignored */
    }
  }
#endif

  for (numloops=0; numloops < MAX_CONNECT_RETRIES; numloops++) {
  
#ifdef DO_CONNECT_DEBUG_SYSLOGS
      syslog (LOG_DEBUG, "dbg: connect() to spamd %d", numloops);
#endif

    if (argaddr != NULL) {
      addr = (struct sockaddr_in *) argaddr;     /* use the one provided */
  
#ifdef DO_CONNECT_DEBUG_SYSLOGS
	syslog (LOG_DEBUG, "dbg: using argaddr");
#endif

    } else {
      /* cycle through the addrs in hent */
      memset(&addrbuf, 0, sizeof(addrbuf));
      addrbuf.sin_family=AF_INET;
      addrbuf.sin_port=htons(hent_port);

      if (sizeof(addrbuf.sin_addr) != sizeof(struct in_addr)) {	/* shouldn't happen */
	syslog (LOG_ERR,	
		"foo! sizeof(sockaddr.sin_addr) != sizeof(struct in_addr)");
	return EX_SOFTWARE;
      }

#ifdef DO_CONNECT_DEBUG_SYSLOGS
	syslog (LOG_DEBUG, "dbg: cpy addr %d/%d at %lx",
		numloops%hostnum, hostnum, &(inaddrlist[numloops % hostnum]));
#endif

      memcpy (&addrbuf.sin_addr, &(inaddrlist[numloops % hostnum]),
                        sizeof(addrbuf.sin_addr));
      addr = &addrbuf;

#ifdef DO_CONNECT_DEBUG_SYSLOGS
	syslog (LOG_DEBUG, "dbg: conn addr %d/%d = %lx",
	    numloops%hostnum, hostnum, addrbuf.sin_addr.s_addr);
#endif

    }

#ifdef DO_CONNECT_DEBUG_SYSLOGS
    syslog (LOG_DEBUG, "dbg: connect() to spamd at %s",
		inet_ntoa(((struct sockaddr_in *)addr)->sin_addr));
#endif
    status = connect(mysock,(const struct sockaddr *) addr, sizeof(*addr));

#ifdef DO_CONNECT_DEBUG_SYSLOGS
      syslog (LOG_DEBUG, "dbg: connect() to spamd at %s done",
	  inet_ntoa(((struct sockaddr_in *)addr)->sin_addr));
#endif

    if (status < 0)
    {
      origerr = errno;        /* take a copy before syslog() */
      syslog (LOG_ERR, "connect() to spamd at %s failed, retrying (%d/%d): %m",
                        inet_ntoa(((struct sockaddr_in *)addr)->sin_addr),
                        numloops+1, MAX_CONNECT_RETRIES);
      sleep(CONNECT_RETRY_SLEEP);

    } else {
      *sockptr = mysock;
      return EX_OK;
    }
  }
 
  /* failed, even with a few retries */
  close (mysock);
  syslog (LOG_ERR, "connection attempt to spamd aborted after %d retries",
       MAX_CONNECT_RETRIES);
 
  switch(origerr)
  {
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
#endif

/* Aug 14, 2002 bj: Reworked things. Now we have message_read, message_write,
 * message_dump, lookup_host, message_filter, and message_process, and a bunch
 * of helper functions.
 */

static void clear_message(struct message *m){
    m->type=MESSAGE_NONE;
    m->raw=NULL; m->raw_len=0;
    m->pre=NULL; m->pre_len=0;
    m->msg=NULL; m->msg_len=0;
    m->post=NULL; m->post_len=0;
    m->is_spam=EX_TOOBIG;
    m->score=0.0; m->threshold=0.0;
    m->out=NULL; m->out_len=0;
    m->content_length=-1;
}

static int
message_read_raw(int fd, struct message *m){
    clear_message(m);
    if((m->raw=malloc(m->max_len+1))==NULL) return EX_OSERR;
    m->raw_len=full_read(fd, m->raw, m->max_len+1, m->max_len+1);
    if(m->raw_len<=0){
        free(m->raw); m->raw=NULL; m->raw_len=0;
        return EX_IOERR;
    }
    m->type=MESSAGE_ERROR;
    if(m->raw_len>m->max_len) return EX_TOOBIG;
    m->type=MESSAGE_RAW;
    m->msg=m->raw;
    m->msg_len=m->raw_len;
    m->out=m->msg;
    m->out_len=m->msg_len;
    return EX_OK;
}

static int message_read_bsmtp(int fd, struct message *m){
    off_t i, j;
    char prev;

    clear_message(m);
    if((m->raw=malloc(m->max_len+1))==NULL) return EX_OSERR;

    /* Find the DATA line */
    m->raw_len=full_read(fd, m->raw, m->max_len+1, m->max_len+1);
    if(m->raw_len<=0){
        free(m->raw); m->raw=NULL; m->raw_len=0;
        return EX_IOERR;
    }
    m->type=MESSAGE_ERROR;
    if(m->raw_len>m->max_len) return EX_TOOBIG;
    m->pre=m->raw;
    for(i=0; i<m->raw_len-6; i++){
        if((m->raw[i]=='\n') &&
           (m->raw[i+1]=='D' || m->raw[i+1]=='d') &&
           (m->raw[i+2]=='A' || m->raw[i+2]=='a') &&
           (m->raw[i+3]=='T' || m->raw[i+3]=='t') &&
           (m->raw[i+4]=='A' || m->raw[i+4]=='a') &&
           ((m->raw[i+5]=='\r' && m->raw[i+6]=='\n') || m->raw[i+5]=='\n')){
            /* Found it! */
            i+=6;
            if(m->raw[i-1]=='\r') i++;
            m->pre_len=i;
            m->msg=m->raw+i;
            m->msg_len=m->raw_len-i;
            break;
        }
    }
    if(m->msg==NULL) return EX_DATAERR;

    /* Find the end-of-DATA line */
    prev='\n';
    for(i=j=0; i<m->msg_len; i++){
        if(prev=='\n' && m->msg[i]=='.'){
            /* Dot at the beginning of a line */
            if((m->msg[i+1]=='\r' && m->msg[i+2]=='\n') || m->msg[i+1]=='\n'){
                /* Lone dot! That's all, folks */
                m->post=m->msg+i;
                m->post_len=m->msg_len-i;
                m->msg_len=j;
                break;
            } else if(m->msg[i+1]=='.'){
                /* Escaping dot, eliminate. */
                prev='.';
                continue;
            } /* Else an ordinary dot, drop down to ordinary char handler */
        }
        prev=m->msg[i];
        m->msg[j++]=m->msg[i];
    }

    m->type=MESSAGE_BSMTP;
    m->out=m->msg;
    m->out_len=m->msg_len;
    return EX_OK;
}

int message_read(int fd, int flags, struct message *m){
    libspamc_timeout = 0;

    /* create the "private" part of the struct message */
    m->priv = malloc (sizeof (struct libspamc_private_message));
    if (m->priv == NULL) {
        syslog(LOG_ERR, "message_read: malloc failed");
        return EX_OSERR;
    }
    m->priv->flags = flags;

    switch(flags&SPAMC_MODE_MASK){
      case SPAMC_RAW_MODE:
        return message_read_raw(fd, m);

      case SPAMC_BSMTP_MODE:
        return message_read_bsmtp(fd, m);

      default:
        syslog(LOG_ERR, "message_read: Unknown mode %d\n", flags&SPAMC_MODE_MASK);
        return EX_USAGE;
    }
}

long message_write(int fd, struct message *m){
    long total=0;
    off_t i, j;
    off_t jlimit;
    char buffer[1024];

    if (m->priv->flags&SPAMC_CHECK_ONLY) {
	if(m->is_spam==EX_ISSPAM || m->is_spam==EX_NOTSPAM){
	    return full_write(fd, m->out, m->out_len);

	} else {
	    syslog(LOG_ERR, "oops! SPAMC_CHECK_ONLY is_spam: %d\n", m->is_spam);
	    return -1;
	}
    }

    /* else we're not in CHECK_ONLY mode */
    switch(m->type){
      case MESSAGE_NONE:
        syslog(LOG_ERR, "Cannot write this message, it's MESSAGE_NONE!\n");
        return -1;

      case MESSAGE_ERROR:
        return full_write(fd, m->raw, m->raw_len);

      case MESSAGE_RAW:
        return full_write(fd, m->out, m->out_len);

      case MESSAGE_BSMTP:
        total=full_write(fd, m->pre, m->pre_len);
        for(i=0; i<m->out_len; ){
	    jlimit = (off_t) (sizeof(buffer)/sizeof(*buffer)-4);
            for(j=0; i < (off_t) m->out_len &&
                                j < jlimit;)
            {
                if(i+1<m->out_len && m->out[i]=='\n' && m->out[i+1]=='.'){
		    if (j > jlimit - 4) {
			break;		/* avoid overflow */
		    }
                    buffer[j++]=m->out[i++];
                    buffer[j++]=m->out[i++];
                    buffer[j++]='.';
                } else {
                    buffer[j++]=m->out[i++];
                }
            }
            total+=full_write(fd, buffer, j);
        }
        return total+full_write(fd, m->post, m->post_len);

      default:
        syslog(LOG_ERR, "Unknown message type %d\n", m->type);
        return -1;
    }
}

void message_dump(int in_fd, int out_fd, struct message *m){
    char buf[8196];
    int bytes;
    
    if(m!=NULL && m->type!=MESSAGE_NONE) {
        message_write(out_fd, m);
    }
    while((bytes=full_read(in_fd, buf, 8192, 8192))>0){
        if (bytes!=full_write(out_fd, buf, bytes)) {
            syslog(LOG_ERR, "oops! message_dump of %d returned different", bytes);
        }
    }
}

static int
_spamc_read_full_line (struct message *m, int flags, SSL *ssl, int sock,
		char *buf, int *lenp, int bufsiz)
{
    int failureval;
    int bytesread = 0;
    int len;

    UNUSED_VARIABLE(m);

    /* Now, read from spamd */
    for(len=0; len<bufsiz-1; len++) {
	if(flags&SPAMC_USE_SSL) {
	  bytesread = ssl_timeout_read (ssl, buf+len, 1);
	} else {
	  bytesread = fd_timeout_read (sock, buf+len, 1);
	}

        if(buf[len]=='\n') {
            buf[len]='\0';
	    if (len > 0 && buf[len-1] == '\r') {
		len--;
		buf[len]='\0';
	    }
	    *lenp = len;
	    return EX_OK;
	}

        if(bytesread<=0){
	    failureval = EX_IOERR; goto failure;
        }
    }

    syslog(LOG_ERR, "spamd responded with line of %d bytes, dying", len);
    failureval = EX_TOOBIG;

failure:
    return failureval;
}

/*
 * May  7 2003 jm: using %f is bad where LC_NUMERIC is "," in the locale.
 * work around using our own locale-independent float-parser code.
 */
static float
_locale_safe_string_to_float (char *buf, int siz)
{
  int is_neg;
  char *cp, *dot;
  int divider;
  float ret, postdot;

  buf[siz-1] = '\0';	/* ensure termination */

  /* ok, let's illustrate using "100.033" as an example... */
  
  is_neg = 0;
  if (*buf == '-') { is_neg = 1; }

  ret = (float) (strtol (buf, &dot, 10));
  if (dot == NULL) { return 0.0; }
  if (dot != NULL && *dot != '.') { return ret; }

  /* ex: ret == 100.0 */

  cp = (dot + 1);
  postdot = (float) (strtol (cp, NULL, 10));
  if (postdot == 0.0) { return ret; }

  /* ex: postdot == 33.0, cp="033" */

  /* now count the number of decimal places and figure out what power of 10 to use */
  divider = 1;
  while (*cp != '\0') {
    divider *= 10; cp++;
  }

  /* ex:
   * cp="033", divider=1
   * cp="33", divider=10
   * cp="3", divider=100
   * cp="", divider=1000
   */

  if (is_neg) {
    ret -= (postdot / ((float) divider));
  } else {
    ret += (postdot / ((float) divider));
  }
  /* ex: ret == 100.033, tada! ... hopefully */

  return ret;
}

static int
_handle_spamd_header (struct message *m, int flags, char *buf, int len)
{
    char is_spam[6];
    char s_str[21], t_str[21];

    UNUSED_VARIABLE(len);

    /* Feb 12 2003 jm: actually, I think sccanf is working fine here ;)
     * let's stick with it for this parser.
     * May  7 2003 jm: using %f is bad where LC_NUMERIC is "," in the locale.
     * work around using our own locale-independent float-parser code.
     */
    if (sscanf(buf, "Spam: %5s ; %20s / %20s", is_spam, s_str, t_str) == 3)
    {
	m->score = _locale_safe_string_to_float (s_str, 20);
	m->threshold = _locale_safe_string_to_float (t_str, 20);

	/* Format is "Spam: x; y / x" */
	m->is_spam=strcasecmp("true", is_spam) == 0 ? EX_ISSPAM: EX_NOTSPAM;

	if(flags&SPAMC_CHECK_ONLY) {
	    m->out_len=snprintf (m->out, m->max_len+EXPANSION_ALLOWANCE,
			"%.1f/%.1f\n", m->score, m->threshold);
	}
	else if ((flags & SPAMC_REPORT_IFSPAM && m->is_spam == EX_ISSPAM)
		|| (flags & SPAMC_REPORT))
	{
	    m->out_len=snprintf (m->out, m->max_len+EXPANSION_ALLOWANCE,
			"%.1f/%.1f\n", m->score, m->threshold);
	}
	return EX_OK;

    } else if(sscanf(buf, "Content-length: %d", &m->content_length) == 1) {
	if (m->content_length < 0) {
	    syslog(LOG_ERR, "spamd responded with bad Content-length '%s'", buf);
	    return EX_PROTOCOL;
	}
	return EX_OK;
    }

    syslog(LOG_ERR, "spamd responded with bad header '%s'", buf);
    return EX_PROTOCOL;
}

int message_filter(struct transport *tp, const char *username,
                int flags, struct message *m)
{
    char buf[8192];
    int bufsiz = (sizeof(buf) / sizeof(*buf)) - 4; /* bit of breathing room */
    int len, i;
    int sock = -1;
    int rc;
    char versbuf[20];
    float version;
    int response;
    int failureval;
    SSL_CTX* ctx;
    SSL* ssl;
    SSL_METHOD *meth;

    if (flags&SPAMC_USE_SSL) {
#ifdef SPAMC_SSL
      SSLeay_add_ssl_algorithms();
      meth = SSLv2_client_method();
      SSL_load_error_strings();
      ctx = SSL_CTX_new(meth);
#else
      UNUSED_VARIABLE(ssl);
      UNUSED_VARIABLE(meth);
      UNUSED_VARIABLE(ctx);
      syslog(LOG_ERR, "spamc not built with SSL support");
      return EX_SOFTWARE;
#endif
    }    

    m->is_spam=EX_TOOBIG;
    if((m->out=malloc(m->max_len+EXPANSION_ALLOWANCE+1))==NULL){
        failureval = EX_OSERR; goto failure;
    }
    m->out_len=0;


    /* Build spamd protocol header */
    if(flags & SPAMC_CHECK_ONLY) 
      len=snprintf(buf, bufsiz, "CHECK %s\r\n", PROTOCOL_VERSION);
    else if(flags & SPAMC_REPORT_IFSPAM)
      len=snprintf(buf, bufsiz, "REPORT_IFSPAM %s\r\n", PROTOCOL_VERSION);
    else if(flags & SPAMC_REPORT) 
      len=snprintf(buf, bufsiz, "REPORT %s\r\n", PROTOCOL_VERSION);
    else if(flags & SPAMC_SYMBOLS) 
      len=snprintf(buf, bufsiz, "SYMBOLS %s\r\n", PROTOCOL_VERSION);
    else
      len=snprintf(buf, bufsiz, "PROCESS %s\r\n", PROTOCOL_VERSION);

    if(len<0 || len >= bufsiz){ free(m->out); m->out=m->msg; m->out_len=m->msg_len; return EX_OSERR; }
    if(username!=NULL){
        len+=i=snprintf(buf+len, bufsiz-len, "User: %s\r\n", username);
        if(i<0 || len >= bufsiz){ free(m->out); m->out=m->msg; m->out_len=m->msg_len; return EX_OSERR; }
    }
    len+=i=snprintf(buf+len, bufsiz-len, "Content-length: %d\r\n", m->msg_len);
    if(i<0 || len >= bufsiz){ free(m->out); m->out=m->msg; m->out_len=m->msg_len; return EX_OSERR; }
    len+=i=snprintf(buf+len, bufsiz-len, "\r\n");
    if(i<0 || len >= bufsiz){ free(m->out); m->out=m->msg; m->out_len=m->msg_len; return EX_OSERR; }

    libspamc_timeout = m->timeout;

    if ( tp->socketpath )
        rc = try_to_connect_unix(tp, &sock);
    else
        rc = try_to_connect_tcp(tp, &sock);

    if ( rc != EX_OK )
    {
        free(m->out); m->out=m->msg; m->out_len=m->msg_len;
        return i;
    }

    if(flags&SPAMC_USE_SSL) {
#ifdef SPAMC_SSL
      ssl = SSL_new(ctx);
      SSL_set_fd(ssl, sock);
      SSL_connect(ssl);
#endif    
    }

    /* Send to spamd */
    if(flags&SPAMC_USE_SSL) {
#ifdef SPAMC_SSL
      SSL_write(ssl, buf, len);
      SSL_write(ssl, m->msg, m->msg_len);
#endif
    } else {
      full_write(sock, buf, len);
      full_write(sock, m->msg, m->msg_len);
      shutdown(sock, SHUT_WR);
    }

    /* ok, now read and parse it.  SPAMD/1.2 line first... */
    failureval = _spamc_read_full_line (m, flags, ssl, sock, buf, &len, bufsiz);
    if (failureval != EX_OK) { goto failure; }

    if(sscanf(buf, "SPAMD/%s %d %*s", versbuf, &response)!=2) {
	syslog(LOG_ERR, "spamd responded with bad string '%s'", buf);
	failureval = EX_PROTOCOL; goto failure;
    }

    version = _locale_safe_string_to_float (versbuf, 20);
    if (version < 1.0) {
	syslog(LOG_ERR, "spamd responded with bad version string '%s'", versbuf);
	failureval = EX_PROTOCOL; goto failure;
    }

    m->score = 0;
    m->threshold = 0;
    m->is_spam = EX_TOOBIG;
    while (1) {
	failureval = _spamc_read_full_line (m, flags, ssl, sock, buf, &len, bufsiz);
	if (failureval != EX_OK) { goto failure; }

	if (len == 0 && buf[0] == '\0') {
	    break;	/* end of headers */
	}

	if (_handle_spamd_header(m, flags, buf, len) < 0) {
	    failureval = EX_PROTOCOL; goto failure;
	}
    }

    len = 0;		/* overwrite those headers */

    if (flags&SPAMC_CHECK_ONLY) {
	close(sock); sock = -1;
	if (m->is_spam == EX_TOOBIG) {
	      /* We should have gotten headers back... Damnit. */
	      failureval = EX_PROTOCOL; goto failure;
	}
	return EX_OK;
    }
    else {
	if (m->content_length < 0) {
	    /* should have got a length too. */
	    failureval = EX_PROTOCOL; goto failure;
	}

	/* have we already got something in the buffer (e.g. REPORT and
         * REPORT_IFSPAM both create a line from the "Spam:" hdr)?  If
	 * so, add the size of that so our sanity check passes.
	 */
	if (m->out_len > 0) {
	    m->content_length += m->out_len;
	}

	if (flags&SPAMC_USE_SSL) {
	  len = full_read_ssl (ssl, (unsigned char *) m->out+m->out_len,
		     m->max_len+EXPANSION_ALLOWANCE+1-m->out_len,
		     m->max_len+EXPANSION_ALLOWANCE+1-m->out_len);
	} else{
	  len = full_read (sock, m->out+m->out_len,
		     m->max_len+EXPANSION_ALLOWANCE+1-m->out_len,
		     m->max_len+EXPANSION_ALLOWANCE+1-m->out_len);
	}


	if(len+m->out_len>m->max_len+EXPANSION_ALLOWANCE){
	    failureval = EX_TOOBIG; goto failure;
	}
	m->out_len+=len;

	shutdown(sock, SHUT_RD);
	close(sock); sock = -1;
    }
    libspamc_timeout = 0;

    if(m->out_len!=m->content_length) {
        syslog(LOG_ERR, "failed sanity check, %d bytes claimed, %d bytes seen",
				m->content_length, m->out_len);
	failureval = EX_PROTOCOL; goto failure;
    }

    return EX_OK;

failure:
    free(m->out); m->out=m->msg; m->out_len=m->msg_len;
    if (sock != -1) {
      close(sock);
    }
    libspamc_timeout = 0;

    if(flags&SPAMC_USE_SSL) {
#ifdef SPAMC_SSL
      SSL_free(ssl);
      SSL_CTX_free(ctx);
#endif
    }
    return failureval;
}


int message_process(struct transport *trans, char *username, int max_size, int in_fd, int out_fd, const int flags){
    int ret;
    struct message m;

    m.type=MESSAGE_NONE;

    m.max_len=max_size;
    ret=message_read(in_fd, flags, &m);
    if(ret!=EX_OK) goto FAIL;
    ret=message_filter(trans, username, flags, &m);
    if(ret!=EX_OK) goto FAIL;
    if(message_write(out_fd, &m)<0) goto FAIL;
    if(m.is_spam!=EX_TOOBIG) {
       message_cleanup(&m);
       return m.is_spam;
    }
    message_cleanup(&m);
    return ret;

FAIL:
   if(flags&SPAMC_CHECK_ONLY){
       full_write(out_fd, "0/0\n", 4);
       message_cleanup(&m);
       return EX_NOTSPAM;
   } else {
       message_dump(in_fd, out_fd, &m);
       message_cleanup(&m);
       return ret;
    }
}

void message_cleanup(struct message *m) {
   if (m->out != NULL && m->out != m->raw) free(m->out);
   if (m->raw != NULL) free(m->raw);
   if (m->priv != NULL) free(m->priv);
   clear_message(m);
}

/* Aug 14, 2002 bj: Obsolete! */
int process_message(struct transport *tp, char *username, int max_size, int in_fd, int out_fd, const int my_check_only, const int my_safe_fallback){
    int flags;

    flags=SPAMC_RAW_MODE;
    if(my_check_only) flags|=SPAMC_CHECK_ONLY;
    if(my_safe_fallback) flags|=SPAMC_SAFE_FALLBACK;

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

static void randomize_hosts(struct transport *tp)
{
int     rnum;

	assert(tp != 0);

	if ( tp->nhosts <= 1 ) return;

	rnum = rand() % tp->nhosts;

	while ( rnum-- > 0 )
	{
	struct in_addr  tmp = tp->hosts[0];
	int             i;

		for (i = 1; i < tp->nhosts; i++ )
			tp->hosts[i-1] = tp->hosts[i];

		tp->hosts[i-1] = tmp;
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
struct hostent *hp = 0;
char           **addrp;

	assert(tp != 0);

	switch ( tp->type )
	{
	  case TRANSPORT_UNIX:
		assert(tp->socketpath != 0);
		return EX_OK;

	  case TRANSPORT_LOCALHOST:
		tp->hosts[0].s_addr = inet_addr("127.0.0.1");
		tp->nhosts          = 1;
		return EX_OK;

	  case TRANSPORT_TCP:
		if (NULL == (hp = gethostbyname(tp->hostname)))
		{
		int	origherr = h_errno;  /* take a copy before syslog() */

			syslog (LOG_ERR, "gethostbyname(%s) failed: h_errno=%d",
				tp->hostname, origherr);
			switch (origherr)
			{
			  case HOST_NOT_FOUND:
			  case NO_ADDRESS:
			  case NO_RECOVERY:
				return EX_NOHOST;
			  case TRY_AGAIN:
				return EX_TEMPFAIL;
			  default:
				return EX_OSERR;
			}
		}

		/*--------------------------------------------------------
		 * If we have no hosts at all, or if they are some other
	 	 * kind of address family besides IPv4, then we really
		 * just have no hosts at all.
		 */
		if ( hp->h_addr_list[0] == 0 )
		{
			/* no hosts in this list */
			return EX_NOHOST;
		}

		if ( hp->h_length   != sizeof tp->hosts[0]
		  || hp->h_addrtype != AF_INET )
		{
			/* FAIL - bad size/protocol/family? */
			return EX_NOHOST;
		}

		/*--------------------------------------------------------
		 * Copy all the IP addresses into our private structure.
		 * This gets them out of the resolver's static area and
		 * means we won't ever walk all over the list with other
		 * calls.
		 *
		 * ==TODO: check that we don't copy more than we have room for
		 */
		tp->nhosts = 0;

		for (addrp = hp->h_addr_list; *addrp; addrp++)
		{
			memcpy(&tp->hosts[tp->nhosts], *addrp,
				sizeof tp->hosts[0]);

			tp->nhosts++;
		}

		/*--------------------------------------------------------
		 * QUASI-LOAD-BALANCING
		 *
		 * If the user wants to do quasi load balancing, "rotate"
		 * the list by a random amount based on the current time.
		 * This may later be truncated to a single item. This is
		 * meaningful only if we have more than one host.
		 */
		if ( (flags & SPAMC_RANDOMIZE_HOSTS)  &&  tp->nhosts > 1 )
		{
			randomize_hosts(tp);
		}

		/*--------------------------------------------------------
		 * If the user wants no fallback, simply truncate the host
		 * list to just one - this pretends that this is the extent
		 * of our connection list - then it's not a special case.
		 */
		if ( !(flags & SPAMC_SAFE_FALLBACK)  &&  tp->nhosts > 1 )
		{
			/* truncating list */
			tp->nhosts = 1;
		}
	}
	return EX_OK;
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

static void
_test_locale_safe_string_to_float_val (float input) {
  char inputstr[99], cmpbuf1[99], cmpbuf2[99];
  float output;

  snprintf (inputstr, 99, "%f", input);
  output = _locale_safe_string_to_float (inputstr, 99);
  if (input == output) { return; }

  /* could be a rounding error.  print as string and compare those */
  snprintf (cmpbuf1, 98, "%f", input);
  snprintf (cmpbuf2, 98, "%f", output);
  if (!strcmp (cmpbuf1, cmpbuf2)) { return; }

  printf ("FAIL: input=%f != output=%f\n", input, output);
}

static void
unit_test_locale_safe_string_to_float (void) {
  float statictestset[] = {	/* will try both +ve and -ve */
	0.1, 0.01, 0.001, 0.0001, 0.00001, 0.000001,
	9.1, 9.91, 9.991, 9.9991, 9.99991, 9.999991,
	0.0		/* end of set constant */
  };
  float num;
  int i;

  printf ("starting unit_test_locale_safe_string_to_float\n");
  /* tests of precision */
  for (i = 0; statictestset[i] != 0.0; i++) {
    _test_locale_safe_string_to_float_val (statictestset[i]);
    _test_locale_safe_string_to_float_val (-statictestset[i]);
    _test_locale_safe_string_to_float_val (1-statictestset[i]);
    _test_locale_safe_string_to_float_val (1+statictestset[i]);
  }
  /* now exhaustive, in steps of 0.01 */
  for (num = -1000.0; num < 1000.0; num += 0.01) {
    _test_locale_safe_string_to_float_val (num);
  }
  printf ("finished unit_test_locale_safe_string_to_float\n");
}

void
do_libspamc_unit_tests (void) {
  unit_test_locale_safe_string_to_float();
  exit (0);
}

#endif /* LIBSPAMC_UNIT_TESTS */
