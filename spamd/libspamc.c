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
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#ifdef SPAMC_SSL
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
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

#define MAX_CONNECT_RETRIES 3
#define CONNECT_RETRY_SLEEP 1

/* RedHat 5.2 doesn't define Shutdown 2nd Parameter Constants */
/* KAM 12-4-01 */
#ifndef HAVE_SHUT_RD
#define SHUT_RD (0)   /* No more receptions.  */
#define SHUT_WR (1)   /* No more transmissions.  */
#define SHUT_RDWR (2) /* No more receptions or transmissions.  */
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

static const int DO_CONNECT_DEBUG_SYSLOGS = 1;

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
static const char *PROTOCOL_VERSION="SPAMC/1.2";

int libspamc_timeout = 0;

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

  int i; char dbgbuf[2048]; int dbgbuflen = 0;		// DBG

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
      dbgbuflen += snprintf (dbgbuf+dbgbuflen, 2047-dbgbuflen,
	          "[%d %lx: %d.%d.%d.%d]",
		  hostnum, hent->h_addr_list[hostnum],
		  hent->h_addr_list[hostnum][0],
		  hent->h_addr_list[hostnum][1],
		  hent->h_addr_list[hostnum][2],
		  hent->h_addr_list[hostnum][3]);

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

      dbgbuflen += snprintf (dbgbuf+dbgbuflen, 2047-dbgbuflen,
		  "[%d: %d.%d.%d.%d] ", sizeof (struct in_addr),
		  hent->h_addr_list[hostnum][0],
		  hent->h_addr_list[hostnum][1],
		  hent->h_addr_list[hostnum][2],
		  hent->h_addr_list[hostnum][3]);

      memcpy ((void *) &(inaddrlist[hostnum]),
		(void *) hent->h_addr_list[hostnum],
		sizeof (struct in_addr));
    }

    if (DO_CONNECT_DEBUG_SYSLOGS) {
      syslog (LOG_DEBUG, "dbg: %d %s", hostnum, dbgbuf); dbgbuflen = 0;
    }
  }


  if (DO_CONNECT_DEBUG_SYSLOGS) {
    for (i = 0; i < hostnum; i++) {
      syslog (LOG_DEBUG, "dbg: host addr %d/%d = %lx at %lx",
		  i, hostnum, inaddrlist[i].s_addr, &(inaddrlist[i]));
    }
  }

  hent = NULL; /* cannot use hent after this point, syslog() may overwrite it */

  if (DO_CONNECT_DEBUG_SYSLOGS) { syslog (LOG_DEBUG, "dbg: socket"); }

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
  
  if (DO_CONNECT_DEBUG_SYSLOGS) { syslog (LOG_DEBUG, "dbg: setsockopt"); }

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
    if (DO_CONNECT_DEBUG_SYSLOGS) {
      syslog (LOG_DEBUG, "dbg: connect() to spamd %d", numloops);
    }
    if (argaddr != NULL) {
      addr = (struct sockaddr_in *) argaddr;     /* use the one provided */
      if (DO_CONNECT_DEBUG_SYSLOGS) {
	syslog (LOG_DEBUG, "dbg: using argaddr");
      }

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

      if (DO_CONNECT_DEBUG_SYSLOGS) {
	syslog (LOG_DEBUG, "dbg: cpy addr %d/%d at %lx",
		numloops%hostnum, hostnum, &(inaddrlist[numloops % hostnum]));
      }

      memcpy (&addrbuf.sin_addr, &(inaddrlist[numloops % hostnum]),
                        sizeof(addrbuf.sin_addr));
      addr = &addrbuf;

      if (DO_CONNECT_DEBUG_SYSLOGS) {
	syslog (LOG_DEBUG, "dbg: conn addr %d/%d = %lx",
	    numloops%hostnum, hostnum, addrbuf.sin_addr.s_addr);
      }

    }

    syslog (LOG_DEBUG, "dbg: connect() to spamd at %s",
		inet_ntoa(((struct sockaddr_in *)addr)->sin_addr));
    status = connect(mysock,(const struct sockaddr *) addr, sizeof(*addr));
    if (DO_CONNECT_DEBUG_SYSLOGS) {
      syslog (LOG_DEBUG, "dbg: connect() to spamd at %s done",
	  inet_ntoa(((struct sockaddr_in *)addr)->sin_addr));
    }

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
}

static int message_read_raw(int fd, struct message *m){
    clear_message(m);
    if((m->raw=malloc(m->max_len+1))==NULL) return EX_OSERR;
    m->raw_len=full_read(fd, (unsigned char *) m->raw, m->max_len+1, m->max_len+1);
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
    m->raw_len=full_read(fd, (unsigned char *) m->raw, m->max_len+1, m->max_len+1);
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

    if(m->is_spam==EX_ISSPAM || m->is_spam==EX_NOTSPAM){
        return full_write(fd, (unsigned char *) m->out, m->out_len);
    }

    switch(m->type){
      case MESSAGE_NONE:
        syslog(LOG_ERR, "Cannot write this message, it's MESSAGE_NONE!\n");
        return -1;

      case MESSAGE_ERROR:
        return full_write(fd, (unsigned char *) m->raw, m->raw_len);

      case MESSAGE_RAW:
        return full_write(fd, (unsigned char *) m->out, m->out_len);

      case MESSAGE_BSMTP:
        total=full_write(fd, (unsigned char *) m->pre, m->pre_len);
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
            total+=full_write(fd, (unsigned char *) buffer, j);
        }
        return total+full_write(fd, (unsigned char *) m->post, m->post_len);

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
    while((bytes=full_read(in_fd, (unsigned char *) buf, 8192, 8192))>0){
        if (bytes!=full_write(out_fd, (unsigned char *) buf, bytes)) {
            syslog(LOG_ERR, "oops! message_dump of %d returned different", bytes);
        }
    }
}

static int _message_filter(const struct sockaddr *addr,
                const struct hostent *hent, int hent_port, char *username,
                int flags, struct message *m)
{
    char buf[8192], is_spam[6];
    int bufsiz = (sizeof(buf) / sizeof(*buf)) - 4; /* bit of breathing room */
    int len, expected_len, i, header_read=0;
    int sock;
    float version;
    int response;
    int failureval;
#ifdef SPAMC_SSL
    SSL_CTX* ctx;
    SSL* ssl;
    SSL_METHOD *meth;

    if(flags&SPAMC_USE_SSL){	
      SSLeay_add_ssl_algorithms();
      meth = SSLv2_client_method();
      SSL_load_error_strings();
      ctx = SSL_CTX_new(meth);
    }    
#endif

    m->is_spam=EX_TOOBIG;
    if((m->out=malloc(m->max_len+EXPANSION_ALLOWANCE+1))==NULL){
        return EX_OSERR;
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

    if((i=try_to_connect(addr, (struct hostent *) hent,
			hent_port, &sock)) != EX_OK)
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
      full_write(sock, (unsigned char *) buf, len);
      full_write(sock, (unsigned char *) m->msg, m->msg_len);
      shutdown(sock, SHUT_WR);
    }

    /* Now, read from spamd */
    for(len=0; len<bufsiz; len++) {
	if(flags&SPAMC_USE_SSL) {
#ifdef SPAMC_SSL
	  i=timeout_read(SSL_read, ssl, buf+len, 1);
#endif
	} else {
	  i=timeout_read(read, sock, buf+len, 1);
	}

        if(i<0){
	    failureval = EX_IOERR; goto failure;
        }
        if(i==0){
            /* Read to end of message! Must be a version <1.0 server */
            if(len<100){
                /* Nope, communication error */
		failureval = EX_IOERR; goto failure;
            }
            break;
        }
        if(buf[len]=='\n'){
            buf[len]='\0';
            if(sscanf(buf, "SPAMD/%f %d %*s", &version, &response)!=2){
                syslog(LOG_ERR, "spamd responded with bad string '%s'", buf);
		failureval = EX_PROTOCOL; goto failure;
            }
            header_read=-1;
            break;
        }
    }
    if(!header_read){
        /* No header, so it must be a version <1.0 server */
        memcpy(m->out, buf, len);
        m->out_len=len;
    } else {
        /* Handle different versioned headers */
        if(version-1.0>0.01){
            for(len=0; len<bufsiz; len++){
#ifdef SPAMC_SSL
	      if(flags&SPAMC_USE_SSL){
		i=timeout_read(SSL_read, ssl, buf+len, 1);
	      } else{
#endif
		i=timeout_read(read, sock, buf+len, 1);
#ifdef SPAMC_SSL
	      }
#endif
                if(i<=0){
		    failureval = (i<0)?EX_IOERR:EX_PROTOCOL; goto failure;
                }
                if(buf[len]=='\n'){
                    buf[len]='\0';
                    if(flags&SPAMC_CHECK_ONLY){
                        /* Check only or report mode, better be "Spam: x; y / x" */
                        i=sscanf(buf, "Spam: %5s ; %f / %f", is_spam, &m->score, &m->threshold);
                        
                        if(i!=3){
                            free(m->out); m->out=m->msg; m->out_len=m->msg_len;
                            return EX_PROTOCOL;
                        }
                        m->out_len=snprintf(m->out, m->max_len+EXPANSION_ALLOWANCE, "%.1f/%.1f\n", m->score, m->threshold);
                        m->is_spam=strcasecmp("true", is_spam)?EX_NOTSPAM:EX_ISSPAM;

                        close(sock);
                        return EX_OK;
                    } else {
                        /* Not check-only, better be Content-length */
                        if(sscanf(buf, "Content-length: %d", &expected_len)!=1){
			    failureval = EX_PROTOCOL;
			    goto failure;
                        }
                    }

                    /* Should be end of headers now */
		    if(flags&SPAMC_USE_SSL){
#ifdef SPAMC_SSL
		      i=timeout_read(SSL_read,ssl, buf, 2);
#endif
		    } else{
		      i=full_read (sock, (unsigned char *) buf, 2, 2);
		    }

                    if(i!=2 || buf[0]!='\r' || buf[1]!='\n'){
                        /* Nope, bail. */
			failureval = EX_PROTOCOL; goto failure;
                    }

                    break;
                }
            }
        }
    }

    if(flags&SPAMC_CHECK_ONLY){
        /* We should have gotten headers back... Damnit. */
	failureval = EX_PROTOCOL; goto failure;
    }

    if(flags&SPAMC_USE_SSL){
#ifdef SPAMC_SSL
      len=timeout_read(SSL_read,ssl, m->out+m->out_len,
		 m->max_len+EXPANSION_ALLOWANCE+1-m->out_len);
#endif
    } else{
      len=full_read(sock, (unsigned char *) m->out+m->out_len,
		 m->max_len+EXPANSION_ALLOWANCE+1-m->out_len,
		 m->max_len+EXPANSION_ALLOWANCE+1-m->out_len);
    }

    if(len+m->out_len>m->max_len+EXPANSION_ALLOWANCE){
	failureval = EX_TOOBIG; goto failure;
    }
    m->out_len+=len;

    shutdown(sock, SHUT_RD);
    close(sock);
    libspamc_timeout = 0;

    if(m->out_len!=expected_len){
        syslog(LOG_ERR, "failed sanity check, %d bytes claimed, %d bytes seen", expected_len, m->out_len);
	failureval = EX_PROTOCOL; goto failure;
    }

    return EX_OK;

failure:
    free(m->out); m->out=m->msg; m->out_len=m->msg_len;
    close(sock);
    libspamc_timeout = 0;

#ifdef SPAMC_SSL
    if(flags&SPAMC_USE_SSL){
      SSL_free(ssl);
      SSL_CTX_free(ctx);
    }
#endif
    return failureval;
}

static int _lookup_host(const char *hostname, struct hostent *out_hent)
{
    struct hostent *hent = NULL;
    int origherr;

    /* no need to try using inet_addr(), gethostbyname() will do that */

    if (NULL == (hent = gethostbyname(hostname))) {
        origherr = h_errno;	/* take a copy before syslog() */
        syslog (LOG_ERR, "gethostbyname(%s) failed: h_errno=%d",
                hostname, origherr);
        switch(origherr)
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

    memcpy (out_hent, hent, sizeof(struct hostent));

    return EX_OK;
}

int message_process(const char *hostname, int port, char *username, int max_size, int in_fd, int out_fd, const int flags){
    struct hostent hent;
    int ret;
    struct message m;

    m.type=MESSAGE_NONE;

    ret=lookup_host_for_failover(hostname, &hent);
    if(ret!=EX_OK) goto FAIL;
    
    m.max_len=max_size;
    ret=message_read(in_fd, flags, &m);
    if(ret!=EX_OK) goto FAIL;
    ret=message_filter_with_failover(&hent, port, username, flags, &m);
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
       full_write(out_fd, (unsigned char *) "0/0\n", 4);
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
   clear_message(m);
}

/* Aug 14, 2002 bj: Obsolete! */
int process_message(const char *hostname, int port, char *username, int max_size, int in_fd, int out_fd, const int my_check_only, const int my_safe_fallback){
    int flags;

    flags=SPAMC_RAW_MODE;
    if(my_check_only) flags|=SPAMC_CHECK_ONLY;
    if(my_safe_fallback) flags|=SPAMC_SAFE_FALLBACK;

    return message_process(hostname, port, username, max_size, in_fd, out_fd, flags);
}

/* public APIs, which call into the static code and enforce sockaddr-OR-hostent
 * conventions */

int lookup_host(const char *hostname, int port, struct sockaddr *out_addr)
{
  struct sockaddr_in *addr = (struct sockaddr_in *)out_addr;
  struct hostent hent;
  int ret;

  memset(&out_addr, 0, sizeof(out_addr));
  addr->sin_family=AF_INET;
  addr->sin_port=htons(port);
  ret = _lookup_host(hostname, &hent);
  memcpy (&(addr->sin_addr), hent.h_addr, sizeof(addr->sin_addr));
  return ret;
}

int lookup_host_for_failover(const char *hostname, struct hostent *hent) {
  return _lookup_host(hostname, hent);
}

int message_filter(const struct sockaddr *addr, char *username, int flags,
                struct message *m)
{ return _message_filter (addr, NULL, 0, username, flags, m); }

int message_filter_with_failover (const struct hostent *hent, int port,
                char *username, int flags, struct message *m)
{ return _message_filter (NULL, hent, port, username, flags, m); }

