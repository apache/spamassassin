/*
 * This code is copyright 2001 by Craig Hughes
 * Portions copyright 2002 by Brad Jorsch
 * It is licensed for use with SpamAssassin according to the terms of the Perl Artistic License
 * The text of this license is included in the SpamAssassin distribution in the file named "License"
 */

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
#include <netdb.h>
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

/* Aug 14, 2002 bj: No more ctx! */
static int
try_to_connect (const struct sockaddr *addr, int *sockptr)
{
#ifdef USE_TCP_NODELAY
  int value;
#endif
  int mysock = -1;
  int status = -1;
  int origerr;
  int numloops;

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
      return EX_SOFTWARE;

    default:
      break;		/* ignored */
    }
  }
#endif

  for (numloops=0; numloops < MAX_CONNECT_RETRIES; numloops++) {
    status = connect(mysock,(const struct sockaddr *) addr, sizeof(*addr));

    if (status < 0)
    {
      origerr = errno;        /* take a copy before syslog() */
      syslog (LOG_ERR, "connect() to spamd at %s failed, retrying (%d/%d): %m",
                        inet_ntoa(((struct sockaddr_in *)addr)->sin_addr),
                        numloops+1, MAX_CONNECT_RETRIES);
      sleep(1);

    } else {
      *sockptr = mysock;
      return EX_OK;
    }
  }
 
  /* failed, even with a few retries */
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
    char buffer[1024];

    if(m->is_spam==EX_ISSPAM || m->is_spam==EX_NOTSPAM){
        return full_write(fd, m->out, m->out_len);
    }

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
            for(j=0; i<m->out_len && j<sizeof(buffer)/sizeof(*buffer)-1; ){
                if(i+1<m->out_len && m->out[i]=='\n' && m->out[i+1]=='.'){
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
        if(bytes!=full_write(out_fd, buf, bytes));
    }
}

int message_filter(const struct sockaddr *addr, char *username, int flags, struct message *m){
    char *buf=NULL, is_spam[6];
    int len, expected_len, i, header_read=0;
    int sock;
    float version;
    int response;

    m->is_spam=EX_TOOBIG;
    if((buf=malloc(8192))==NULL) return EX_OSERR;
    if((m->out=malloc(m->max_len+EXPANSION_ALLOWANCE+1))==NULL){
        free(buf);
        return EX_OSERR;
    }
    m->out_len=0;

    /* Build spamd protocol header */
    len=snprintf(buf, 1024, "%s %s\r\n", (flags&SPAMC_CHECK_ONLY)?"CHECK":"PROCESS", PROTOCOL_VERSION);
    if(len<0 || len>1024){ free(buf); free(m->out); m->out=m->msg; m->out_len=m->msg_len; return EX_OSERR; }
    if(username!=NULL){
        len+=i=snprintf(buf+len, 1024-len, "User: %s\r\n", username);
        if(i<0 || len>1024){ free(buf); free(m->out); m->out=m->msg; m->out_len=m->msg_len; return EX_OSERR; }
    }
    len+=i=snprintf(buf+len, 1024-len, "Content-length: %d\r\n", m->msg_len);
    if(i<0 || len>1024){ free(buf); free(m->out); m->out=m->msg; m->out_len=m->msg_len; return EX_OSERR; }
    len+=i=snprintf(buf+len, 1024-len, "\r\n");
    if(i<0 || len>1024){ free(buf); free(m->out); m->out=m->msg; m->out_len=m->msg_len; return EX_OSERR; }

    if((i=try_to_connect(addr, &sock))!=EX_OK){
        free(buf);
        free(m->out); m->out=m->msg; m->out_len=m->msg_len;
        return i;
    }

    /* Send to spamd */
    full_write(sock, buf, len);
    full_write(sock, m->msg, m->msg_len);
    shutdown(sock, SHUT_WR);

    /* Now, read from spamd */
    for(len=0; len<8192; len++){
        i=read(sock, buf+len, 1);
        if(i<0){
            free(buf);
            free(m->out); m->out=m->msg; m->out_len=m->msg_len;
            close(sock);
            return EX_IOERR;
        }
        if(i==0){
            /* Read to end of message! Must be a version <1.0 server */
            if(len<100){
                /* Nope, communication error */
                free(buf);
                free(m->out); m->out=m->msg; m->out_len=m->msg_len;
                close(sock);
                return EX_IOERR;
            }
            break;
        }
        if(buf[len]=='\n'){
            buf[len]='\0';
            if(sscanf(buf, "SPAMD/%f %d %*s", &version, &response)!=2){
                syslog(LOG_ERR, "spamd responded with bad string '%s'", buf);
                free(buf);
                free(m->out); m->out=m->msg; m->out_len=m->msg_len;
                close(sock);
                return EX_PROTOCOL;
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
            for(len=0; len<8192; len++){
                i=read(sock, buf+len, 1);
                if(i<=0){
                    free(buf);
                    free(m->out); m->out=m->msg; m->out_len=m->msg_len;
                    close(sock);
                    return (i<0)?EX_IOERR:EX_PROTOCOL;
                }
                if(buf[len]=='\n'){
                    buf[len]='\0';
                    if(flags&SPAMC_CHECK_ONLY){
                        /* Check only mode, better be "Spam: x; y / x" */
                        i=sscanf(buf, "Spam: %5s ; %f / %f", is_spam, &m->score, &m->threshold);
                        free(buf);
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
                            free(buf);
                            free(m->out); m->out=m->msg; m->out_len=m->msg_len;
                            close(sock);
                            return EX_PROTOCOL;
                        }
                    }

                    /* Should be end of headers now */
                    if(full_read(sock, buf, 2, 2)!=2 || buf[0]!='\r' || buf[1]!='\n'){
                        /* Nope, bail. */
                        free(buf);
                        free(m->out); m->out=m->msg; m->out_len=m->msg_len;
                        close(sock);
                        return EX_PROTOCOL;
                    }

                    break;
                }
            }
        }
    }
    free(buf);

    if(flags&SPAMC_CHECK_ONLY){
        /* We should have gotten headers back... Damnit. */
        free(m->out); m->out=m->msg; m->out_len=m->msg_len;
        close(sock);
        return EX_PROTOCOL;
    }

    len=full_read(sock, m->out+m->out_len, m->max_len+EXPANSION_ALLOWANCE+1-m->out_len, m->max_len+EXPANSION_ALLOWANCE+1-m->out_len);
    if(len+m->out_len>m->max_len+EXPANSION_ALLOWANCE){
        free(m->out); m->out=m->msg; m->out_len=m->msg_len;
        close(sock);
        return EX_TOOBIG;
    }
    m->out_len+=len;

    shutdown(sock, SHUT_RD);
    close(sock);

    if(m->out_len!=expected_len){
        syslog(LOG_ERR, "failed sanity check, %d bytes claimed, %d bytes seen", expected_len, m->out_len);
        free(m->out); m->out=m->msg; m->out_len=m->msg_len;
        close(sock);
        return EX_PROTOCOL;
    }

    return EX_OK;
}

int lookup_host(const char *hostname, int port, struct sockaddr *a){
    struct sockaddr_in *addr=(struct sockaddr_in *)a;
  struct hostent *hent;
  int origherr;

    memset(&a, 0, sizeof(a));

    addr->sin_family=AF_INET;
    addr->sin_port=htons(port);

    /* first, try to mangle it directly into an addr->  This will work
   * for numeric IP addresses, but not for hostnames...
   */
    addr->sin_addr.s_addr = inet_addr (hostname);
    if (addr->sin_addr.s_addr == INADDR_NONE) {
    /* If that failed, we can use gethostbyname() to resolve it.
     */
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

        memcpy (&addr->sin_addr, hent->h_addr, sizeof(addr->sin_addr));
  }

    return EX_OK;
}

int message_process(const char *hostname, int port, char *username, int max_size, int in_fd, int out_fd, const int flags){
    struct sockaddr addr;
    int ret;
    struct message m;

    m.type=MESSAGE_NONE;

    ret=lookup_host(hostname, port, &addr);
    if(ret!=EX_OK) goto FAIL;
    
    m.max_len=max_size;
    ret=message_read(in_fd, flags, &m);
    if(ret!=EX_OK) goto FAIL;
    ret=message_filter(&addr, username, flags, &m);
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
