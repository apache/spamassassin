/*
 * This code is copyright 2001 by Craig Hughes
 * It is licensed for use with SpamAssassin according to the terms of the Perl Artistic License
 * The text of this license is included in the SpamAssassin distribution in the file named "License"
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sysexits.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "libspamc.h"

#define MAX_CONNECT_RETRIES 3
#define CONNECT_RETRY_SLEEP 1

/* RedHat 5.2 doesn't define Shutdown 2nd Parameter Constants */
/* KAM 12-4-01 */
#ifndef SHUT_RD
#define SHUT_RD (0)   /* No more receptions.  */
#endif
#ifndef SHUT_WR
#define SHUT_WR (1)   /* No more receptions or transmissions.  */
#endif
#ifndef SHUT_RDWR
#define SHUT_RDWR (2) /* No more receptions or transmissions.  */
#endif

/* SunOS 4.1.4 patch from Tom Lipkis <tal@pss.com> */
#if (defined(__sun__) && defined(__sparc__) && !defined(__svr4__)) /* SunOS */ \
     || (defined(__sgi))  /* IRIX */ \
     || (defined(__osf__)) /* Digital UNIX */ \
     || (defined(hpux) || defined(__hpux)) /* HPUX */
# ifndef h_errno
# define h_errno errno
# endif

extern char *optarg;
#endif

#ifndef INADDR_NONE
# if (defined(__sun__) && defined(__sparc__) && !defined(__svr4__)) /* SunOS */ \
     || (defined(hpux) || defined(__hpux)) /* HPUX */
typedef unsigned long   in_addr_t;      /* base type for internet address */
/* don't define for Digital UNIX or IRIX, they have it in netinet/in.h */
# endif
#define       INADDR_NONE             ((in_addr_t) 0xffffffff)
#endif

/* jm: turned off for now, it should not be necessary. */
#undef USE_TCP_NODELAY

#ifndef EX__MAX
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

/* Jul  4 2002 jm: use a struct to avoid use of globals inside libspamc. */
struct spamc_context {
  int check_only;
  int safe_fallback;
  /* This guy has to be global so that if comms fails, we can passthru the message raw */
  char *msg_buf;
  /* Keep track of how much is stored in this buffer in case of failure later */
  int amount_read;
};

/* Dec 13 2001 jm: added safe full-read and full-write functions.  These
 * can cope with networks etc., where a write or read may not read all
 * the data that's there, in one call.
 */
static int
full_read (int fd, unsigned char *buf, int min, int len)
{
  int total;
  int thistime;

  for (total = 0; total < min; ) {
    thistime = read (fd, buf+total, len-total);

    if (thistime < 0) {
      return -1;
    } else if (thistime == 0) {
      /* EOF, but we didn't read the minimum.  return what we've read
       * so far and next read (if there is one) will return 0. */
      return total;
    }

    total += thistime;
  }
  return total;
}

static int
full_write (int fd, const unsigned char *buf, int len)
{
  int total;
  int thistime;

  for (total = 0; total < len; ) {
    thistime = write (fd, buf+total, len-total);

    if (thistime < 0) {
      return thistime;        /* always an error for writes */
    }
    total += thistime;
  }
  return total;
}


static int dump_message(int in,int out)
{
  size_t bytes;
  unsigned char buf[8192];

  while((bytes=full_read(in, buf, 8192, 8192)) > 0)
  {
    if(bytes != full_write (out,buf,bytes))
    {
      return EX_IOERR;
    }
  }

  return (0==bytes)?EX_OK:EX_IOERR;
}

static int send_message(int in,int out,char *username, int max_size, struct spamc_context *ctx)
{
  char *header_buf = NULL;
  size_t bytes,bytes2;
  int ret = EX_OK;

  if(NULL == (header_buf = malloc(1024))) return EX_OSERR;

  /* Ok, now we'll read the message into the buffer up to the limit */
  /* Hmm, wonder if this'll just work ;) */
  if((bytes = full_read (in, ctx->msg_buf, max_size+1024, max_size+1024)) > max_size)
  {
    /* Message is too big, so return so we can dump the message back out */
    bytes2 = snprintf(header_buf,1024,"SKIP %s\r\nUser: %s\r\n\r\n",
			PROTOCOL_VERSION, username);
    full_write (out,header_buf,bytes2);
    ret = ESC_PASSTHROUGHRAW;
  } else
  {
    /* First send header */
    if(ctx->check_only)
    {
      if(NULL != username)
      {
	bytes2 = snprintf(header_buf,1024,"CHECK %s\r\nUser: %s\r\nContent-length: %d\r\n\r\n",PROTOCOL_VERSION,username,bytes);
      }
      else
      {
	bytes2 = snprintf(header_buf,1024,"CHECK %s\r\nContent-length: %d\r\n\r\n",PROTOCOL_VERSION,bytes);
      }
    }
    else
    {
      if(NULL != username)
      {
	bytes2 = snprintf(header_buf,1024,"PROCESS %s\r\nUser: %s\r\nContent-length: %d\r\n\r\n",PROTOCOL_VERSION,username,bytes);
      }
      else
      {
	bytes2 = snprintf(header_buf,1024,"PROCESS %s\r\nContent-length: %d\r\n\r\n",PROTOCOL_VERSION,bytes);
      }
    }

    full_write (out,header_buf,bytes2);
    full_write (out,ctx->msg_buf,bytes);
  }

  free(header_buf);

  ctx->amount_read = bytes;
  shutdown(out,SHUT_WR);
  return ret;
}

static int read_message(int in, int out, int max_size, struct spamc_context *ctx)
{
  size_t bytes;
  int header_read=0;
  char buf[8192];
  char is_spam[5];
  float score,threshold;
  float version;
  int response=EX_OK;
  unsigned char *out_buf;
  size_t out_index=0;
  int expected_length=0;

  out_buf = (unsigned char *) malloc(max_size+EXPANSION_ALLOWANCE);

  for(bytes=0;bytes<8192;bytes++)
  {
    if(read(in,&buf[bytes],1) == 0) /* read header one byte at a time */
    {
      /* Read to end of message!  Must be because this is version <1.0 server */
      if(bytes < 100)
      {
	/* No, this wasn't a <1.0 server, it's a comms break! */
	response = EX_IOERR;
      }
      /* No need to copy buf to out_buf here, because since header_read is unset that'll happen below */
      break;
    }

    if('\n' == buf[bytes])
    {
      buf[bytes] = '\0';	/* terminate the string */
      if(2 != sscanf(buf,"SPAMD/%f %d %*s",&version,&response))
      {
	syslog (LOG_ERR, "spamd responded with bad string '%s'", buf);
	response = EX_PROTOCOL; break;
      }
      header_read = -1; /* Set flag to show we found a header */
      break;
    }
  }

  if(!header_read && EX_OK == response)
  {
    /* We never received a header, so it's a message with version <1.0 server */
    memcpy(&out_buf[out_index], buf, bytes);
    out_index += bytes;
    /* Now we'll fall into the while loop if there's more message left. */
  }
  else if(header_read && EX_OK == response)
  {
    /* Now if the header was 1.1, we need to pick up the content-length field */
    if(version - 1.0 > 0.01) /* Do this for any version higher than 1.0 [and beware of float rounding errors]*/
    {
      for(bytes=0;bytes<8192;bytes++)
      {
	if(read(in,&buf[bytes],1) == 0) /* keep reading one byte at a time */
	{
	  /* Read to end of message, but shouldn't have! */
	  response = EX_PROTOCOL; break;
	}
	if('\n' == buf[bytes])
	{
	  if(ctx->check_only)
	  {
	    /* Ok, found a header line, it better be "Spam: x; y / x" */
	    if(3 != sscanf(buf,"Spam: %5s ; %f / %f",is_spam,&score,&threshold))
	    {
	      response = EX_PROTOCOL; break;
	    }

	    printf("%.1f/%.1f\n",score,threshold);

	    if(!strcasecmp("true",is_spam)) /* If message is indeed spam */
	    {
	      response = EX_ISSPAM; break;
	    }
	    else
	    {
	      response = EX_NOTSPAM; break;
	    }
	  }
	  else
	  {
	    /* Ok, found a header line, it better be content-length */
	    if(1 != sscanf(buf,"Content-length: %d",&expected_length))
	    {
	      /* Something's wrong, so bail */
	      response = EX_PROTOCOL; break;
	    }
	  }

	  /* Ok, got here means we just read the content-length.  Now suck up the header/body separator.. */
	  if(full_read (in,buf,2,2) != 2 || !('\r' == buf[0] && '\n' == buf[1]))
	  {
	    /* Oops, bail */
	    response = EX_PROTOCOL; break;
	  }

	  /* header done being sucked, let's get out of this inner-for */
	  break;
	} /* if EOL */
      } /* for loop to read subsequent header lines */
    }
  }

  if(!ctx->check_only && EX_OK == response)
  {
    while((bytes=full_read (in,buf,8192, 8192)) > 0)
    {
      if (out_index+bytes >= max_size+EXPANSION_ALLOWANCE)
      {
	syslog (LOG_ERR, "spamd expanded message to more than %d bytes",
		max_size+EXPANSION_ALLOWANCE);
	response = ESC_PASSTHROUGHRAW;
	break;
      }
      memcpy(&out_buf[out_index], buf, bytes);
      out_index += bytes;
    }
  }

  shutdown(in,SHUT_RD);

  if (!ctx->check_only && EX_OK == response)
  {
    /* Check the content length for sanity */
    if(expected_length && expected_length != out_index)
    {
      syslog (LOG_ERR, "failed sanity check, %d bytes claimed, %d bytes seen",
	      expected_length, out_index);
      response = ESC_PASSTHROUGHRAW;
    }
    else
    {
      full_write (out, out_buf, out_index);
    }
  }

  free(out_buf);

  return response;
}

static int
try_to_connect (const struct sockaddr *addr, int *sockptr, struct spamc_context *ctx)
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

int process_message(const char *hostname, int port, char *username, int max_size,
        int in_fd, int out_fd, const int my_check_only, const int my_safe_fallback)
{
  int exstatus;
  int mysock;
  struct sockaddr_in addr;
  struct hostent *hent;
  struct spamc_context ctx;
  int origherr;

  memset (&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  ctx.msg_buf = NULL;
  ctx.amount_read = 0;
  ctx.check_only = my_check_only;
  ctx.safe_fallback = my_safe_fallback;

  /* first, try to mangle it directly into an addr.  This will work
   * for numeric IP addresses, but not for hostnames...
   */
  addr.sin_addr.s_addr = inet_addr (hostname);
  if (addr.sin_addr.s_addr == INADDR_NONE) {
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
	if(ctx.check_only) { printf("0/0\n"); return EX_NOTSPAM; } else { return EX_NOHOST; }
      case TRY_AGAIN:
	if(ctx.check_only) { printf("0/0\n"); return EX_NOTSPAM; } else { return EX_TEMPFAIL; }
      }
    }

    memcpy (&addr.sin_addr, hent->h_addr, sizeof(addr.sin_addr));
  }

  exstatus = try_to_connect ((const struct sockaddr *) &addr, &mysock, &ctx);
  if (EX_OK == exstatus)
  {
    if(NULL == (ctx.msg_buf = malloc(max_size+1024)))
    {
      if(ctx.check_only) { printf("0/0\n"); return EX_NOTSPAM; } else { return EX_OSERR; }
    }

    exstatus = send_message(in_fd,mysock,username,max_size, &ctx);
    if (EX_OK == exstatus)
    {
      exstatus = read_message(mysock,out_fd,max_size, &ctx);
    }

    if(ctx.check_only && ESC_PASSTHROUGHRAW == exstatus)
    {
	printf("0/0\n");
	exstatus = EX_OK;
    }

    if(!ctx.check_only && (ESC_PASSTHROUGHRAW == exstatus || (ctx.safe_fallback && EX_OK != exstatus)))
    {
      /* Message was too big or corrupted, so dump the buffer then bail */
      full_write (out_fd,ctx.msg_buf,ctx.amount_read);
      dump_message(in_fd,out_fd);
      exstatus = EX_OK;
    }
    free(ctx.msg_buf);
  }
  else if(ctx.check_only) /* If connect failed, but check_only then print "0/0" and return 0 */
  {
    printf("0/0\n");
    exstatus = EX_NOTSPAM;
  }
  else if(ctx.safe_fallback) /* If connection failed but safe_fallback set then dump original message */
  {
    if(ctx.amount_read > 0)
    {
      full_write(out_fd,ctx.msg_buf,ctx.amount_read);
    }
    return dump_message(in_fd,out_fd);
  }

  return exstatus;	/* return the last failure code */
}

