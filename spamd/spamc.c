/*
 * This code is copyright 2001 by Craig Hughes
 * It is licensed for use with SpamAssassin according to the terms of the Perl Artistic License
 * The text of this license is included in the SpamAssassin distribution in the file named "License"
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <syslog.h>
#include <sysexits.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pwd.h>

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
#if defined(__sun__) && defined(__sparc__) && !defined(__svr4__)
# ifndef EX__MAX
# define EX__MAX 77
extern char *optarg;
typedef unsigned long	in_addr_t;	/* base type for internet address */
# endif
#endif

#ifndef INADDR_NONE
#define       INADDR_NONE             ((in_addr_t) 0xffffffff)
#endif

/* jm: turned off for now, it should not be necessary. */
#undef USE_TCP_NODELAY

int SAFE_FALLBACK=-1; /* default to on now - CRH */

int CHECK_ONLY=0;

const int EX_ISSPAM = 1;
const int EX_NOTSPAM = 0;

const int ESC_PASSTHROUGHRAW = EX__MAX+666;

/* set EXPANSION_ALLOWANCE to something more than might be
   added to a message in X-headers and the report template */
const int EXPANSION_ALLOWANCE = 16384;

/* set NUM_CHECK_BYTES to number of bytes that have to match at beginning and end
   of the data streams before and after processing by spamd */
const int NUM_CHECK_BYTES = 32;

/* Set the protocol version that this spamc speaks */
const char *PROTOCOL_VERSION="SPAMC/1.2";

void print_usage(void)
{
  printf("Usage: spamc [-d host] [-p port] [-c] [-f] [-h]\n");
  printf("-c: check only - print score/threshold and exit code set to 0 if message is not spam, 1 if spam\n");
  printf("-d host: specify host to connect to  [default: localhost]\n");
  printf("-f: fallback safely - in case of comms error, dump original message unchanges instead of setting exitcode\n");
  printf("-h: print this help message\n");
  printf("-p port: specify port for connection [default: 783]\n");
  printf("-s size: specify max message size, any bigger and it will be returned w/out processing [default: 250k]\n");
  printf("-u username: specify the username for spamd to process this message under\n");
}


/* Dec 13 2001 jm: added safe full-read and full-write functions.  These
 * can cope with networks etc., where a write or read may not read all
 * the data that's there, in one call.
 */
int
full_read (int fd, unsigned char *buf, int min, int len)
{
  int total;
  int thistime;

  for (total = 0; total < min; ) {
    thistime = read (fd, buf+total, len-total);

    if (thistime < 0) {
      return -1;
    } else if (thistime == 0) {
      // EOF, but we didn't read the minimum.  return what we've read
      // so far and next read (if there is one) will return 0.
      return total;
    }

    total += thistime;
  }
  return total;
}

int
full_write (int fd, const unsigned char *buf, int len)
{
  int total;
  int thistime;

  for (total = 0; total < len; ) {
    thistime = write (fd, buf+total, len-total);

    if (thistime < 0) {
      return thistime;        // always an error for writes
    }
    total += thistime;
  }
  return total;
}


int dump_message(int in,int out)
{
  size_t bytes;
  char buf[8192];

  while((bytes=full_read(in, buf, 8192, 8192)) > 0)
  {
    if(bytes != full_write (out,buf,bytes))
    {
      return EX_IOERR;
    }
  }

  return (0==bytes)?EX_OK:EX_IOERR;
}

/* This guy has to be global so that if comms fails, we can passthru the message raw */
char *msg_buf = NULL;
/* Keep track of how much is stored in this buffer in case of failure later */
int amount_read = 0;

int send_message(int in,int out,char *username, int max_size)
{
  char *header_buf = NULL;
  size_t bytes,bytes2;
  int ret = EX_OK;

  if(NULL == (header_buf = malloc(1024))) return EX_OSERR;

  /* Ok, now we'll read the message into the buffer up to the limit */
  /* Hmm, wonder if this'll just work ;) */
  if((bytes = full_read (in, msg_buf, max_size+1024, max_size+1024)) > max_size)
  {
    /* Message is too big, so return so we can dump the message back out */
    bytes2 = snprintf(header_buf,1024,"SKIP %s\r\nUser: %s\r\n\r\n",
			PROTOCOL_VERSION, username);
    full_write (out,header_buf,bytes2);
    ret = ESC_PASSTHROUGHRAW;
  } else
  {
    /* First send header */
    if(CHECK_ONLY)
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
    full_write (out,msg_buf,bytes);
  }

  free(header_buf);

  amount_read = bytes;
  shutdown(out,SHUT_WR);
  return ret;
}

int read_message(int in, int out, int max_size)
{
  size_t bytes;
  int header_read=0;
  char buf[8192];
  char is_spam[5];
  int score,threshold;
  float version;
  int response=EX_OK;
  char* out_buf;
  size_t out_index=0;
  int expected_length=0;

  out_buf = malloc(max_size+EXPANSION_ALLOWANCE);

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
	  if(CHECK_ONLY)
	  {
	    /* Ok, found a header line, it better be "Spam: x; y / x" */
	    if(3 != sscanf(buf,"Spam: %5s ; %d / %d",is_spam,&score,&threshold))
	    {
	      response = EX_PROTOCOL; break;
	    }

	    printf("%d/%d\n",score,threshold);

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

  if(!CHECK_ONLY && EX_OK == response)
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

  if (!CHECK_ONLY && EX_OK == response)
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

int
try_to_connect (const struct sockaddr *addr, int *sockptr)
{
#ifdef USE_TCP_NODELAY
  int value;
#endif
  int mysock;
  int origerr;

  if(-1 == (mysock = socket(PF_INET,SOCK_STREAM,0)))
  {
    origerr = errno;	/* take a copy before syslog() */
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

  if(connect(mysock,(const struct sockaddr *) addr, sizeof(*addr)) < 0)
  {
    origerr = errno;	/* take a copy before syslog() */
    syslog (LOG_ERR, "connect() to spamd failed: %m");
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

  *sockptr = mysock;

  return EX_OK;
}

int process_message(const char *hostname, int port, char *username, int max_size)
{
  int exstatus;
  int mysock;
  struct sockaddr_in addr;
  struct hostent *hent;
  int origherr;

  memset (&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

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
	if(CHECK_ONLY) { printf("0/0\n"); return EX_NOTSPAM; } else { return EX_NOHOST; }
      case TRY_AGAIN:
	if(CHECK_ONLY) { printf("0/0\n"); return EX_NOTSPAM; } else { return EX_TEMPFAIL; }
      }
    }

    memcpy (&addr.sin_addr, hent->h_addr, sizeof(addr.sin_addr));
  }

  exstatus = try_to_connect ((const struct sockaddr *) &addr, &mysock);
  if (EX_OK == exstatus)
  {
    if(NULL == (msg_buf = malloc(max_size+1024)))
    {
      if(CHECK_ONLY) { printf("0/0\n"); return EX_NOTSPAM; } else { return EX_OSERR; }
    }

    exstatus = send_message(STDIN_FILENO,mysock,username,max_size);
    if (EX_OK == exstatus)
    {
      exstatus = read_message(mysock,STDOUT_FILENO,max_size);
    }

    if(!CHECK_ONLY && (ESC_PASSTHROUGHRAW == exstatus || (SAFE_FALLBACK && EX_OK != exstatus)))
    {
      /* Message was too big or corrupted, so dump the buffer then bail */
      full_write (STDOUT_FILENO,msg_buf,amount_read);
      dump_message(STDIN_FILENO,STDOUT_FILENO);
      exstatus = EX_OK;
    }
    free(msg_buf);
  }
  else if(CHECK_ONLY) /* If connect failed, but CHECK_ONLY then print "0/0" and return 0 */
  {
    printf("0/0\n");
    exstatus = EX_NOTSPAM;
  }
  else if(SAFE_FALLBACK) /* If connection failed but SAFE_FALLBACK set then dump original message */
  {
    if(amount_read > 0)
    {
      full_write(STDOUT_FILENO,msg_buf,amount_read);
    }
    return dump_message(STDIN_FILENO,STDOUT_FILENO);
  }

  return exstatus;	/* return the last failure code */
}

void read_args(int argc, char **argv, char **hostname, int *port, int *max_size, char **username)
{
  int opt;

  while(-1 != (opt = getopt(argc,argv,"cd:fhp:s:u:")))
  {
    switch(opt)
    {
    case 'c':
      {
	CHECK_ONLY = -1;
	break;
      }
    case 'd':
      {
	*hostname = optarg;	/* fix the ptr to point to this string */
	break;
      }
    case 'p':
      {
	*port = atoi(optarg);
	break;
      }
    case 'f':
      {
	SAFE_FALLBACK = -1;
	break;
      }
    case 'u':
      {
	*username = optarg;
	break;
      }
    case 's':
      {
	*max_size = atoi(optarg);
	break;
      }
    case '?': {
      syslog (LOG_ERR, "invalid usage");
      /* NOTE: falls through to usage case below... */
    }
    case 'h':
      {
	print_usage();
	exit(EX_USAGE);
      }
    }
  }
}	

int main(int argc,char **argv)
{
  int port = 783;
  int max_size = 250*1024;
  char *hostname = "127.0.0.1";
  char *username = NULL;
  struct passwd *curr_user;

  openlog ("spamc", LOG_CONS|LOG_PID, LOG_MAIL);
  signal (SIGPIPE, SIG_IGN);

  read_args(argc,argv,&hostname,&port,&max_size,&username);

  if(NULL == username)
  {
    curr_user = getpwuid(getuid());
    if (curr_user == NULL) {
      perror ("getpwuid failed");
      if(CHECK_ONLY) { printf("0/0\n"); return EX_NOTSPAM; } else { return EX_OSERR; }
    }
    username = curr_user->pw_name;
  }

  return process_message(hostname,port,username,max_size);
}
