/*
 * This code is copyright 2001 by Craig Hughes
 * It is licensed for use with SpamAssassin according to the terms of the Perl Artistic License
 * The text of this license is included in the SpamAssassin distribution in the file named "License"
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <syslog.h>
#include <sysexits.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>

#ifndef INADDR_NONE
#define       INADDR_NONE             ((in_addr_t) 0xffffffff)
#endif

/* jm: turned off for now, it should not be necessary. */
#undef USE_TCP_NODELAY

void print_usage(void)
{
  printf("Usage: spamc [-d host] [-p port] [-h]\n");
  printf("-d host: specify host to connect to  [default: localhost]\n");
  printf("-p port: specify port for connection [default: 22874]\n");
  printf("-h: print this help message\n");
}

int send_message(int in,int out)
{
  size_t bytes;
  char buf[8192];

  bytes = snprintf(buf,8192,"PROCESS SPAMC/1.0\r\n");

  do
  {
    write(out,buf,bytes);
  } while((bytes=read(in,buf,8192)) > 0);

  shutdown(out,SHUT_WR);

  return EX_OK;
}

int read_message(int in, int out)
{
  size_t bytes;
  int flag=0;
  char buf[8192];
  float version; int response=EX_OK;

  /* ch: Just call me Mr. Livingontheedge ;) fixed your bytes+1 kludge below too */
  for(bytes=0;bytes<8192;bytes++)
  {
    if(read(in,&buf[bytes],1) == 0) /* read header one byte at a time */
    {
      /* Read to end of message!  Must be because this is version <1.0 server */
      write(out,buf,bytes); /* so write out the message */
      break; /* if we break here, the while loop below will never be entered and we'll return properly */
    }
    if('\n' == buf[bytes])
    {
      buf[bytes] = '\0';	/* terminate the string */
      if(2 != sscanf(buf,"SPAMD/%f %d %*s",&version,&response))
      {
	syslog (LOG_ERR, "spamd responded with bad string '%s'", buf);
	exit(EX_PROTOCOL);
      }
      flag = -1; /* Set flag to show we found a header */
      break;
    }
  }
	
  if(!flag)
  {
    /* We never received a header, so it's a long message with version <1.0 server */
    write(out,buf,bytes); /* so write out the message so far */
    /* Now we'll fall into the while loop if there's more message left. */
  }

  if(EX_OK == response)
  {
    while((bytes=read(in,buf,8192)) > 0)
    {
      write(out,buf,bytes);
    }
  }

  shutdown(in,SHUT_RD);

  return response;
}

int
try_to_connect (const struct sockaddr *addr, int *sockptr)
{
  int value;
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
  return 0;
}

int process_message(const char *hostname, int port)
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
	exit(EX_NOHOST);
      case TRY_AGAIN:
	exit(EX_TEMPFAIL);
      }
    }

    memcpy (&addr.sin_addr, hent->h_addr, sizeof(addr.sin_addr));
  }

  exstatus = try_to_connect ((const struct sockaddr *) &addr, &mysock);
  if (0 == exstatus) {
    exstatus = send_message(STDIN_FILENO,mysock);
    if (0 == exstatus) {
      exstatus = read_message(mysock,STDOUT_FILENO);
    }
  }

  return exstatus;	/* return the last failure code */
}

void read_args(int argc, char **argv, char **hostname, int *port)
{
  int opt;

  while(-1 != (opt = getopt(argc,argv,"d:p:h")))
  {
    switch(opt)
    {
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
  int port = 22874;
  char *hostname = "localhost";

  srand(time(NULL));
  openlog ("spamc", LOG_CONS|LOG_PID, LOG_MAIL);

  read_args(argc,argv,&hostname,&port);
    
  return process_message(hostname,port);
}

  
  
