/*
 * This code is copyright 2001 by Craig Hughes
 * It is licensed for use with SpamAssassin according to the terms of the Perl Artistic License
 * The text of this license is included in the SpamAssassin distribution in the file named "License"
 */

#include "libspamc.h"

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
#if (defined(__sun__) && defined(__sparc__) && !defined(__svr4__)) /* SunOS */ \
     || (defined(__sgi))  /* IRIX */ \
     || (defined(__osf__)) /* Digital UNIX */ \
     || (defined(hpux) || defined(__hpux)) /* HPUX */
# ifndef h_errno
# define h_errno errno
# endif

# ifndef EX__MAX
# define EX__MAX 77
# endif

extern char *optarg;
#endif

/* don't def in_addr_t for Digital UNIX or IRIX, they have it in netinet/in.h */
#if (defined(__sun__) && defined(__sparc__) && !defined(__svr4__)) /* SunOS */ \
     || (defined(hpux) || defined(__hpux)) /* HPUX */
typedef unsigned long	in_addr_t;	/* base type for internet address */
#endif

#ifndef INADDR_NONE
#define       INADDR_NONE             ((in_addr_t) 0xffffffff)
#endif

int SAFE_FALLBACK=-1; /* default to on now - CRH */

int CHECK_ONLY=0;

static const int ESC_PASSTHROUGHRAW = EX__MAX+666;

/* set EXPANSION_ALLOWANCE to something more than might be
   added to a message in X-headers and the report template */
static const int EXPANSION_ALLOWANCE = 16384;

/* set NUM_CHECK_BYTES to number of bytes that have to match at beginning and end
   of the data streams before and after processing by spamd */
static const int NUM_CHECK_BYTES = 32;

/* Set the protocol version that this spamc speaks */
static const char *PROTOCOL_VERSION="SPAMC/1.2";

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

void
read_args(int argc, char **argv, char **hostname, int *port, int *max_size, char **username)
{
  int opt;

  while(-1 != (opt = getopt(argc,argv,"cd:fhp:t:s:u:")))
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

int
main(int argc,char **argv)
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

  return process_message(hostname, port, username, max_size, STDIN_FILENO,
                STDOUT_FILENO, CHECK_ONLY, SAFE_FALLBACK);
}
