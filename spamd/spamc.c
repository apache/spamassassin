/*
 * This code is copyright 2001 by Craig Hughes
 * It is licensed for use with SpamAssassin according to the terms of the Perl Artistic License
 * The text of this license is included in the SpamAssassin distribution in the file named "License"
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
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

/* SunOS 4.1.4 patch from Tom Lipkis <tal@pss.com> */
#if (defined(__sun__) && defined(__sparc__) && !defined(__svr4__)) /* SunOS */ \
     || (defined(__sgi))  /* IRIX */ \
     || (defined(__osf__)) /* Digital UNIX */ \
     || (defined(hpux) || defined(__hpux)) /* HPUX */

extern int optind;
extern char *optarg;
#endif

/* safe fallback defaults to on now - CRH */
int flags = SPAMC_RAW_MODE | SPAMC_SAFE_FALLBACK;

/* Aug 14, 2002 bj: global to hold -e command */
char **exec_argv;

static int timeout = 600;

void print_usage(void)
{
  printf("Usage: spamc [-d host] [-p port] [-B] [-c] [-f] [-h] [-x] [-t tout] [-e command [args]]\n");
  printf("-B: BSMTP mode - expect input to be a single SMTP-formatted message\n");
  printf("-c: check only - print score/threshold and exit code set to 0 if message is not spam, 1 if spam\n");
  printf("-d host: specify host to connect to  [default: localhost]\n");
  printf("-e command [args]: Command to output to instead of stdout. MUST BE THE LAST OPTION.\n");
  printf("-f: fallback safely - in case of comms error, dump original message unchanges instead of setting exitcode\n");
  printf("-h: print this help message\n");
  printf("-p port: specify port for connection [default: 783]\n");
  printf("-s size: specify max message size, any bigger and it will be returned w/out processing [default: 250k]\n");
  printf("-S: use SSL to talk to spamd\n");
  printf("-u username: specify the username for spamd to process this message under\n");
  printf("-x: don't fallback safely - in a comms error, exit with an error code\n");
  printf("-t: timeout in seconds to read from spamd. 0 disables. [default: 600]\n");
}

int
read_args(int argc, char **argv, char **hostname, int *port, int *max_size, char **username)
{
  int opt, i, j;

  while(-1 != (opt = getopt(argc,argv,"-Bcd:e:fhp:t:s:u:xS")))
  {
    switch(opt)
    {
    case 'B':
      {
        flags = (flags & ~SPAMC_MODE_MASK) | SPAMC_BSMTP_MODE;
        break;
      }
    case 'c':
      {
        flags |= SPAMC_CHECK_ONLY;
	break;
      }
    case 'd':
      {
	*hostname = optarg;	/* fix the ptr to point to this string */
	break;
      }
    case 'e':
      {
        if((exec_argv=malloc(sizeof(*exec_argv)*(argc-optind+2)))==NULL)
            return EX_OSERR;
        for(i=0, j=optind-1; j<argc; i++, j++){
            exec_argv[i]=argv[j];
        }
        exec_argv[i]=NULL;
        return EX_OK;
      }
    case 'p':
      {
	*port = atoi(optarg);
	break;
      }
    case 'f':
      {
        flags |= SPAMC_SAFE_FALLBACK;
	break;
      }
    case 'x':
      {
	flags &= (~SPAMC_SAFE_FALLBACK);
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
    case 'S':
      {
	flags |= SPAMC_USE_SSL;
	break;
      }
    case 't':
      {
	timeout = atoi(optarg);
	break;
      }
    case '?': {
      syslog (LOG_ERR, "invalid usage");
      /* NOTE: falls through to usage case below... */
    }
    case 'h':
    case 1:
      {
	print_usage();
	exit(EX_USAGE);
      }
    }
  }
  return EX_OK;
}	

void get_output_fd(int *fd){
    int fds[2];
    pid_t pid;
    
    if(*fd!=-1) return;
    if(exec_argv==NULL){
        *fd=STDOUT_FILENO;
        return;
    }
    if(pipe(fds)){
        syslog(LOG_ERR, "pipe creation failed: %m");
        exit(EX_OSERR);
    }
    pid=fork();
    if(pid<0){
        syslog(LOG_ERR, "fork failed: %m");
        exit(EX_OSERR);
    } else if(pid==0){
        /* child process */
        /* Normally you'd expect the parent process here, however that would
         * screw up an invoker waiting on the death of the parent. So instead,
         * we fork a child to feed the data and have the parent exec the new
         * prog */
        close(fds[0]);
        *fd=fds[1];
        return;
    }
    /* parent process (see above) */
    close(fds[1]);
    if(dup2(fds[0], STDIN_FILENO)){
        syslog(LOG_ERR, "redirection of stdin failed: %m");
        exit(EX_OSERR);
    }
    close(fds[0]); /* no point in leaving extra fds lying around */
    execv(exec_argv[0], exec_argv);
    syslog(LOG_ERR, "exec failed: %m");
    exit(EX_OSERR);
}

int main(int argc, char **argv){
  int port = 783;
  int max_size = 250*1024;
  char *hostname = (char *) "127.0.0.1";
  char *username = NULL;
  struct passwd *curr_user;
  struct hostent hent;
  int ret;
  struct message m;
  int out_fd;

  openlog ("spamc", LOG_CONS|LOG_PID, LOG_MAIL);
  signal (SIGPIPE, SIG_IGN);

  read_args(argc,argv,&hostname,&port,&max_size,&username);

  if(NULL == username)
  {
    curr_user = getpwuid(geteuid());
    if (curr_user == NULL) {
      perror ("getpwuid failed");
            if(flags&SPAMC_CHECK_ONLY) { printf("0/0\n"); return EX_NOTSPAM; } else { return EX_OSERR; }
    }
    username = curr_user->pw_name;
  }

    out_fd=-1;
    m.type=MESSAGE_NONE;

    ret=lookup_host_for_failover (hostname, &hent);
    if(ret!=EX_OK) goto FAIL;

    m.max_len = max_size;
    m.timeout = timeout;

    ret=message_read(STDIN_FILENO, flags, &m);
    if(ret!=EX_OK) goto FAIL;
    ret=message_filter_with_failover(&hent, port, username, flags, &m);
    if(ret!=EX_OK) goto FAIL;
    get_output_fd(&out_fd);
    if(message_write(out_fd, &m)<0) goto FAIL;
    if(m.is_spam!=EX_TOOBIG) return m.is_spam;
    return ret;

FAIL:
    get_output_fd(&out_fd);
    if(flags&SPAMC_CHECK_ONLY){
        full_write(out_fd, (unsigned char *) "0/0\n", 4);
        return EX_NOTSPAM;
    } else {
        message_dump(STDIN_FILENO, out_fd, &m);
        if (ret == EX_TOOBIG) {
          return 0;
        } else if (flags & SPAMC_SAFE_FALLBACK) {
	  return EX_OK;
	} else {
	  return ret;
	}
    }
}
