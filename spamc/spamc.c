/*
 * This code is copyright 2001 by Craig Hughes
 *
 * <@LICENSE>
 * ====================================================================
 * The Apache Software License, Version 1.1
 * 
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
 * reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 * 
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 * 
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 * 
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 * 
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 * </@LICENSE>
 */

#include "config.h"
#include "libspamc.h"
#include "utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#define syslog(x, y) fprintf(stderr, #y "\n")
#else
#include <syslog.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
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
     || (defined(hpux) || defined(__hpux)) /* HPUX */ \
     || (defined(__CYGWIN__)) /* CygWin, Win32 */

extern int optind;
extern char *optarg;

#endif

#ifdef _WIN32
#include "replace/getopt.h"
char* __progname = "spamc";
#endif


/* safe fallback defaults to on now - CRH */
int flags = SPAMC_RAW_MODE | SPAMC_SAFE_FALLBACK;

/* Aug 14, 2002 bj: global to hold -e command */
char **exec_argv;

static int timeout = 600;

void print_usage(void)
{
  printf("Usage: spamc [options] < message\n\n");
  printf("-B: BSMTP mode - expect input to be a single SMTP-formatted message\n");
  printf("-c: check only - print score/threshold and exit code set to 0 if message is not spam, 1 if spam\n");
  printf("-r: report if spam - print report for spam messages\n");
  printf("-R: report - print report for all messages\n");
  printf("-y: symbols - print only the names of the tests hit\n");
  printf("-d host: specify host to connect to  [default: localhost]\n");
  printf("-e command [args]: Command to output to instead of stdout. MUST BE THE LAST OPTION.\n");
  printf("-f: fallback safely - in case of comms error, dump original message unchanges instead of setting exitcode\n");
  printf("-h: print this help message\n");
  printf("-p port: specify port for connection [default: 783]\n");
  printf("-s size: specify max message size, any bigger and it will be returned w/out processing [default: 250k]\n");
#ifdef SPAMC_SSL
  printf("-S: use SSL to talk to spamd\n");
#endif
  printf("-u username: specify the username for spamd to process this message under\n");
  printf("-x: don't fallback safely - in a comms error, exit with a TEMPFAIL error code\n");
  printf("-t: timeout in seconds to read from spamd. 0 disables. [default: 600]\n\n");
  printf("-H: randomize the IP addresses in the looked-up hostname\n");
  printf("-U path: use UNIX domain socket with path\n");
}

int
read_args(int argc, char **argv, int *max_size, const char **username,
	struct transport *ptrn)
{
  int opt, i, j;

  while(-1 != (opt = getopt(argc,argv,
#ifndef _WIN32
                            "-BcrRd:e:fhyp:t:s:u:xSHU:"
#else
                            "-BcrRd:fhyp:t:s:u:xSH"
#endif
)))
  {
    switch(opt)
    {
    case 'H':
      {
        flags |= SPAMC_RANDOMIZE_HOSTS;
        break;
      }
#ifndef _WIN32
    case 'U':
      {
        ptrn->type       = TRANSPORT_UNIX;
        ptrn->socketpath = optarg;
        break;
      }
#endif
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
    case 'r':
      {
        flags |= SPAMC_REPORT_IFSPAM;
	break;
      }
    case 'R':
      {
        flags |= SPAMC_REPORT;
	break;
      }
    case 'y':
      {
        flags |= SPAMC_SYMBOLS;
	break;
      }
    case 'd':
      {
        ptrn->type     = TRANSPORT_TCP;
	ptrn->hostname = optarg;	/* fix the ptr to point to this string */
	break;
      }
#ifndef _WIN32
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
#endif
    case 'p':
      {
	ptrn->port = atoi(optarg);
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
#ifdef SPAMC_SSL
    case 'S':
      {
	flags |= SPAMC_USE_SSL;
	break;
      }
#endif
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
#ifndef _WIN32
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
#else
    fprintf(stderr, "exec failed: %d\n", errno);
#endif
    exit(EX_OSERR);
}

int main (int argc, char **argv) {
  int max_size = 250*1024;
  const char *username = NULL;
  int ret;
  struct message m;
  int out_fd;
  struct transport trans;
  int result;

  transport_init(&trans);

#ifdef LIBSPAMC_UNIT_TESTS
  /* unit test support; divert execution.  will not return */
  do_libspamc_unit_tests();
#endif

#ifndef _WIN32
  openlog ("spamc", LOG_CONS|LOG_PID, LOG_MAIL);
  signal (SIGPIPE, SIG_IGN);
#endif

  read_args(argc,argv, &max_size, &username, &trans);

  /*--------------------------------------------------------------------
   * DETERMINE USER
   *
   * If the program's caller didn't identify the user to run as, use the
   * current user for this. Note that we're not talking about UNIX perm-
   * issions, but giving SpamAssassin a username so it can do per-user
   * configuration (whitelists & the like).
   *
   * Since "curr_user" points to static library data, we don't wish to risk
   * some other part of the system overwriting it, so we copy the username
   * to our own buffer - then this won't arise as a problem.
   */
 
#ifndef _WIN32
  if(NULL == username)
  {
  static char   userbuf[256];
  struct passwd *curr_user;

    curr_user = getpwuid(geteuid());
    if (curr_user == NULL) {
      perror ("getpwuid failed");
            if(flags&SPAMC_CHECK_ONLY) { printf("0/0\n"); return EX_NOTSPAM; } else { return EX_OSERR; }
    }
    memset(userbuf, 0, sizeof userbuf);
    strncpy(userbuf, curr_user->pw_name, sizeof userbuf - 1);
    userbuf[sizeof userbuf - 1] = '\0';
    username = userbuf;
  }
#endif

  if ((flags & SPAMC_RANDOMIZE_HOSTS) != 0) {
    /* we don't need strong randomness; this is just so we pick
     * a random host for loadbalancing.
     */
    srand(getpid() ^ time(NULL));
  }

  /*--------------------------------------------------------------------
   * SET UP TRANSPORT
   *
   * This takes the user parameters and digs up what it can about how
   * we connect to the spam daemon. Mainly this involves lookup up the
   * hostname and getting the IP addresses to connect to.
   */
  if ( (ret = transport_setup(&trans, flags)) == EX_OK ) {
    out_fd=-1;
    m.type    = MESSAGE_NONE;
    m.max_len = max_size;
    m.timeout = timeout;

    ret=message_read(STDIN_FILENO, flags, &m);
    if(ret==EX_OK) {
    ret=message_filter(&trans, username, flags, &m);
      if(ret==EX_OK) {
    get_output_fd(&out_fd);

        if(message_write(out_fd, &m)>=0) {

    result = m.is_spam;
    if ((flags&SPAMC_CHECK_ONLY) && result != EX_TOOBIG) {
      message_cleanup (&m);
            ret = result;
    } else {
      message_cleanup (&m);
          }
#ifdef _WIN32
          WSACleanup();
#endif
      return ret;
    }
      }
    }
  }

 FAIL:
    get_output_fd(&out_fd);

    result = m.is_spam;
    if((flags&SPAMC_CHECK_ONLY) && result != EX_TOOBIG) {
	/* probably, the write to stdout failed; we can still report exit code */
	message_cleanup (&m);
      ret = result;      
    } else if(flags&SPAMC_CHECK_ONLY || flags&SPAMC_REPORT || flags&SPAMC_REPORT_IFSPAM) {
      full_write(out_fd, 1, "0/0\n", 4);
	message_cleanup (&m);
      ret = EX_NOTSPAM;      
    } else {
        message_dump(STDIN_FILENO, out_fd, &m);
	message_cleanup (&m);
        if (ret == EX_TOOBIG) {
        ret = 0;
        } else if (flags & SPAMC_SAFE_FALLBACK) {
        ret = EX_OK;
	}
    }
#ifdef _WIN32
    WSACleanup();
#endif
    return ret;
}
