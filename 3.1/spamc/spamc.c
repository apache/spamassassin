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

#include "config.h"
#include "version.h"
#include "libspamc.h"
#include "utils.h"
#include "spamc.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <process.h>
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

#ifdef SPAMC_SSL
#include <openssl/crypto.h>
#ifndef OPENSSL_VERSION_TEXT
#define OPENSSL_VERSION_TEXT "OpenSSL"
#endif
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
     || (defined(__CYGWIN__))	/* CygWin, Win32 */

extern int optind;
extern char *optarg;

#endif

#ifdef _WIN32
#include "replace/getopt.h"
char *__progname = "spamc";
#endif


/* safe fallback defaults to on now - CRH */
int flags = SPAMC_RAW_MODE | SPAMC_SAFE_FALLBACK;

/* global to control whether we should exit(0)/exit(1) on ham/spam */
int use_exit_code = 0;

/* Aug 14, 2002 bj: global to hold -e command */
char **exec_argv;

static int timeout = 600;


void
check_malloc (void *ptr)
{
    if(ptr == NULL) {
        libspamc_log(flags, LOG_ERR,
                      "Error allocating memory using malloc\n");
        /* this is really quite serious.  we can't do anything. die */
        exit(EX_OSERR);
    }
}

void
print_version(void)
{
    printf("%s version %s\n", "SpamAssassin Client", VERSION_STRING);
#ifdef SPAMC_SSL
    printf("  compiled with SSL support (%s)\n", OPENSSL_VERSION_TEXT);
#endif
}

static void
usg(char *str)
{
    printf("%s", str);
}

void
print_usage(void)
{
    print_version();
    usg("\n");
    usg("Usage: spamc [options] [-e command [args]] < message\n");
    usg("\n");
    usg("Options:\n");

    usg("  -d host[,host2]     Specify one or more hosts to connect to.\n"
        "                      [default: localhost]\n");
    usg("  -H                  Randomize IP addresses for the looked-up\n"
        "                      hostname.\n");
    usg("  -p port             Specify port for connection to spamd.\n"
        "                      [default: 783]\n");
#ifdef SPAMC_SSL
    usg("  -S                  Use SSL to talk to spamd.\n");
#endif
#ifndef _WIN32
    usg("  -U path             Connect to spamd via UNIX domain sockets.\n");
#endif
    usg("  -F path             Use this configuration file.\n");
    usg("  -t timeout          Timeout in seconds for communications to\n"
        "                      spamd. [default: 600]\n");
    usg("  -s size             Specify maximum message size, in bytes.\n"
        "                      [default: 250k]\n");
    usg("  -u username         User for spamd to process this message under.\n"
        "                      [default: current user]\n");

    usg("  -L learntype        Learn message as spam, ham or forget to\n"
	"                      forget or unlearn the message.\n");

    usg("  -C reporttype       Report message to collaborative filtering\n"
	"                      databases.  Report type should be report for\n"
	"                      spam or revoke for ham.\n");
	
    usg("  -B                  Assume input is a single BSMTP-formatted\n"
        "                      message.\n");
    
    usg("  -c                  Just print the summary line and set an exit\n"
        "                      code.\n");
    usg("  -y                  Just print the names of the tests hit.\n");
    usg("  -r                  Print full report for messages identified as\n"
        "                      spam.\n");
    usg("  -R                  Print full report for all messages.\n");
    usg("  -E                  Filter as normal, and set an exit code.\n");
    
    usg("  -x                  Don't fallback safely.\n");
    usg("  -l                  Log errors and warnings to stderr.\n");
#ifndef _WIN32
    usg("  -e command [args]   Pipe the output to the given command instead\n"
        "                      of stdout. This must be the last option.\n");
#endif
    usg("  -h                  Print this help message and exit.\n");
    usg("  -V                  Print spamc version and exit.\n");
    usg("  -f                  (Now default, ignored.)\n");
    usg("\n");
}

/**
 * Does the command line parsing for argv[].
 *
 * Returns EX_OK or EX_TEMPFAIL if successful. EX_TEMPFAIL is a kludge for
 * the cases where we want in main to return immediately; we can't exit()
 * because on Windows WSACleanup() needs to be called.
 */
int
read_args(int argc, char **argv,
          int *max_size, char **username, int *extratype,
          struct transport *ptrn)
{
#ifndef _WIN32
    const char *opts = "-BcrRd:e:fyp:t:s:u:L:C:xSHU:ElhVF:";
#else
    const char *opts = "-BcrRd:fyp:t:s:u:L:C:xSHElhVF:";
#endif
    int opt;
    int ret = EX_OK;
    
    while ((opt = getopt(argc, argv, opts)) != -1)
    {
        switch (opt)
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
                ptrn->type = TRANSPORT_TCP;
                ptrn->hostname = optarg;        /* fix the ptr to point to this string */
                break;
            }
#ifndef _WIN32
            case 'e':
            {
                int i, j;
                
                /* Allocate memory for the necessary pointers needed to 
                 * store the remaining arguments.
                 */
                exec_argv = malloc(sizeof(*exec_argv) * (argc - optind + 2));
                if (exec_argv == NULL) {
                    return EX_OSERR;
                }
                
                for (i = 0, j = optind - 1; j < argc; i++, j++) {
                    exec_argv[i] = argv[j];
                }
                exec_argv[i] = NULL;
                
                return EX_OK;
            }
#endif
            case 'f':
            {
                /* obsolete, backwards compat */
                break;
            }
            case 'l':
            {
                flags |= SPAMC_LOG_TO_STDERR;
                break;
            }
            case 'H':
            {
                flags |= SPAMC_RANDOMIZE_HOSTS;
                break;
            }
            case 'p':
            {
                ptrn->port = (unsigned short)atoi(optarg);
                break;
            }
            case 'r':
            {
                flags |= SPAMC_REPORT_IFSPAM;
                break;
            }
            case 'E':
            {
                use_exit_code = 1;
                break;
            }
            case 'R':
            {
                flags |= SPAMC_REPORT;
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
            case 'u':
            {
                *username = optarg;
                break;
            }
            case 'L':
	    {
	        flags |= SPAMC_LEARN;
		if (strcmp(optarg,"spam") == 0) {
		    *extratype = 0;
		}
	        else if (strcmp(optarg,"ham") == 0) {
		    *extratype = 1;
		}
		else if (strcmp(optarg,"forget") == 0) {
		    *extratype = 2;
		}
		else {
		    libspamc_log(flags, LOG_ERR, "Please specifiy a legal learn type");
		    ret = EX_USAGE;
		}
		break;
	    }
        case 'C':
	    {
	        flags |= SPAMC_REPORT_MSG;
		if (strcmp(optarg,"report") == 0) {
		    *extratype = 0;
		}
                else if (strcmp(optarg,"revoke") == 0) {
		    *extratype = 1;
		}
		else {
		    libspamc_log(flags, LOG_ERR, "Please specifiy a legal report type");
		    ret = EX_USAGE;
		}
		break;
	    }
#ifndef _WIN32
            case 'U':
            {
                ptrn->type = TRANSPORT_UNIX;
                ptrn->socketpath = optarg;
                break;
            }
#endif
            case 'x':
            {
                flags &= (~SPAMC_SAFE_FALLBACK);
                break;
            }
            case 'y':
            {
                flags |= SPAMC_SYMBOLS;
                break;
            }
            
            case '?':
            case ':':
            {
                libspamc_log(flags, LOG_ERR, "invalid usage");
                ret = EX_USAGE;
                /* FALLTHROUGH */
            }
            case 'h':
            {
                print_usage();
                if (ret == EX_OK)
                    ret = EX_TEMPFAIL;
                return(ret);
            }
            case 'V':
            {
                print_version();
                return(EX_TEMPFAIL);
            }
        }
    }

    /* learning action has to block some parameters */
    if (flags & SPAMC_LEARN) {
        if (flags & SPAMC_CHECK_ONLY) {
	    libspamc_log(flags, LOG_ERR, "Learning excludes check only");
	    ret = EX_USAGE;
	}
	if (flags & SPAMC_REPORT_IFSPAM) {
	    libspamc_log(flags, LOG_ERR, "Learning excludes report if spam");
	    ret = EX_USAGE;
	}
	if (flags & SPAMC_REPORT) {
	    libspamc_log(flags, LOG_ERR, "Learning excludes report");
	    ret = EX_USAGE;
	}
	if (flags & SPAMC_SYMBOLS) {
	    libspamc_log(flags, LOG_ERR, "Learning excludes symbols");
	    ret = EX_USAGE;
	}
	if (flags & SPAMC_REPORT_MSG) {
	    libspamc_log(flags, LOG_ERR, "Learning excludes reporting to collaborative filtering databases");
	    ret = EX_USAGE;
	}
    }
    return ret;
}

/* combine_args() :: parses spamc.conf for options, and combines those
 * with options passed via command line
 *
 * lines beginning with # or blank lines are ignored
 *
 * returns EX_OK on success, EX_CONFIG on failure
 */
int
combine_args(char *config_file, int argc, char **argv,
	     int *combo_argc, char **combo_argv)
{
    FILE *config;
    char option[100];
    int i, count = 0;
    char *tok = NULL;
    int is_user_defined_p = 1;

    if (config_file == NULL) {
      config_file = CONFIG_FILE;
      is_user_defined_p = 0;
    }

    if((config = fopen(config_file, "r")) == NULL) {
        if (is_user_defined_p == 1) { /* if the config file was user defined we should issue an error */
	    fprintf(stderr,"Failed to open config file: %s\n", config_file);
	}
	return EX_CONFIG;
    }

    while(!(feof(config)) && (fgets(option, 100, config))) {

        count++; /* increment the line counter */

	if(option[0] == '#' || option[0] == '\n') {
	    continue;
        }

	tok = option;
	while((tok = strtok(tok, " ")) != NULL) {
       if(tok[0] == '\n')
          break;
	    for(i=strlen(tok); i>0; i--) {
	        if(tok[i] == '\n')
		    tok[i] = '\0';
	    }
            combo_argv[*combo_argc] = strdup(tok);
            check_malloc(combo_argv[*combo_argc]);
            /* TODO: leaked.  not a big deal since spamc exits quickly */
	    tok = NULL;
	    *combo_argc+=1;
	}
    }

    fclose(config);

    /* note: not starting at 0, that's the command name */
    for(i=1; i<argc; i++) {
        combo_argv[*combo_argc] = strdup(argv[i]);
        check_malloc(combo_argv[*combo_argc]);
        /* TODO: leaked.  not a big deal since spamc exits quickly */
        *combo_argc+=1;
    }
    return EX_OK;
}

void
get_output_fd(int *fd)
{
#ifndef _WIN32
    int pipe_fds[2];
    pid_t pid;
#endif

    if (*fd != -1)
	return;
    
    /* If we aren't told to feed our output to an external app, we simply
     * write to stdout.
     */
    if (exec_argv == NULL) {
	*fd = STDOUT_FILENO;
	return;
    }
    
#ifndef _WIN32
    /* Create a pipe for communication between child and parent. */
    if (pipe(pipe_fds)) {
	libspamc_log(flags, LOG_ERR, "pipe creation failed: %m");
	exit(EX_OSERR);
    }
    
    pid = fork();
    if (pid < 0) {
	libspamc_log(flags, LOG_ERR, "fork failed: %m");
	exit(EX_OSERR);
    }
    else if (pid == 0) {
	/* This is the child process:
	 * Normally you'd expect the parent process here, however that would
	 * screw up an invoker waiting on the death of the parent. So instead,
	 * we fork a child to feed the data and have the parent exec the new
	 * program.
	 */
	close(pipe_fds[0]);
	*fd = pipe_fds[1];
	return;
    }
    
    /* This is the parent process (see above) */
    close(pipe_fds[1]);
    if (dup2(pipe_fds[0], STDIN_FILENO)) {
	libspamc_log(flags, LOG_ERR, "redirection of stdin failed: %m");
	exit(EX_OSERR);
    }
    /* No point in leaving extra fds lying around. */
    close(pipe_fds[0]);
    
    /* Now execute the command specified. */
    execv(exec_argv[0], exec_argv);
    
    /* Whoa, something failed... */
    libspamc_log(flags, LOG_ERR, "exec failed: %m");
#else
    libspamc_log(flags, LOG_CRIT, "THIS MUST NOT HAPPEN AS -e IS NOT SUPPORTED UNDER WINDOWS.");
#endif
    exit(EX_OSERR);
}


/**
 * Determines the username of the uid spamc is running under.
 *
 * If the program's caller didn't identify the user to run as, use the
 * current user for this. Note that we're not talking about UNIX perm-
 * issions, but giving SpamAssassin a username so it can do per-user
 * configuration (whitelists & the like).
 *
 * Allocates memory for the username, returns EX_OK if successful.
 */
int
get_current_user(char **username)
{
#ifndef _WIN32
    struct passwd *curr_user;
#endif

    if (*username != NULL) {
        *username = strdup(*username);
	if (username == NULL)
	    goto fail;
	goto pass;
    }

#ifndef _WIN32
    
    /* Get the passwd information for the effective uid spamc is running
     * under. Setting errno to zero is recommended in the manpage.
     */
    errno = 0;
    curr_user = getpwuid(geteuid());
    if (curr_user == NULL) {
        perror("getpwuid() failed");
        goto fail;
    }
    
    /* Since "curr_user" points to static library data, we don't wish to
     * risk some other part of the system overwriting it, so we copy the 
     * username to our own buffer -- then this won't arise as a problem.
     */
    *username = strdup(curr_user->pw_name);
    if (*username == NULL) {
        goto fail;
    }

#endif

pass:
    return EX_OK;
    
fail:
    /* FIXME: The handling of SPAMC_CHECK_ONLY should probably be moved to 
     *        the end of main()
     */
    if (flags & SPAMC_CHECK_ONLY) {
        printf("0/0\n");
        return EX_NOTSPAM;
    }
    return EX_OSERR;
}


int
main(int argc, char *argv[])
{
    int max_size;
    char *username;
    struct transport trans;
    struct message m;
    int out_fd = -1;
    int result;
    int ret;
    int extratype = 0;
    int islearned = 0;
    int isreported = 0;

    /* these are to hold CLI and config options combined, to be passed
     * to read_args() */
    char *combo_argv[24];
    int combo_argc;

    int i;
    char *config_file = NULL;

    transport_init(&trans);

#ifdef LIBSPAMC_UNIT_TESTS
    /* unit test support; divert execution.  will not return */
    do_libspamc_unit_tests();
#endif

#ifndef _WIN32
    openlog("spamc", LOG_CONS | LOG_PID, LOG_MAIL);
    signal(SIGPIPE, SIG_IGN);
#endif

    /* set some defaults */
    max_size = 250 * 1024;
    username = NULL;
 
    combo_argc = 1;
    combo_argv[0] = strdup(argv[0]);
    check_malloc(combo_argv[0]);
    /* TODO: leaked.  not a big deal since spamc exits quickly */
 
    for(i=0; i<argc; i++) {
       if(strncmp(argv[i], "-F", 2) == 0) {
          config_file = argv[i+1];
          break;
       }
    }
 
    if((combine_args(config_file, argc, argv, &combo_argc, combo_argv)) == EX_OK)
    {
      /* Parse the combined arguments of command line and config file */
      if ((ret = read_args(combo_argc, combo_argv, &max_size, &username, 
 			  &extratype, &trans)) != EX_OK)
      {
        if (ret == EX_TEMPFAIL)
 	 ret = EX_OK;
        goto finish;
      }
    }
    else {
      /* parse only command line arguments (default behaviour) */
      if((ret = read_args(argc, argv, &max_size, &username, 
 			 &extratype, &trans)) != EX_OK)
      {
        if(ret == EX_TEMPFAIL)
 	 ret = EX_OK;
        goto finish;
      }
    }
 
    ret = get_current_user(&username);
    if (ret != EX_OK)
        goto finish;
        
    if ((flags & SPAMC_RANDOMIZE_HOSTS) != 0) {
	/* we don't need strong randomness; this is just so we pick
	 * a random host for loadbalancing.
	 */
	srand(getpid() ^ time(NULL));
    }

    /**********************************************************************
     * SET UP TRANSPORT
     *
     * This takes the user parameters and digs up what it can about how
     * we connect to the spam daemon. Mainly this involves lookup up the
     * hostname and getting the IP addresses to connect to.
     */
    m.type = MESSAGE_NONE;
    m.out = NULL;
    m.outbuf = NULL;
    m.raw = NULL;
    m.priv = NULL;
    m.max_len = max_size;
    m.timeout = timeout;
    m.is_spam = EX_NOHOST;	/* default err code if can't reach the daemon */
#ifdef _WIN32
    setmode(STDIN_FILENO, O_BINARY);
    setmode(STDOUT_FILENO, O_BINARY);
#endif
    ret = transport_setup(&trans, flags);

    if (ret == EX_OK) {

	ret = message_read(STDIN_FILENO, flags, &m);

	if (ret == EX_OK) {

 	    if (flags & SPAMC_LEARN) {
	      int msg_class = 0;
	      unsigned int tellflags = 0;
	      unsigned int didtellflags = 0;

	      if ((extratype == 0) || (extratype == 1)) {
		if (extratype == 0) {
		  msg_class = SPAMC_MESSAGE_CLASS_SPAM;
		}
		else {
		  msg_class = SPAMC_MESSAGE_CLASS_HAM;
		}
		tellflags |= SPAMC_SET_LOCAL;
	      }
	      else {
		tellflags |= SPAMC_REMOVE_LOCAL;
	      }

	      ret = message_tell(&trans, username, flags, &m, msg_class,
				 tellflags, &didtellflags);

	      if (ret == EX_OK) {
		if ((extratype == 0) || (extratype == 1)) {
		  if (didtellflags & SPAMC_SET_LOCAL) {
		    islearned = 1;
		  }
		}
		else {
		  if (didtellflags & SPAMC_REMOVE_LOCAL) {
		    islearned = 1;
		  }
		}
	      }
	    }
 	    else if (flags & SPAMC_REPORT_MSG) {
	      int msg_class = 0;
	      unsigned int tellflags = 0;
	      unsigned int didtellflags = 0;

	      if (extratype == 0) {
		msg_class = SPAMC_MESSAGE_CLASS_SPAM;
		tellflags |= SPAMC_SET_REMOTE;
		tellflags |= SPAMC_SET_LOCAL;
	      }
	      else {
		msg_class = SPAMC_MESSAGE_CLASS_HAM;
		tellflags |= SPAMC_SET_LOCAL;
		tellflags |= SPAMC_REMOVE_REMOTE;
	      }

	      ret = message_tell(&trans, username, flags, &m, msg_class,
				 tellflags, &didtellflags);

	      if (ret == EX_OK) {
		if (extratype == 0) {
		  if (didtellflags & SPAMC_SET_REMOTE) {
		    isreported = 1;
		  }
		}
		else {
		  if (didtellflags & SPAMC_REMOVE_REMOTE) {
		    isreported = 1;
		  }
		}
	      }
	    }
	    else {
	      ret = message_filter(&trans, username, flags, &m);
	    }

	    free(username); username = NULL;
	    
	    if (ret == EX_OK) {

		get_output_fd(&out_fd);

		if (flags & SPAMC_LEARN) {
		    if (islearned == 1) {
  		        printf("Message successfully un/learned\n");
		    }
		    else {
		        printf("Message was already un/learned\n");
		    }
		    message_cleanup(&m);
		    goto finish;
		}
		else if (flags & SPAMC_REPORT_MSG) {
		    if (isreported == 1) {
  		        printf("Message successfully reported/revoked\n");
		    }
		    else {
		        printf("Unable to report/revoke message\n");
		    }
		    message_cleanup(&m);
		    goto finish;
		}
		else if (message_write(out_fd, &m) >= 0) {
		    result = m.is_spam;
		    if ((flags & SPAMC_CHECK_ONLY) && result != EX_TOOBIG) {
		        message_cleanup(&m);
			ret = result;
		    }
		    else {
		        message_cleanup(&m);
			if (use_exit_code && result != EX_TOOBIG) {
			    ret = result;
			}
		    }
		    goto finish;
		}
	    }
	}
    }
    free(username);

/* FAIL: */
    get_output_fd(&out_fd);

    result = m.is_spam;
    if ((flags & SPAMC_CHECK_ONLY) && result != EX_TOOBIG) {
	/* probably, the write to stdout failed; we can still report exit code */
	message_cleanup(&m);
	ret = result;
    }
    else if (flags & SPAMC_CHECK_ONLY || flags & SPAMC_REPORT
	     || flags & SPAMC_REPORT_IFSPAM) {
	full_write(out_fd, 1, "0/0\n", 4);
	message_cleanup(&m);
	ret = EX_NOTSPAM;
    }
    else if (flags & SPAMC_LEARN) {
        message_cleanup(&m);
    }
    else if (flags & SPAMC_SYMBOLS) {
	/* bug 4991: -y should only output a blank line on connection failure */
	full_write(out_fd, 1, "\n", 1);
        message_cleanup(&m);
        if (use_exit_code) {
            ret = result;
        }
	else if (flags & SPAMC_SAFE_FALLBACK) {
	    ret = EX_OK;
	}
    }
    else {
	message_dump(STDIN_FILENO, out_fd, &m);
	message_cleanup(&m);
	if (ret == EX_TOOBIG) {
	    ret = 0;
	}
        else if (use_exit_code) {
            ret = result;
        }
	else if (flags & SPAMC_SAFE_FALLBACK) {
	    ret = EX_OK;
	}
    }
    
finish:
#ifdef _WIN32
    WSACleanup();
#endif
    return ret;
}
