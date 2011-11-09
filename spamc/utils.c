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

#ifndef _WIN32
#include <unistd.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#else

#ifdef _MSC_VER
/* ignore MSVC++ warnings that are annoying and hard to remove:
 4115 named type definition in parentheses
 4127 conditional expression is constant
 4514 unreferenced inline function removed
 4996 deprecated "unsafe" functions
 */
#pragma warning( disable : 4115 4127 4514 4996 )
#endif

#include <io.h>
#endif
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include "utils.h"

/* Dec 13 2001 jm: added safe full-read and full-write functions.  These
 * can cope with networks etc., where a write or read may not read all
 * the data that's there, in one call.
 */
/* Aug 14, 2002 bj: EINTR and EAGAIN aren't fatal, are they? */
/* Aug 14, 2002 bj: moved these to utils.c */
/* Jan 13, 2003 ym: added timeout functionality */
/* Apr 24, 2003 sjf: made full_read and full_write void* params */

/* -------------------------------------------------------------------------- */
#ifndef _WIN32
typedef void sigfunc(int);	/* for signal handlers */

sigfunc *sig_catch(int sig, void (*f) (int))
{
    struct sigaction act, oact;
    act.sa_handler = f;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(sig, &act, &oact);
    return oact.sa_handler;
}

static void catch_alrm(int x)
{
    UNUSED_VARIABLE(x);
}
#endif

int timeout_connect (int sockfd, const struct sockaddr *serv_addr, size_t addrlen)
{
    int ret;

#ifndef _WIN32
    sigfunc* sig;

    sig = sig_catch(SIGALRM, catch_alrm);
    if (libspamc_connect_timeout > 0) {
      alarm(libspamc_connect_timeout);
    }
#endif

    ret = connect(sockfd, serv_addr, addrlen);

#ifndef _WIN32
    if (libspamc_connect_timeout > 0) {
      alarm(0);
    }
  
    /* restore old signal handler */
    sig_catch(SIGALRM, sig);
#endif
  
    return ret;
}

int fd_timeout_read(int fd, char fdflag, void *buf, size_t nbytes)
{
    int nred;
    int origerr;
#ifndef _WIN32
    sigfunc *sig;

    sig = sig_catch(SIGALRM, catch_alrm);
    if (libspamc_timeout > 0) {
	alarm(libspamc_timeout);
    }
#endif

    do {
	if (fdflag) {
	    nred = (int)read(fd, buf, nbytes);
	    origerr = errno;
	}
	else {
	    nred = (int)recv(fd, buf, nbytes, 0);
#ifndef _WIN32
	    origerr = errno;
#else
	    origerr = WSAGetLastError();
#endif
	}
    } while (nred < 0 && origerr == EWOULDBLOCK);

#ifndef _WIN32
    if (nred < 0 && origerr == EINTR)
	errno = ETIMEDOUT;

    if (libspamc_timeout > 0) {
	alarm(0);
    }

    /* restore old signal handler */
    sig_catch(SIGALRM, sig);
#endif

    return nred;
}

int ssl_timeout_read(SSL * ssl, void *buf, int nbytes)
{
    int nred;

#ifndef _WIN32
    sigfunc *sig;

    sig = sig_catch(SIGALRM, catch_alrm);
    if (libspamc_timeout > 0) {
	alarm(libspamc_timeout);
    }
#endif

    do {

#ifdef SPAMC_SSL
	nred = SSL_read(ssl, buf, nbytes);
#else
	UNUSED_VARIABLE(ssl);
	UNUSED_VARIABLE(buf);
	UNUSED_VARIABLE(nbytes);
	nred = 0;		/* never used */
#endif

    } while (nred < 0 && errno == EWOULDBLOCK);

#ifndef _WIN32
    if (nred < 0 && errno == EINTR)
	errno = ETIMEDOUT;

    if (libspamc_timeout > 0) {
	alarm(0);
    }

    /* restore old signal handler */
    sig_catch(SIGALRM, sig);
#endif

    return nred;
}

/* -------------------------------------------------------------------------- */

int full_read(int fd, char fdflag, void *vbuf, int min, int len)
{
    unsigned char *buf = (unsigned char *) vbuf;
    int total;
    int thistime;

    for (total = 0; total < min;) {
	thistime = fd_timeout_read(fd, fdflag, buf + total, len - total);

	if (thistime < 0) {
	    if (total >= min) {
		/* error, but we read *some*.  return what we've read
		 * so far and next read (if there is one) will return -1. */
		return total;
	    } else {
		return -1;
	    }
	}
	else if (thistime == 0) {
	    /* EOF, but we didn't read the minimum.  return what we've read
	     * so far and next read (if there is one) will return 0. */
	    return total;
	}

	total += thistime;
    }
    return total;
}

int full_read_ssl(SSL * ssl, unsigned char *buf, int min, int len)
{
    int total;
    int thistime;

    for (total = 0; total < min;) {
	thistime = ssl_timeout_read(ssl, buf + total, len - total);

	if (thistime < 0) {
	    if (total >= min) {
		/* error, but we read *some*.  return what we've read
		 * so far and next read (if there is one) will return -1. */
		return total;
	    } else {
		return -1;
	    }
	}
	else if (thistime == 0) {
	    /* EOF, but we didn't read the minimum.  return what we've read
	     * so far and next read (if there is one) will return 0. */
	    return total;
	}

	total += thistime;
    }
    return total;
}

int full_write(int fd, char fdflag, const void *vbuf, int len)
{
    const char *buf = (const char *) vbuf;
    int total;
    int thistime;
    int origerr;

    for (total = 0; total < len;) {
	if (fdflag) {
	    thistime = write(fd, buf + total, len - total);
	    origerr = errno;
	}
	else {
	    thistime = send(fd, buf + total, len - total, 0);
#ifndef _WIN32
	    origerr = errno;
#else
	    origerr = WSAGetLastError();
#endif
	}
	if (thistime < 0) {
	    if (EINTR == origerr || EWOULDBLOCK == origerr)
		continue;
	    return thistime;	/* always an error for writes */
	}
	total += thistime;
    }
    return total;
}
