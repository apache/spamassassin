/*
 * This code is copyright (c) 2002-2003 by John Peacock
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAXOPTS 16

int main()
{
    int  pfds[2];
    int  childpid;
    char *socket = getenv("SPAMDSOCK" ); /* Unix Domain Socket path  */
    char *host   = getenv("SPAMDHOST" ); /* remote spamd host name   */
    char *port   = getenv("SPAMDPORT" ); /* remote spamd host port   */
    char *ssl    = getenv("SPAMDSSL"  ); /* use ssl for spamc/spamd  */
    char *limit  = getenv("SPAMDLIMIT"); /* message size limit       */
    char *user   = getenv("SPAMDUSER" ); /* spamc user configuration */
    char *options[MAXOPTS];
    int  opt = 0;

    /* create the array of options */
    options[opt++] = "spamc"; /* zeroth argument */
    if ( socket ) {
        options[opt++] = "-U";
        options[opt++] = socket;
    }
    if ( host ) {
        options[opt++] = "-d";
        options[opt++] = host;
    }
    if ( port ) {
        options[opt++] = "-p";
        options[opt++] = port;
    }
    if ( ssl ) {
        options[opt++] = "-S";
    }
    if ( limit ) {
        options[opt++] = "-s";
        options[opt++] = limit;
    }
    if ( user ) {
        options[opt++] = "-u";
        options[opt++] = user;
    }
    options[opt] = NULL;

    if ( pipe(pfds) == -1 ) {
        perror("Failed to create pipe; quitting\n");
        exit(1);
    }

    if ( ( childpid = fork() ) == -1 ) {
        perror("Failed to fork; quitting\n");
        exit(2);
    }

    if ( childpid == 0 ) {
        close(1);       /* close normal stdout */
        dup(pfds[1]);   /* make stdout same as pfds[1] */
        close(pfds[0]); /* we don't need this */
        execvp("spamc", options);
    } else {
        close(0);       /* close normal stdin */
        dup(pfds[0]);   /* make stdin same as pfds[0] */
        close(pfds[1]); /* we don't need this */
        execlp("qmail-queue", "qmail-queue", NULL);
    }
}

