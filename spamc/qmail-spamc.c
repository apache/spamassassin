/* <@LICENSE>
 * Copyright 2004 Apache Software Foundation
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAXOPTS 16

int main()
{
    int pfds[2];
    int childpid;
    char *socket = getenv("SPAMDSOCK");	/* Unix Domain Socket path  */
    char *host = getenv("SPAMDHOST");	/* remote spamd host name   */
    char *port = getenv("SPAMDPORT");	/* remote spamd host port   */
    char *ssl = getenv("SPAMDSSL");	/* use ssl for spamc/spamd  */
    char *limit = getenv("SPAMDLIMIT");	/* message size limit       */
    char *user = getenv("SPAMDUSER");	/* spamc user configuration */
    char *options[MAXOPTS];
    int opt = 0;

    /* create the array of options */
    options[opt++] = "spamc";	/* zeroth argument */
    if (socket) {
	options[opt++] = "-U";
	options[opt++] = socket;
    }
    if (host) {
	options[opt++] = "-d";
	options[opt++] = host;
    }
    if (port) {
	options[opt++] = "-p";
	options[opt++] = port;
    }
    if (ssl) {
	options[opt++] = "-S";
    }
    if (limit) {
	options[opt++] = "-s";
	options[opt++] = limit;
    }
    if (user) {
	options[opt++] = "-u";
	options[opt++] = user;
    }
    options[opt] = NULL;

    if (pipe(pfds) == -1) {
	perror("Failed to create pipe; quitting\n");
	exit(1);
    }

    if ((childpid = fork()) == -1) {
	perror("Failed to fork; quitting\n");
	exit(2);
    }

    if (childpid == 0) {
	close(1);		/* close normal stdout */
	dup(pfds[1]);		/* make stdout same as pfds[1] */
	close(pfds[0]);		/* we don't need this */
	execvp("spamc", options);
    }
    else {
	close(0);		/* close normal stdin */
	dup(pfds[0]);		/* make stdin same as pfds[0] */
	close(pfds[1]);		/* we don't need this */
	execlp("qmail-queue", "qmail-queue", NULL);
    }
}
