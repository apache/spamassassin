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

#define TRY(exp) do {                                                         \
          if ((exp) == -1) {                                                  \
            printf("%s:%d: '%s' failed: ",                                    \
              __FILE__,                                                       \
              __LINE__,                                                       \
              #exp                                                            \
            ); perror(NULL);                                                  \
            exit(81);                                                         \
          }                                                                   \
        } while(0)

int main(int argc, char **argv)
{
    int pfds[2];
    pid_t childpid;
    char *socket = getenv("SPAMDSOCK");   /* Unix Domain Socket path  */
    char *host = getenv("SPAMDHOST");     /* remote spamd host name   */
    char *port = getenv("SPAMDPORT");     /* remote spamd host port   */
    char *ssl = getenv("SPAMDSSL");       /* use ssl for spamc/spamd  */
    char *limit = getenv("SPAMDLIMIT");   /* message size limit       */
    char *user = getenv("SPAMDUSER");     /* spamc user configuration */
    char *options[MAXOPTS];
    int opt = 0;

    /* create the array of options */
    options[opt++] = "spamc";             /* set zeroth argument */
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

    TRY(pipe(pfds));
    TRY(childpid = fork());
    if (childpid == 0) {                /* the child ... */
        TRY(close(1));                    /* close normal stdout */
        TRY(dup(pfds[1]));                /* make stdout same as pfds[1] */
        TRY(close(pfds[0]));              /* we don't need this */
        TRY(execvp("spamc", options));
    }
    else {                              /* the parent ... */
        TRY(close(0));                    /* close normal stdin */
        TRY(dup(pfds[0]));                /* make stdin same as pfds[0] */
        TRY(close(pfds[1]));              /* we don't need this */
        TRY(execlp("qmail-queue", "qmail-queue", NULL));
    }
    
    /* never reached */
    return 81;
}
