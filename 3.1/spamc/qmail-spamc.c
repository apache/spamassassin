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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>


#define MAXOPTS 16

#define TRY(exp) do {                                                         \
          if ((exp) == -1) {                                                  \
            fprintf(stderr, "%s:%d: '%s' failed: ",                           \
              __FILE__,                                                       \
              __LINE__,                                                       \
              #exp                                                            \
            ); perror(NULL);                                                  \
            exit(81);                                                         \
          }                                                                   \
        } while(0)


int main(int argc, char **argv)
{
    char *options[MAXOPTS];
    char *val = NULL;
    int   opt = 0;

    pid_t childpid;
    int pfds[2];


#ifdef HAVE_QMAIL_RELAYCLIENT
    /*
     * bug 2927: use standard qmail-queue if this is a RELAYCLIENT
     */
    if (getenv("RELAYCLIENT")) {
       TRY(execlp("qmail-queue", "qmail-queue", NULL));
    }
#endif


    /* create the array of options */
    options[opt++] = "spamc";            /* set zeroth argument */
    if ((val = getenv("SPAMDSOCK")) != NULL) {   /* Unix Domain Socket path */
        options[opt++] = "-U";
        options[opt++] = val;
    }
    if ((val = getenv("SPAMDHOST")) != NULL) {   /* remote spamd host name */
        options[opt++] = "-d";
        options[opt++] = val;
    }
    if ((val = getenv("SPAMDPORT")) != NULL) {   /* remote spamd port number */
        options[opt++] = "-p";
        options[opt++] = val;
    }
    if ((val = getenv("SPAMDSSL")) != NULL) {    /* use ssl for spamc/spamd */
        options[opt++] = "-S";
    }
    if ((val = getenv("SPAMDLIMIT")) != NULL) {  /* message size limit */
        options[opt++] = "-s";
        options[opt++] = val;
    }
    if ((val = getenv("SPAMDUSER")) != NULL) {   /* spamc user configuration */
        options[opt++] = "-u";
        options[opt++] = val;
    }
    options[opt] = NULL;                 /* terminate argument list */


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

