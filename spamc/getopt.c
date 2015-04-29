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


#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "getopt.h"

#ifdef WIN32

#ifdef _MSC_VER
/* ignore MSVC++ warnings that are annoying and hard to remove:
 4702 unreachable code
 (there is an unreachable assert(0) in case somehow it is reached)
 */
#pragma warning( disable : 4702 )
#endif

#endif /* WIN32 */

#define OPTERRCOLON (1)
#define OPTERRNF (2)
#define OPTERRARG (3)

char *spamc_optarg;
int spamc_optreset = 0;
int spamc_optind = 1;
int spamc_opterr = 1;
int spamc_optopt;

static int
optiserr(int argc, char * const *argv, int oint, const char *optstr,
         int optchr, int err)
{
    (void) argc;  /* not used */
    (void) optstr; /* not used */
    if(spamc_opterr)
    {
        fprintf(stderr, "Error in argument %d, char %d: ", oint, optchr+1);
        switch(err)
        {
        case OPTERRCOLON:
            fprintf(stderr, ": in flags\n");
            break;
        case OPTERRNF:
            fprintf(stderr, "option not found %c\n", argv[oint][optchr]);
            break;
        case OPTERRARG:
            fprintf(stderr, "argument required for option %c\n", argv[oint][optchr]);
            break;
        default:
            fprintf(stderr, "unknown\n");
            break;
        }
    }
    spamc_optopt = argv[oint][optchr];
    return('?');
}
    
static int
longoptiserr(int argc, char * const *argv, int oint, int err)
{
    (void) argc;  /* not used */
    if(spamc_opterr)
    {
        fprintf(stderr, "Error in argument %d : ", oint);
        switch(err)
        {
        case OPTERRCOLON:
            fprintf(stderr, ": in flags\n");
            break;
        case OPTERRNF:
            fprintf(stderr, "option not found %s\n", argv[oint]);
            break;
        case OPTERRARG:
            fprintf(stderr, "argument required for option %s\n", argv[oint]);
            break;
        default:
            fprintf(stderr, "unknown\n");
            break;
        }
    }
    return('?');
}
    
int
spamc_getopt(int argc, char* const *argv, const char *optstr)
{
    static int optchr = 0;
    static int dash = 0; /* have already seen the - */

    char *cp;

    if (spamc_optreset)
        spamc_optreset = optchr = dash = 0;
    if(spamc_optind >= argc)
       return(EOF);
    if(!dash && (argv[spamc_optind][0] !=  '-')) 
       return(EOF);
    if(!dash && (argv[spamc_optind][0] ==  '-') && !argv[spamc_optind][1])
    {
        /*
         * use to specify stdin. Need to let pgm process this and
         * the following args
         */
       return(EOF);
    }
    if((argv[spamc_optind][0] == '-') && (argv[spamc_optind][1] == '-'))
    {
        /* -- indicates end of args */
        spamc_optind++;
        return(EOF);
    }
    if(!dash)
    {
        assert((argv[spamc_optind][0] == '-') && argv[spamc_optind][1]);
        dash = 1;
        optchr = 1;
    }

    /* Check if the guy tries to do a -: kind of flag */
    assert(dash);
    if(argv[spamc_optind][optchr] == ':')
    {
        dash = 0;
        spamc_optind++;
        return(optiserr(argc, argv, spamc_optind-1, optstr, optchr, OPTERRCOLON));
    }
    cp = strchr(optstr, argv[spamc_optind][optchr]);
    if(!cp)
    {
        int errind = spamc_optind;
        int errchr = optchr;

        if(!argv[spamc_optind][optchr+1])
        {
            dash = 0;
            spamc_optind++;
        }
        else
            optchr++;
        return(optiserr(argc, argv, errind, optstr, errchr, OPTERRNF));
    }
    if(cp[1] == ':')
    {
        dash = 0;
        spamc_optind++;
        if(spamc_optind == argc)
            return(optiserr(argc, argv, spamc_optind-1, optstr, optchr, OPTERRARG));
        spamc_optarg = argv[spamc_optind++];
        return(*cp);
    }
    else
    {
        if(!argv[spamc_optind][optchr+1])
        {
            dash = 0;
            spamc_optind++;
        }
        else
           optchr++;
        return(*cp);
    }
    assert(0);
    return(0);
}

int
spamc_getopt_long(int argc, char * const argv[], 
      const char *optstring, struct option *longopts,
      int *longindex)
{
   static int optchr = 0;
   static int dash = 0;
   char *cp, *longopt;
   char *bp, *opt = NULL;
   int i, longoptlen;;

   spamc_optarg = NULL; /* clear any left over state from previous option */
   if(spamc_optreset)
      spamc_optreset = optchr = dash = 0;
   if(spamc_optind >= argc) {
      return(EOF);
   }
   if(!dash && (argv[spamc_optind][0] != '-')) {
      return(EOF);
   }
   if(!dash && (argv[spamc_optind][0] == '-') && !argv[spamc_optind][1]) {
      /* used to specify stdin */
      return(EOF);
   }
   if((argv[spamc_optind][0] == '-') && (argv[spamc_optind][1] == '-')
         && !argv[spamc_optind][2]) {
      /* used to specify end of args */
      return(EOF);
   }
   if((argv[spamc_optind][0] == '-') && argv[spamc_optind][1] && 
         (argv[spamc_optind][1] != '-')) {
      /* short option */
      optchr = 1;
      if(argv[spamc_optind][optchr] == ':')
         return(optiserr(argc, argv, spamc_optind++, optstring, optchr, OPTERRCOLON));

      cp = strchr(optstring, argv[spamc_optind++][optchr]);
      if(cp == NULL)
         return(optiserr(argc, argv, spamc_optind-1, optstring, optchr, OPTERRNF));
      if(cp[1] == ':') {
         /* requires an argument */
         if(!argv[spamc_optind] || (argv[spamc_optind][0] == '-') || 
               (spamc_optind >= argc)) {
            return(optiserr(argc, argv, spamc_optind-1, optstring, optchr, OPTERRARG));
         }
         spamc_optarg = argv[spamc_optind++];
         return(*cp);
      } else {
         dash = 0;
         return(*cp);
      }
   }
   if((argv[spamc_optind][0] == '-') && (argv[spamc_optind][1] == '-') && 
         argv[spamc_optind][2]) {
      /* long option */
      optchr = 2;
      longopt = argv[spamc_optind++];
      if(longopt[2] == ':')
         return(longoptiserr(argc, argv, spamc_optind, OPTERRCOLON));
      longoptlen = strlen(longopt) - 2;
      if((bp = strchr(longopt, '='))) {
         opt = strdup(bp+1);
         longoptlen -= strlen(bp);
      }

      for(i=0; ; i++) {
	 /* changed to longopts[i].name[0] == 0 - bug 7148 */
         if((longopts[i].name == NULL) || (longopts[i].name[0] == 0))
            return(longoptiserr(argc, argv, spamc_optind-1, OPTERRNF));
         if((memcmp(longopt+2, longopts[i].name, longoptlen)) == 0) {
            *longindex = i;
            if(longopts[i].has_arg == required_argument) {
               if(((spamc_optind >= argc) || (!argv[spamc_optind]) || (argv[spamc_optind][0] == '-')) && 
                   (opt == NULL))
                  return(longoptiserr(argc, argv, spamc_optind-1, OPTERRARG));
               if(opt != NULL) {
                  spamc_optarg = opt;
               } else {
                  spamc_optarg = argv[spamc_optind++];
               }
            } else if(longopts[i].has_arg == optional_argument) {
               if(((spamc_optind < argc) && (argv[spamc_optind]) && (argv[spamc_optind][0] != '-')) || 
                     (opt != NULL)) {
                  if(opt != NULL) {
                     spamc_optarg = opt;
                  } else {
                     spamc_optarg = argv[spamc_optind++];
                  }
               }
            }
            if(longopts[i].flag == NULL) {
               return(longopts[i].val);
            } else {
               *longopts[i].flag = longopts[i].val;
               return(0);
            }
         }
      }
   }
   return(0); /* should never reach here */
}

#ifdef TESTGETOPT
int
 main (int argc, char **argv)
 {
      int c, l;
      extern char *spamc_optarg;
      extern int spamc_optind;
      int aflg = 0;
      int bflg = 0;
      int errflg = 0;
      char *ofile = NULL;
      struct option longopts[] = {
         { "test", required_argument, 0, 't' },
      };

      while ((c = spamc_getopt(argc, argv, "abo:")) != EOF)
           switch (c) {
           case 'a':
                if (bflg)
                     errflg++;
                else
                     aflg++;
                break;
           case 'b':
                if (aflg)
                     errflg++;
                else
                     bflg++;
                break;
           case 'o':
                ofile = spamc_optarg;
                (void)printf("ofile = %s\n", ofile);
                break;
           case '?':
                errflg++;
           }

      while((l = spamc_getopt_long(argc, argv, "t:", longopts, &l)) != EOF)
         switch(l) {
            case 't':
               printf("--test = %s\n",spamc_optarg);
               break;
         }

      if (errflg) {
           (void)fprintf(stderr,
                "usage: cmd [-a|-b] [-o <filename>] files...\n");
           exit (2);
      }
      /*for ( ; spamc_optind < argc; spamc_optind++)
       *     (void)printf("%s\n", argv[spamc_optind]);
       */
      return 0;
 }

#endif /* TESTGETOPT */
