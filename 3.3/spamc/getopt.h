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

#ifndef REPLACE_GETOPT_H
#define REPLACE_GETOPT_H

extern char *spamc_optarg;
extern int spamc_optreset;
extern int spamc_optind;
extern int spamc_opterr;
extern int spamc_optopt;
int spamc_getopt(int argc, char* const *argv, const char *optstr);

struct option {
#if (defined __STDC__ && __STDC__) || defined __cplusplus
   const char *name;
#else
   char *name;
#endif
   int has_arg;
   int *flag;
   int val;
};

int spamc_getopt_long(int argc, char* const argv[], const char *optstring,
      struct option *longopts, int *longindex);

int spamc_getopt_long_only(int argc, char* const *argv, const char *optstr,
      const struct option *longoptions, int *longopt);

#define no_argument (0)
#define required_argument (1)
#define optional_argument (2)

#endif /* REPLACE_GETOPT_H */
