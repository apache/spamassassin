#ifndef LIBSPAMC_H
#define LIBSPAMC_H 1

/*
 * This code is copyright 2001 by Craig Hughes
 * Conversion to a thread-safe shared library copyright 2002 Liam Widdowson
 * It is licensed for use with SpamAssassin according to the terms of the
 * Perl Artistic License
 * The text of this license is included in the SpamAssassin distribution in
 * the file named "License"
 */

#include <stdio.h>

#define EX_ISSPAM       1
#define EX_NOTSPAM      0

int process_message(const char *hostname, int port, char *username, 
                    int max_size, int in_fd, int out_fd,
                    const int check_only, const int safe_fallback);

#endif

