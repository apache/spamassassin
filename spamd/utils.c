/*
 * This code is copyright 2001 by Craig Hughes
 * Portions copyright 2002 by Brad Jorsch
 * It is licensed for use with SpamAssassin according to the terms of the Perl Artistic License
 * The text of this license is included in the SpamAssassin distribution in the file named "License"
 */

#include <unistd.h>
#include <errno.h>

#include "utils.h"

/* Dec 13 2001 jm: added safe full-read and full-write functions.  These
 * can cope with networks etc., where a write or read may not read all
 * the data that's there, in one call.
 */
/* Aug 14, 2002 bj: EINTR and EAGAIN aren't fatal, are they? */
/* Aug 14, 2002 bj: moved these to utils.c */
int
full_read (int fd, unsigned char *buf, int min, int len)
{
  int total;
  int thistime;

  for (total = 0; total < min; ) {
    thistime = read (fd, buf+total, len-total);

    if (thistime < 0) {
      if(EINTR == errno || EAGAIN == errno) continue;
      return -1;
    } else if (thistime == 0) {
      /* EOF, but we didn't read the minimum.  return what we've read
       * so far and next read (if there is one) will return 0. */
      return total;
    }

    total += thistime;
  }
  return total;
}

int
full_write (int fd, const unsigned char *buf, int len)
{
  int total;
  int thistime;

  for (total = 0; total < len; ) {
    thistime = write (fd, buf+total, len-total);

    if (thistime < 0) {
      if(EINTR == errno || EAGAIN == errno) continue;
      return thistime;        /* always an error for writes */
    }
    total += thistime;
  }
  return total;
}
