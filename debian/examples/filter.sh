#!/bin/sh
#
# filter.sh
#
# Simple filter to plug Anomy Sanitizer and SpamAssassin
# into the Postfix MTA
#
# From http://advosys.ca/papers/postfix-filtering.html
# Advosys Consulting Inc., Ottawa
# Modified by Jesus Climent
#
# For use with:
#    Postfix 20010228 or later
#    SpamAssassin 2.42 or later
#
# Note: Modify the file locations to match your particular 
#       server and installation of SpamAssassin.

# File locations: 
# (CHANGE AS REQUIRED TO MATCH YOUR SERVER)

SENDMAIL=/usr/sbin/sendmail
SPAMASSASSIN=/usr/bin/spamc

/bin/cat | ${SPAMASSASSIN} -f | ${SENDMAIL} -i "$@"

exit $?
