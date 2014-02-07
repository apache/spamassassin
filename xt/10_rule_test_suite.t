#!/usr/bin/perl
#
# run the "t.rules" rule test suite in its entirety

(-d "xt") and chdir "xt";       # boilerplate for xt, ensure we know where we are

chdir "..";
exec "t.rules/run" or die "exec failed";
