#!/usr/bin/perl
#
# run the "t.rules" rule test suite in its entirety

(-d "../t") and chdir "..";

exec "t.rules/run" or die "exec failed";
