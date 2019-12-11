#!/usr/bin/perl

  (-d "../t") and chdir "..";
  system( "$^X", "-T", "t/spf.t", "--override", "run_long_tests:run_net_tests", "1:1", @ARGV);
  ($? >> 8 == 0) or die "exec failed";
  

