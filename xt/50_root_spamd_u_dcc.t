#!/usr/bin/perl
  (-d "../t") and chdir "..";
  system( "$^X", "-T", "t/root_spamd_u_dcc.t",
        "--override", "run_dcc_tests:run_root_tests", "1:1", @ARGV);
  ($? >> 8 == 0) or die "exec failed";
  

