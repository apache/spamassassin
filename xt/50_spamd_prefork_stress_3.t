#!/usr/bin/perl

  (-d "../t") and chdir "..";
  system( "$^X", "-T", "t/spamd_prefork_stress_3.t",
        "--override", "run_long_tests:run_spamd_prefork_stress_test", "1:1", @ARGV);
  ($? >> 8 == 0) or die "exec failed";
  

