
#!/usr/bin/perl
  (-d "../t") and chdir "..";
  system( "$^X", "t/db_based_whitelist.t",
        "--override", "run_long_tests", "1", @ARGV);
  ($? >> 8 == 0) or die "exec failed";
  

