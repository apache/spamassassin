
#!/usr/bin/perl
  (-d "../t") and chdir "..";
  system( "$^X", "t/dkim.t",
        "--override", "run_net_tests", "1", @ARGV);
  ($? >> 8 == 0) or die "exec failed";
  

