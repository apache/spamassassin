
#!/usr/bin/perl
  (-d "../t") and chdir "..";
  system( "$^X", "-T", "t/lang_lint.t",
        "--override", "run_long_tests", "1", @ARGV);
  ($? >> 8 == 0) or die "exec failed";
  

