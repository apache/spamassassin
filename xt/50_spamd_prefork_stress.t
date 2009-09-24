
#!/usr/bin/perl
  (-d "../t") and chdir "..";
  system( "$^X", "t/spamd_prefork_stress.t",
        "--override", "run_spamd_prefork_stress_test", "1", @ARGV);
  ($? >> 8 == 0) or die "exec failed";
  

