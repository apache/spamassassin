
#!/usr/bin/perl
  (-d "../t") and chdir "..";
  system("sudo",  "$^X", "t/root_spamd_x_u.t",
        "--override", "run_root_tests", "1", @ARGV);
  ($? >> 8 == 0) or die "exec failed";
  system('sudo chown -R jmason t/log');

