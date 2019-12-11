
#!/usr/bin/perl
  (-d "../t") and chdir "..";
  system("sudo", "-n", "$^X", "-T", "t/root_spamd_tell_x_paranoid.t",
        "--override", "run_root_tests", "1", @ARGV);
  ($? >> 8 == 0) or die "exec failed";

  my $uid = (stat("t"))[4];
  system("sudo -n chown -R $uid t/log") if $uid;

