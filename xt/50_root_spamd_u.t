#!/usr/bin/perl
  (-d "../t") and chdir "..";
  system("sudo",  "$^X", "t/root_spamd_u.t",
        "--override", "run_root_tests", "1", @ARGV);
  ($? >> 8 == 0) or die "exec failed";

  my $uid = (stat("t"))[4];
  system("sudo chown -R $uid t/log") if $uid;

