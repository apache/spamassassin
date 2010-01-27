#!/usr/bin/perl
# bug 6241

use lib '.'; use lib 't';
use SATest; sa_t_init("mkrules_else");
use Test; BEGIN { plan tests => 18 };
use File::Copy;
use File::Path;

# ---------------------------------------------------------------------------
print "\n rule with 'else'\n\n";

my $tdir = "log/mkrules_else_t";
rmtree([ $tdir ]);

%patterns = (
  # ensure these have the appropriate conditional attached
  "/(?s)ifplugin Mail::SpamAssassin::Plugin::WhateverNonExistent".
        "[^\\n]*\\n".
        "die_with_a_syntax_error/" => die_with_a_syntax_error_found,

  "/(?s)if !plugin\\(Mail::SpamAssassin::Plugin::WhateverNonExistent\\)".
        "[^\\n]*\\n".
        "body GOOD \\/foo\\//" => rule_GOOD,

);
%anti_patterns = (
  "ERROR"        => ERROR_in_stdout,
  "WARNING"      => WARNING_in_stdout,
);

mkpath ([ "$tdir/rulesrc/sandbox/foo", "$tdir/rules" ]);
write_file("$tdir/MANIFEST", [ "$tdir/rules/70_sandbox.cf\n", "$tdir/rules/72_active.cf\n" ]);
write_file("$tdir/rules/active.list", [ "GOOD\n" ]);
write_file("$tdir/rulesrc/sandbox/foo/20_foo.cf", [

    "ifplugin Mail::SpamAssassin::Plugin::WhateverNonExistent\n",
        "die_with_a_syntax_error\n",        # shouldn't get here
    "else\n",
        "body GOOD /foo/\n",
        "describe GOOD desc_found\n",
    "endif\n",

]);

ok (mkrun ("--src $tdir/rulesrc --out $tdir/rules --manifest $tdir/MANIFEST --manifestskip $tdir/MANIFEST.SKIP --active $tdir/rules/active.list 2>&1", \&patterns_run_cb));
checkfile("$tdir/rules/72_active.cf", \&patterns_run_cb);
checkfile("$tdir/rules/70_sandbox.cf", \&patterns_run_cb);
ok ok_all_patterns();
save_tdir();

# ---------------------------------------------------------------------------
print "\n rule with 2 nested 'else's\n\n";

rmtree([ $tdir ]);

%patterns = (
);
%anti_patterns = (
  "/(?s)meta\\s+T_B1\\s+\\S+\\n".
        "meta\\s+T_B1\\s+\\S+/" => two_metas_in_one_ifplugin_scope,

  "ERROR"        => ERROR_in_stdout,
  "WARNING"      => WARNING_in_stdout,
);

mkpath ([ "$tdir/rulesrc/sandbox/foo", "$tdir/rules" ]);
write_file("$tdir/rules/active.list", [ "A1\n", "A2\n" ]);
write_file("$tdir/MANIFEST", [ "$tdir/rules/70_sandbox.cf\n", "$tdir/rules/72_active.cf\n" ]);
write_file("$tdir/rulesrc/sandbox/foo/20_foo.cf", [
    "body A1 /foo/\n",
    "body A2 /foo/\n",

    "ifplugin Mail::SpamAssassin::Plugin::SPF\n",
      "ifplugin Mail::SpamAssassin::Plugin::DKIM\n",
        "meta   B1   A1\n",
      "else\n",
        "meta   B1   A2\n",
      "endif\n",
    "else\n",
      "ifplugin Mail::SpamAssassin::Plugin::DKIM\n",
        "meta   B1   !A1\n",
      "else\n",
        "meta   B1   !A2\n",
      "endif\n",
    "endif\n",

]);

ok (mkrun ("--src $tdir/rulesrc --out $tdir/rules --manifest $tdir/MANIFEST --manifestskip $tdir/MANIFEST.SKIP --active $tdir/rules/active.list 2>&1", \&patterns_run_cb));
checkfile("$tdir/rules/72_active.cf", \&patterns_run_cb);
checkfile("$tdir/rules/70_sandbox.cf", \&patterns_run_cb);
ok ok_all_patterns();
save_tdir();

# ---------------------------------------------------------------------------
print "\n rule with 2 nested 'else's, with promoted meta rule from sandbox subrule\n\n";

rmtree([ $tdir ]);

%patterns = (
);
%anti_patterns = (
  "/(?s)meta\\s+__B1\\s+\\S+\\n".
        "meta\\s+__B1\\s+\\S+/" => two_metas_in_one_ifplugin_scope,

  "ERROR"        => ERROR_in_stdout,
  "WARNING"      => WARNING_in_stdout,
);

mkpath ([ "$tdir/rulesrc/sandbox/foo", "$tdir/rules" ]);
write_file("$tdir/rules/active.list", [ "C1\n" ]);
write_file("$tdir/MANIFEST", [ "$tdir/rules/70_sandbox.cf\n", "$tdir/rules/72_active.cf\n" ]);
write_file("$tdir/rulesrc/sandbox/foo/20_foo.cf", [
    "body A1 /foo/\n",
    "body A2 /foo/\n",
    "meta C1 __B1\n",

    "ifplugin Mail::SpamAssassin::Plugin::SPF\n",
      "ifplugin Mail::SpamAssassin::Plugin::DKIM\n",
        "meta   __B1   A1\n",
      "else\n",
        "meta   __B1   A2\n",
      "endif\n",
    "else\n",
      "ifplugin Mail::SpamAssassin::Plugin::DKIM\n",
        "meta   __B1   !A1\n",
      "else\n",
        "meta   __B1   !A2\n",
      "endif\n",
    "endif\n",

]);

ok (mkrun ("--src $tdir/rulesrc --out $tdir/rules --manifest $tdir/MANIFEST --manifestskip $tdir/MANIFEST.SKIP --active $tdir/rules/active.list 2>&1", \&patterns_run_cb));
checkfile("$tdir/rules/70_sandbox.cf", \&patterns_run_cb);

%patterns = (
  "body T_A1" => T_A1_defined,
  "meta __B1" => __B1_defined,
);
checkfile("$tdir/rules/72_active.cf", \&patterns_run_cb);
ok ok_all_patterns();
save_tdir();

# ---------------------------------------------------------------------------

exit;

sub write_file {
  my $file = shift;
  my $linesref = shift;
  open (O, ">$file") or die "cannot write to $file";
  print O @$linesref;
  close O or die "cannot save $file";
}


sub mkrun {
  my $args = shift;
  my $read_sub = shift;

  my $post_redir = '';
  $args =~ s/ 2\>\&1$// and $post_redir = ' 2>&1';

  rmtree ("log/outputdir.tmp"); # some tests use this
  mkdir ("log/outputdir.tmp", 0755);

  clear_pattern_counters();

  my $scrargs = "$perl_path -I../lib ../build/mkrules $args";
  print ("\t$scrargs\n");
  system ("$scrargs > log/$testname.${Test::ntest} $post_redir");
  $mk_exitcode = ($?>>8);
  if ($mk_exitcode != 0) { return undef; }
  &checkfile ("$testname.${Test::ntest}", $read_sub) if (defined $read_sub);
  1;
}

sub save_tdir {
  rmtree("$tdir.${Test::ntest}");
  if (move( "$tdir", "$tdir.${Test::ntest}")) {
    print "\ttest output tree copied to $tdir.${Test::ntest}\n";
  }
}

