#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("mkrules");
use Test; BEGIN { plan tests => 97 };
use File::Copy;
use File::Path;

# ---------------------------------------------------------------------------
print " script runs, even with nothing to do\n\n";

my $tdir = "log/mkrules_t";
rmtree([ $tdir ]);

mkpath (["$tdir/rulesrc", "$tdir/rules"]);

write_file("$tdir/MANIFEST", [ ]);
write_file("$tdir/MANIFEST.SKIP", [ "foo2\n" ]);
write_file("$tdir/rules/active.list", [ "" ]);

ok (mkrun ("--src $tdir/rulesrc --out $tdir/rules --manifest $tdir/MANIFEST --manifestskip $tdir/MANIFEST.SKIP --active $tdir/rules/active.list", \&patterns_run_cb));
ok ok_all_patterns();
save_tdir();

# ---------------------------------------------------------------------------
print " promotion of an active rule\n\n";

%patterns = (
  '72_active.cf: WARNING: not listed in manifest file' => manif_found,
  "body GOOD /foo/"   => rule_line_1,
  "describe GOOD desc_found"  => rule_line_2,
);
%anti_patterns = (
  "describe T_GOOD desc_found"  => rule_line_2,
);

mkpath ([ "$tdir/rulesrc/sandbox/foo", "$tdir/rules" ]);

write_file("$tdir/MANIFEST", [ ]);
write_file("$tdir/MANIFEST.SKIP", [ "foo2\n" ]);
write_file("$tdir/rules/active.list", [ "GOOD\n" ]);
write_file("$tdir/rulesrc/sandbox/foo/20_foo.cf", [
    "body GOOD /foo/\n",
    "describe GOOD desc_found\n"
]);

ok (mkrun ("--src $tdir/rulesrc --out $tdir/rules --manifest $tdir/MANIFEST --manifestskip $tdir/MANIFEST.SKIP --active $tdir/rules/active.list 2>&1", \&patterns_run_cb));
checkfile("$tdir/rules/72_active.cf", \&patterns_run_cb);
checkfile("$tdir/rules/70_sandbox.cf", \&patterns_run_cb);
ok ok_all_patterns();
save_tdir();

# ---------------------------------------------------------------------------
print " non-promotion of an inactive rule\n\n";

%patterns = (
  '70_sandbox.cf: WARNING: not listed in manifest file' => manif_found,
  "body T_GOOD /foo/"   => rule_line_1,
  "describe T_GOOD desc_found"  => rule_line_2,
);
%anti_patterns = (
  "describe GOOD desc_found"  => rule_line_2,
);

mkpath ([ "$tdir/rulesrc/sandbox/foo", "$tdir/rules" ]);

write_file("$tdir/MANIFEST", [ ]);
write_file("$tdir/MANIFEST.SKIP", [ "foo2\n" ]);
write_file("$tdir/rules/active.list", [ "NOT_GOOD\n" ]);
write_file("$tdir/rulesrc/sandbox/foo/20_foo.cf", [
    "body GOOD /foo/\n",
    "describe GOOD desc_found\n"
]);

ok (mkrun ("--src $tdir/rulesrc --out $tdir/rules --manifest $tdir/MANIFEST --manifestskip $tdir/MANIFEST.SKIP --active $tdir/rules/active.list 2>&1", \&patterns_run_cb));
checkfile("$tdir/rules/72_active.cf", \&patterns_run_cb);
checkfile("$tdir/rules/70_sandbox.cf", \&patterns_run_cb);
ok ok_all_patterns();
save_tdir();

# ---------------------------------------------------------------------------
print " non-promotion of an inactive rule with score set\n\n";

%patterns = (
  '70_sandbox.cf: WARNING: not listed in manifest file' => manif_found,
  "body T_GOOD /foo/"   => rule_line_1,
  "describe T_GOOD desc_found"  => rule_line_2,
  "#score T_GOOD 4.0"  => score_good,
);
%anti_patterns = (
  "describe GOOD desc_found"  => rule_line_2,
  "score GOOD 4.0"  => 'score',
);

mkpath ([ "$tdir/rulesrc/sandbox/foo", "$tdir/rules" ]);

write_file("$tdir/MANIFEST", [ ]);
write_file("$tdir/MANIFEST.SKIP", [ "foo2\n" ]);
write_file("$tdir/rules/active.list", [ "NOT_GOOD\n" ]);
write_file("$tdir/rulesrc/sandbox/foo/20_foo.cf", [
    "body GOOD /foo/\n",
    "score GOOD 4.0\n",
    "describe GOOD desc_found\n"
]);

ok (mkrun ("--src $tdir/rulesrc --out $tdir/rules --manifest $tdir/MANIFEST --manifestskip $tdir/MANIFEST.SKIP --active $tdir/rules/active.list 2>&1", \&patterns_run_cb));
checkfile("$tdir/rules/72_active.cf", \&patterns_run_cb);
checkfile("$tdir/rules/70_sandbox.cf", \&patterns_run_cb);
ok ok_all_patterns();
save_tdir();

# ---------------------------------------------------------------------------
print " non-promotion of a broken rule\n\n";

%patterns = (
  '70_sandbox.cf: WARNING: not listed in manifest file' => manif_found,
  'LINT FAILED' => lint_failed,
);
%anti_patterns = (
  "body GOOD"   => rule_line_1,
  "describe GOOD desc_found"  => rule_line_2,
);

mkpath ([ "$tdir/rulesrc/sandbox/foo", "$tdir/rules" ]);

write_file("$tdir/MANIFEST", [ ]);
write_file("$tdir/MANIFEST.SKIP", [ "foo2\n" ]);
write_file("$tdir/rules/active.list", [ "GOOD\n" ]);
write_file("$tdir/rulesrc/sandbox/foo/20_foo.cf", [
    "body GOOD /***\n",
    "describe GOOD desc_found\n"
]);

ok (mkrun ("--src $tdir/rulesrc --out $tdir/rules --manifest $tdir/MANIFEST --manifestskip $tdir/MANIFEST.SKIP --active $tdir/rules/active.list 2>&1", \&patterns_run_cb));
checkfile("$tdir/rules/70_sandbox.cf", \&patterns_run_cb);
ok (-f "$tdir/rules/72_active.cf");
ok (-s "$tdir/rules/72_active.cf" == 0);
ok ok_all_patterns();
save_tdir();

# ---------------------------------------------------------------------------
print " promotion of an active meta rule\n\n";

%patterns = (
  '70_sandbox.cf: WARNING: not listed in manifest file' => manif_found,
  '20_foo.cf: 1 active rules, 1 other' => 'foundrule',
  "body __GOOD /foo/"   => rule_line_1,
  "meta GOOD (__GOOD)"   => rule_line_1a,
  "describe GOOD desc_found"  => rule_line_2,
);
%anti_patterns = (
  "describe T_GOOD desc_found"  => rule_line_2,
);

mkpath ([ "$tdir/rulesrc/sandbox/foo", "$tdir/rules" ]);

write_file("$tdir/MANIFEST", [ ]);
write_file("$tdir/MANIFEST.SKIP", [ "foo2\n" ]);
write_file("$tdir/rules/active.list", [ "GOOD\n" ]);
write_file("$tdir/rulesrc/sandbox/foo/20_foo.cf", [
    "body __GOOD /foo/\n",
    "meta GOOD (__GOOD)\n",
    "describe GOOD desc_found\n"
]);

ok (mkrun ("--src $tdir/rulesrc --out $tdir/rules --manifest $tdir/MANIFEST --manifestskip $tdir/MANIFEST.SKIP --active $tdir/rules/active.list 2>&1", \&patterns_run_cb));
checkfile("$tdir/rules/72_active.cf", \&patterns_run_cb);
checkfile("$tdir/rules/70_sandbox.cf", \&patterns_run_cb);
ok ok_all_patterns();
save_tdir();

# ---------------------------------------------------------------------------
print " inactive meta rule\n\n";

%patterns = (
  '70_sandbox.cf: WARNING: not listed in manifest file' => manif_found,
  '20_foo.cf: 0 active rules, 2 other' => 'foundrule',
  "body __GOOD /foo/"   => rule_line_1,
  "meta T_GOOD (__GOOD)"   => rule_line_1a,
  "describe T_GOOD desc_found"  => rule_line_2,
);
%anti_patterns = (
  "describe GOOD desc_found"  => rule_line_2,
);

mkpath ([ "$tdir/rulesrc/sandbox/foo", "$tdir/rules" ]);

write_file("$tdir/MANIFEST", [ ]);
write_file("$tdir/MANIFEST.SKIP", [ "foo2\n" ]);
write_file("$tdir/rules/active.list", [ "NOT_GOOD\n" ]);
write_file("$tdir/rulesrc/sandbox/foo/20_foo.cf", [
    "body __GOOD /foo/\n",
    "meta GOOD (__GOOD)\n",
    "describe GOOD desc_found\n"
]);

ok (mkrun ("--src $tdir/rulesrc --out $tdir/rules --manifest $tdir/MANIFEST --manifestskip $tdir/MANIFEST.SKIP --active $tdir/rules/active.list 2>&1", \&patterns_run_cb));
checkfile("$tdir/rules/72_active.cf", \&patterns_run_cb);
checkfile("$tdir/rules/70_sandbox.cf", \&patterns_run_cb);
ok ok_all_patterns();
save_tdir();

# ---------------------------------------------------------------------------
print " active plugin in sandbox\n\n";

%patterns = (
  '70_sandbox.cf: WARNING: not listed in manifest file' => manif_found,
  "loadplugin Good plugin.pm" => loadplugin_found,
  "body GOOD eval:check_foo()"   => rule_line_1,
  "describe GOOD desc_found"  => rule_line_2,
  "ifplugin Good" => if1,
  "endif" => endif_found,
);
%anti_patterns = (
  "describe T_GOOD desc_found"  => rule_line_2,
);

mkpath ([ "$tdir/rulesrc/sandbox/foo", "$tdir/rules" ]);

write_file("$tdir/MANIFEST", [ "rulesrc/sandbox/foo/20_foo.cf\n", "rulesrc/sandbox/foo/plugin.pm\n" ]);
write_file("$tdir/MANIFEST.SKIP", [ "foo2\n" ]);
write_file("$tdir/rules/active.list", [ "GOOD\n" ]);
write_file("$tdir/rulesrc/sandbox/foo/20_foo.cf", [
    "loadplugin Good plugin.pm\n",
    "ifplugin Good\n",
    "body GOOD eval:check_foo()\n",
    "describe GOOD desc_found\n",
    "endif\n",
]);
write_file("$tdir/rulesrc/sandbox/foo/plugin.pm", [
    'package Good;',
    'use Mail::SpamAssassin::Plugin; our @ISA = qw(Mail::SpamAssassin::Plugin);',
    'sub new { my ($class, $m) = @_; $class = ref($class) || $class;',
    'my $self = bless $class->SUPER::new($m), $class;',
    '$self->register_eval_rule("check_foo"); return $self; }',
    'sub check_foo { my ($self, $pms) = @_; return 1; }',
]);

ok (mkrun ("--src $tdir/rulesrc --out $tdir/rules --manifest $tdir/MANIFEST --manifestskip $tdir/MANIFEST.SKIP --active $tdir/rules/active.list 2>&1", \&patterns_run_cb));
# checkfile("$tdir/rules/72_active.cf", \&patterns_run_cb);
checkfile("$tdir/rules/70_sandbox.cf", \&patterns_run_cb);
ok (-f "$tdir/rules/plugin.pm");
ok ok_all_patterns();
save_tdir();

# ---------------------------------------------------------------------------
print " inactive plugin\n\n";

%patterns = (
  '70_sandbox.cf: WARNING: not listed in manifest file' => manif_found,
  # "WARNING: GOOD: renamed as T_GOOD due to missing T_ prefix" => warning_seen,
  "loadplugin Good plugin.pm" => loadplugin_found,
  "body T_GOOD eval:check_foo()" => rule_line_1,
  "describe T_GOOD desc_found" => rule_line_2,
  "ifplugin Good" => if1,
  "endif" => endif_found,
);
%anti_patterns = (
  "describe GOOD desc_found"  => rule_line_2,
);

mkpath ([ "$tdir/rulesrc/sandbox/foo", "$tdir/rules" ]);

write_file("$tdir/MANIFEST", [ "rulesrc/sandbox/foo/20_foo.cf\n", "rulesrc/sandbox/foo/plugin.pm\n" ]);
write_file("$tdir/MANIFEST.SKIP", [ "foo2\n" ]);
write_file("$tdir/rules/active.list", [ "NOT_GOOD\n" ]);
write_file("$tdir/rulesrc/sandbox/foo/20_foo.cf", [
    "loadplugin Good plugin.pm\n",
    "ifplugin Good\n",
    "body GOOD eval:check_foo()\n",
    "describe GOOD desc_found\n",
    "endif\n",
]);
write_file("$tdir/rulesrc/sandbox/foo/plugin.pm", [
    'package Good;',
    'use Mail::SpamAssassin::Plugin; our @ISA = qw(Mail::SpamAssassin::Plugin);',
    'sub new { my ($class, $m) = @_; $class = ref($class) || $class;',
    'my $self = bless $class->SUPER::new($m), $class;',
    '$self->register_eval_rule("check_foo"); return $self; }',
    'sub check_foo { my ($self, $pms) = @_; return 1; }',
]);

ok (mkrun ("--src $tdir/rulesrc --out $tdir/rules --manifest $tdir/MANIFEST --manifestskip $tdir/MANIFEST.SKIP --active $tdir/rules/active.list 2>&1", \&patterns_run_cb));
# checkfile("$tdir/rules/72_active.cf", \&patterns_run_cb);
checkfile("$tdir/rules/70_sandbox.cf", \&patterns_run_cb);
ok (-f "$tdir/rules/plugin.pm");
ok ok_all_patterns();
save_tdir();


# ---------------------------------------------------------------------------
print " active plugin, but the .pm file is AWOL\n\n";

%patterns = (
  "body GOOD eval:check_foo()"   => rule_line_1,
  "describe GOOD desc_found"  => rule_line_2,
  "ifplugin Good" => if1,
  "endif" => endif_found,
  "rulesrc/sandbox/foo/20_foo.cf: WARNING: plugin code file 'log/mkrules_t/rulesrc/sandbox/foo/plugin.pm' not found, line ignored: loadplugin Good plugin.pm" => plugin_not_found,
);
%anti_patterns = (
  "describe T_GOOD desc_found"  => rule_line_2,
);

rmtree([ $tdir ]); mkpath ([ "$tdir/rulesrc/sandbox/foo", "$tdir/rules" ]);

write_file("$tdir/MANIFEST", [ "rulesrc/sandbox/foo/20_foo.cf\n", "rulesrc/sandbox/foo/plugin.pm\n" ]);
write_file("$tdir/MANIFEST.SKIP", [ "foo2\n" ]);
write_file("$tdir/rules/active.list", [ "GOOD\n" ]);
write_file("$tdir/rulesrc/sandbox/foo/20_foo.cf", [
    "loadplugin Good plugin.pm\n",
    "ifplugin Good\n",
    "body GOOD eval:check_foo()\n",
    "describe GOOD desc_found\n",
    "endif\n",
]);

ok (mkrun ("--src $tdir/rulesrc --out $tdir/rules --manifest $tdir/MANIFEST --manifestskip $tdir/MANIFEST.SKIP --active $tdir/rules/active.list 2>&1", \&patterns_run_cb));
checkfile("$tdir/rules/72_active.cf", \&patterns_run_cb);
# checkfile("$tdir/rules/70_sandbox.cf", \&patterns_run_cb);
ok (!-f "$tdir/rules/plugin.pm");
ok ok_all_patterns();
save_tdir();

# ---------------------------------------------------------------------------
print " active plugin, but the .pm file is not in MANIFEST\n\n";

%patterns = (
  "body GOOD eval:check_foo()"   => rule_line_1,
  "describe GOOD desc_found"  => rule_line_2,
  "ifplugin Good" => if1,
  "endif" => endif_found,
  "tryplugin Good plugin.pm" => 'tryplugin',
  "log/mkrules_t/rulesrc/sandbox/foo/20_foo.cf: WARNING: 'log/mkrules_t/rules/plugin.pm' not listed in manifest file, making 'tryplugin': loadplugin Good plugin.pm" => not_found_in_manifest_warning
);
%anti_patterns = (
);

rmtree([ $tdir ]); mkpath ([ "$tdir/rulesrc/sandbox/foo", "$tdir/rules" ]);

write_file("$tdir/MANIFEST", [ "rulesrc/sandbox/foo/20_foo.cf\n" ]);
write_file("$tdir/MANIFEST.SKIP", [ ]);
write_file("$tdir/rules/active.list", [ "GOOD\n" ]);
write_file("$tdir/rulesrc/sandbox/foo/20_foo.cf", [
    "loadplugin Good plugin.pm\n",
    "ifplugin Good\n",
    "body GOOD eval:check_foo()\n",
    "describe GOOD desc_found\n",
    "endif\n",
]);
write_file("$tdir/rulesrc/sandbox/foo/plugin.pm", [
    'package Good;',
    'use Mail::SpamAssassin::Plugin; our @ISA = qw(Mail::SpamAssassin::Plugin);',
    'sub new { my ($class, $m) = @_; $class = ref($class) || $class;',
    'my $self = bless $class->SUPER::new($m), $class;',
    '$self->register_eval_rule("check_foo"); return $self; }',
    'sub check_foo { my ($self, $pms) = @_; return 1; }',
]);

ok (mkrun ("--src $tdir/rulesrc --out $tdir/rules --manifest $tdir/MANIFEST --manifestskip $tdir/MANIFEST.SKIP --active $tdir/rules/active.list 2>&1", \&patterns_run_cb));
# checkfile("$tdir/rules/72_active.cf", \&patterns_run_cb);
checkfile("$tdir/rules/70_sandbox.cf", \&patterns_run_cb);
ok (-f "$tdir/rules/plugin.pm");
ok ok_all_patterns();
save_tdir();

# ---------------------------------------------------------------------------
print "meta rule depends on unpromoted subrule in lexically-earlier file\n\n";
# (see mail from Sidney of Oct 16 2006, rules HS_INDEX_PARAM and HS_PHARMA_1)

%patterns = (
  "header T_GOOD_SUB"   => rule_line_1,
  "header T_BAD_SUB"   => rule_line_2,
  "meta GOOD (T_GOOD_SUB && !T_BAD_SUB)" => meta_found
);
%anti_patterns = (
);

rmtree([ $tdir ]); mkpath ([ "$tdir/rulesrc/sandbox/foo", "$tdir/rules" ]);

write_file("$tdir/MANIFEST", [ "rules/72_active.cf\n" ]);
write_file("$tdir/MANIFEST.SKIP", [ ]);
write_file("$tdir/rules/active.list", [ "GOOD\n" ]);
write_file("$tdir/rulesrc/sandbox/foo/20_aaa.cf", [
    "meta GOOD (GOOD_SUB && !BAD_SUB)\n",
]);
write_file("$tdir/rulesrc/sandbox/foo/20_bbb.cf", [
    "header GOOD_SUB Foo =~ /good/\n",
    "header BAD_SUB Foo =~ /bad/\n",
]);

ok (mkrun ("--src $tdir/rulesrc --out $tdir/rules --manifest $tdir/MANIFEST --manifestskip $tdir/MANIFEST.SKIP --active $tdir/rules/active.list 2>&1", \&patterns_run_cb));
checkfile("$tdir/rules/72_active.cf", \&patterns_run_cb);
ok ok_all_patterns();
save_tdir();

# ---------------------------------------------------------------------------
print " nested conditionals\n\n";

%patterns = (
  '72_active.cf: WARNING: not listed in manifest file' => manif_found,
  "body GOOD /foo/"   => rule_line_1,
  "describe GOOD desc_found"  => rule_line_2,
  "ifplugin Mail::SpamAssassin::Plugin::DKIM" => 'ifplugin',
  "if (version >= 3.002000)" => 'ifversion',
);
%anti_patterns = (
  "describe T_GOOD desc_found"  => rule_line_2,
);

mkpath ([ "$tdir/rulesrc/sandbox/foo", "$tdir/rules" ]);

write_file("$tdir/MANIFEST", [ ]);
write_file("$tdir/MANIFEST.SKIP", [ "foo2\n" ]);
write_file("$tdir/rules/active.list", [ "GOOD\n" ]);
write_file("$tdir/rulesrc/sandbox/foo/20_foo.cf", [
  "ifplugin Mail::SpamAssassin::Plugin::DKIM\n",
  "if (version >= 3.002000)\n",
  "body GOOD /foo/\n",
  "describe GOOD desc_found\n",
  "endif\n",
  "endif\n",
]);

ok (mkrun ("--src $tdir/rulesrc --out $tdir/rules --manifest $tdir/MANIFEST --manifestskip $tdir/MANIFEST.SKIP --active $tdir/rules/active.list 2>&1", \&patterns_run_cb));
checkfile("$tdir/rules/72_active.cf", \&patterns_run_cb);
checkfile("$tdir/rules/70_sandbox.cf", \&patterns_run_cb);
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

