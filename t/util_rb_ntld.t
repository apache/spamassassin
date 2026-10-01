#!/usr/bin/perl -T

use strict;
use warnings;
use lib '.'; use lib 't';
use SATest; sa_t_init("util_rb_ntld");

use Test::More;
use Mail::SpamAssassin;

my $tested_levels = 12;

my $tests = 0;
for my $n (2 .. $tested_levels) {
  $tests += 2 * ($n + 2);  # every label count from 1 to N+2
  $tests += 3;             # mixed line
}
$tests += 3 * 2;  # empty labels
$tests += 5;      # invalid command names
$tests += 3;      # clear_util_rb
$tests += 3;      # large N
$tests += 7;      # deprecated aliases
plan tests => $tests;

##############################################

# returns ($lint_errors, $conf)
sub lint_config {
  my ($cf) = @_;
  my $sa = create_saobj({
    config_text     => "loadplugin Mail::SpamAssassin::Plugin::Check\n".
                       "util_rb_tld com\n$cf\n",
    dont_copy_prefs => 1,
  });
  local $SIG{__WARN__} = sub {};  # silence expected lint warnings
  my $errors = $sa->lint_rules();
  return ($errors, $sa->{conf});
}

sub make_domain {
  my ($labels) = @_;
  return join('.', map { "l$_" } 1 .. $labels);
}

for my $n (2 .. $tested_levels) {
  for my $labels (1 .. $n + 2) {
    my $dom = make_domain($labels);
    my ($errors, $conf) = lint_config("util_rb_${n}tld $dom");
    if ($labels == $n) {
      is($errors, 0, "util_rb_${n}tld accepts $labels labels");
      ok($conf->{multi_level_domains}{$dom},
         "util_rb_${n}tld stores $dom");
    } else {
      ok($errors > 0, "util_rb_${n}tld rejects $labels labels");
      ok(!$conf->{multi_level_domains}{$dom},
         "util_rb_${n}tld does not store $dom");
    }
  }

  # mixed valid/invalid value: all or nothing
  my $good = make_domain($n);
  my $bad  = make_domain($n + 1);
  my ($errors, $conf) = lint_config("util_rb_${n}tld $good $bad");
  ok($errors > 0, "util_rb_${n}tld rejects mixed value");
  ok(!$conf->{multi_level_domains}{$good}, "util_rb_${n}tld mixed: valid entry not stored");
  ok(!$conf->{multi_level_domains}{$bad},  "util_rb_${n}tld mixed: invalid entry not stored");
}

# empty labels
for my $dom ('a..b', '.a.b', 'a.b.') {
  my ($errors, $conf) = lint_config("util_rb_3tld $dom");
  ok($errors > 0, "util_rb_3tld rejects '$dom'");
  ok(!$conf->{multi_level_domains} || !%{$conf->{multi_level_domains}},
     "util_rb_3tld '$dom' not stored");
}

# invalid command names
for my $cmd (qw(util_rb_0tld util_rb_1tld util_rb_02tld util_rb_tld2 util_rb_Ntld)) {
  my ($errors) = lint_config("$cmd a.b");
  ok($errors > 0, "$cmd is not a valid command");
}

# clear_util_rb
{
  my ($errors, $conf) = lint_config("util_rb_2tld a.b\nutil_rb_5tld a.b.c.d.e\nclear_util_rb");
  is($errors, 0, "clear_util_rb lints");
  ok(!$conf->{multi_level_domains}{'a.b'}, "clear_util_rb clears 2tld");
  ok(!$conf->{multi_level_domains}{'a.b.c.d.e'}, "clear_util_rb clears 5tld");
}

# no upper limit on N
{
  my $dom = make_domain(20);
  my ($errors, $conf) = lint_config("util_rb_20tld $dom\nutil_rb_3tld a.b.c");
  is($errors, 0, "util_rb_20tld accepted");
  ok($conf->{multi_level_domains}{$dom}, "util_rb_20tld stored");
  ok($conf->{multi_level_domains}{'a.b.c'}, "util_rb_3tld stored alongside");
}

# deprecated compatibility aliases
{
  my ($errors, $conf) = lint_config("util_rb_2tld co.uk\nutil_rb_3tld demon.co.uk\nutil_rb_4tld a.s3.amazonaws.com");
  is($errors, 0, "deprecated aliases: config lints");
  ok($conf->{two_level_domains}{'co.uk'}, "two_level_domains alias");
  ok($conf->{three_level_domains}{'demon.co.uk'}, "three_level_domains alias");
  ok($conf->{four_level_domains}{'a.s3.amazonaws.com'}, "four_level_domains alias");
  ok($conf->{two_level_domains} == $conf->{multi_level_domains},
     "two_level_domains is the same hash as multi_level_domains");

  my $sa = create_saobj({
    config_text     => "loadplugin Mail::SpamAssassin::Plugin::Check\n".
                       "util_rb_tld com\nutil_rb_2tld co.uk\n",
    dont_copy_prefs => 1,
  });
  $sa->init(0);
  my $clone = Mail::SpamAssassin::Conf->new($sa);
  $clone->clone($sa->{conf});
  ok($clone->{two_level_domains} == $clone->{multi_level_domains}
       && $clone->{two_level_domains}{'co.uk'},
     "aliases survive config clone");

  ($errors, $conf) = lint_config("util_rb_2tld co.uk\nclear_util_rb");
  ok(!$conf->{two_level_domains}, "clear_util_rb clears deprecated aliases");
}
