#!/usr/bin/perl

# Test regular expression base-string extraction in
# Mail::SpamAssassin::Plugin::BodyRuleBaseExtractor

use lib '.'; use lib 't';
use SATest; sa_t_init("re_base_extraction");
use Test;
use strict;
use warnings;

BEGIN { 
  if (-e 't/test_dir') { chdir 't'; } 
  if (-e 'test_dir') { unshift(@INC, '../blib/lib'); }

  plan tests => 20;

};
use lib '../lib';

try_extraction ('
    body FOO /foo bar/
    body EXCUSE_REMOVE /to be removed from.{0,20}(?:mailings|offers)/i
    body KAM_STOCKTIP15 /(?:Nano Superlattice Technology|NSLT)/is
    body TEST1 /foo(?:ish)? bar/
    body TEST2 /foody* bar/
    body TEST3 /foody? bar/
    body TEST4 /A(?i:ct) N(?i:ow)/
    body TEST5 /time to refinance|refinanc\w{1,3}\b.{0,16}\bnow\b/i
    # body TEST6 /(?:Current|Target)(?: Price)?:\s+\$(?:O\.|\d\.O)/

', {
    base_extract => 1,
    bases_must_be_casei => 1,
    bases_can_use_alternations => 0,
    bases_can_use_quantifiers => 0,
    bases_can_use_char_classes => 0,
    bases_split_out_alternations => 1
}, [

    'foo bar:TEST1 FOO',
    'to be removed from:EXCUSE_REMOVE',
    'nslt:KAM_STOCKTIP15',
    'nano superlattice technology:KAM_STOCKTIP15',
    'fooish bar:TEST1',
    'act now:TEST4',
    'food:TEST2',
    'food bar:TEST3 TEST2',
    'foody bar:TEST3 TEST2',
    'refinanc:TEST5',
    'time to refinance:TEST5',


]);

try_extraction ('
    body FOO /foo bar/
    body EXCUSE_REMOVE /to be removed from.{0,20}(?:mailings|offers)/i
    body KAM_STOCKTIP15 /(?:Nano Superlattice Technology|NSLT)/is
    body TEST1 /foo(?:ish)? bar/

', {
    base_extract => 1,
    bases_must_be_casei => 1,
    bases_can_use_alternations => 0,
    bases_can_use_quantifiers => 0,
    bases_can_use_char_classes => 0,
    bases_split_out_alternations => 0
}, [

    'foo bar:FOO',
    'to be removed from:EXCUSE_REMOVE',
],[

    'foo bar:FOO TEST1',
    'nano superlattice technology:KAM_STOCKTIP15',
    'fooish bar:TEST1'

]);
###########################################################################

use Mail::SpamAssassin;

sub try_extraction {
  my ($rules, $params, $output, $notoutput) = @_;

  my $sa = Mail::SpamAssassin->new({
    rules_filename => "log/test_rules_copy",
    site_rules_filename => "log/test_default.cf",
    userprefs_filename  => "log/userprefs.cf",
    local_tests_only    => 1,
    debug             => 1,
    dont_copy_prefs   => 1,
  });
  ok($sa);

  # remove all rules and plugins; we want just our stuff
  unlink(<log/test_rules_copy/*.pre>);
  unlink(<log/test_rules_copy/*.pm>);
  unlink(<log/test_rules_copy/*.cf>);

  open (OUT, ">log/test_rules_copy/00_test.cf") or die "failed to write rule";
  print OUT "
    loadplugin Mail::SpamAssassin::Plugin::BodyRuleBaseExtractor
    ".$rules;
  close OUT;

  my ($k, $v);
  while (($k, $v) = each %{$params}) { $sa->{$k}=$v; }

  $sa->init();
  ok ($sa->lint_rules() == 0) or warn "lint failed: $rules";

  my $conf = $sa->{conf};
  my $ruletype = "body_0";
  foreach my $key1 (sort keys %{$conf->{base_orig}->{$ruletype}}) {
    print "INPUT: $key1 $conf->{base_orig}->{$ruletype}->{$key1}\n";
  }
  my %found = ();
  foreach my $key (sort keys %{$conf->{base_string}->{$ruletype}}) {
    my $str = "$key:$conf->{base_string}->{$ruletype}->{$key}";
    print "BASES: '$str'\n";
    $found{$str} = 1;
  }

  # $output ||= [];
  foreach my $line (@{$output}) {
    ok($found{$line}) or warn "failed to find '$line'";
  }

  $notoutput ||= [];
  foreach my $line (@{$notoutput}) {
    ok(!$found{$line}) or warn "found '$line' but didn't want to";
  }
}


