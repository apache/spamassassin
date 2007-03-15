#!/usr/bin/perl

# Test regular expression base-string extraction in
# Mail::SpamAssassin::Plugin::BodyRuleBaseExtractor

use lib '.'; use lib 't'; use lib '../lib';
use SATest; sa_t_init("re_base_extraction");
use Test;
use strict;
use warnings;

my $debug = 0;
my $running_perl56 = ($] < 5.007);

# perl 5.6.1 on Solaris fails all tests here if PERL_DL_NONLAZY=1
# but works fine if it is =0.  ho hum
$ENV{'PERL_DL_NONLAZY'} = 0;

close STDIN;    # inhibits noise from sa-compile

BEGIN { 
  if (-e 't/test_dir') { chdir 't'; } 
  if (-e 'test_dir') { unshift(@INC, '../blib/lib'); }

  plan tests => 112;

};
use lib '../lib';

# ---------------------------------------------------------------------------

1 and try_extraction ('

  body FOO /(?:(?:bbbb)|dddd (?:eeee )?by|aaaa)/i

', {
    base_extract => 1,
    bases_must_be_casei => 1,
    bases_can_use_alternations => 0,
    bases_can_use_quantifiers => 0,
    bases_can_use_char_classes => 0,
    bases_split_out_alternations => 1
}, [

  'bbbb:FOO',
  'dddd by:FOO',
  'dddd eeee by:FOO',
  'aaaa:FOO'

], [ ]);

# ---------------------------------------------------------------------------

1 and try_extraction ('
    body TEST5 /time to refinance|refinanc\w{1,3}\b.{0,16}\bnow\b/i

', {
    base_extract => 1,
    bases_must_be_casei => 1,
    bases_can_use_alternations => 0,
    bases_can_use_quantifiers => 0,
    bases_can_use_char_classes => 0,
    bases_split_out_alternations => 1
}, [
    'refinanc:TEST5',
], [ ]);

# ---------------------------------------------------------------------------

1 and try_extraction ('
    body TEST2 /foody* bar/
    body TEST3 /foody? bar/


', {
    base_extract => 1,
    bases_must_be_casei => 1,
    bases_can_use_alternations => 0,
    bases_can_use_quantifiers => 0,
    bases_can_use_char_classes => 0,
    bases_split_out_alternations => 1
}, [

    'food:TEST2',
    'food bar:TEST2 TEST3',
    'foody bar:TEST2 TEST3',

], [ ]);

# ---------------------------------------------------------------------------

1 and try_extraction ('

  body __SARE_FRAUD_BADTHINGS /(?:all funds will be returned|ass?ylum|assassinate|(?:auto|boat|car|plane|train).{1,7}(?:crash|accident|disaster|wreck)|before they both died|brutal acts|cancer|coup attempt|disease|due to the current|\bexile\b|\bfled|\bflee\b|have been frozen|impeach|\bkilled|land dispute|murder|over-invoice|political crisis|poisoned (?:to death )?by|relocate|since the demise|\bslay\b)/i

  body __FRAUD_PTS /\b(?:ass?ass?inat(?:ed|ion)|murder(?:e?d)?|kill(?:ed|ing)\b[^.]{0,99}\b(?:war veterans|rebels?))\b/i

', {
    base_extract => 1,
    bases_must_be_casei => 1,
    bases_can_use_alternations => 0,
    bases_can_use_quantifiers => 0,
    bases_can_use_char_classes => 0,
    bases_split_out_alternations => 1
}, [

  'accident:__SARE_FRAUD_BADTHINGS',
  'all funds will be returned:__SARE_FRAUD_BADTHINGS',
  'asasinated:__FRAUD_PTS',
  'asasination:__FRAUD_PTS',
  'asassinated:__FRAUD_PTS',
  'asassination:__FRAUD_PTS',
  'assasinated:__FRAUD_PTS',
  'assasination:__FRAUD_PTS',
  'assassinate:__SARE_FRAUD_BADTHINGS',
  'assassinated:__FRAUD_PTS __SARE_FRAUD_BADTHINGS',
  'assassination:__FRAUD_PTS',
  'assylum:__SARE_FRAUD_BADTHINGS',
  'asylum:__SARE_FRAUD_BADTHINGS',
  'before they both died:__SARE_FRAUD_BADTHINGS',
  'brutal acts:__SARE_FRAUD_BADTHINGS',
  'cancer:__SARE_FRAUD_BADTHINGS',
  'coup attempt:__SARE_FRAUD_BADTHINGS',
  'crash:__SARE_FRAUD_BADTHINGS',
  'disaster:__SARE_FRAUD_BADTHINGS',
  'disease:__SARE_FRAUD_BADTHINGS',
  'due to the current:__SARE_FRAUD_BADTHINGS',
  'exile:__SARE_FRAUD_BADTHINGS',
  'fled:__SARE_FRAUD_BADTHINGS',
  'flee:__SARE_FRAUD_BADTHINGS',
  'have been frozen:__SARE_FRAUD_BADTHINGS',
  'impeach:__SARE_FRAUD_BADTHINGS',
  'killed:__FRAUD_PTS __SARE_FRAUD_BADTHINGS',
  'killing:__FRAUD_PTS',
  'land dispute:__SARE_FRAUD_BADTHINGS',
  'murder:__FRAUD_PTS __SARE_FRAUD_BADTHINGS',
  'over-invoice:__SARE_FRAUD_BADTHINGS',
  'plane:__SARE_FRAUD_BADTHINGS',
  'poisoned by:__SARE_FRAUD_BADTHINGS',
  'poisoned to death by:__SARE_FRAUD_BADTHINGS',
  'political crisis:__SARE_FRAUD_BADTHINGS',
  'relocate:__SARE_FRAUD_BADTHINGS',
  'since the demise:__SARE_FRAUD_BADTHINGS',
  'slay:__SARE_FRAUD_BADTHINGS',
  'train:__SARE_FRAUD_BADTHINGS',
  'war veterans:__FRAUD_PTS',
  'wreck:__SARE_FRAUD_BADTHINGS',

], [ ]);

# ---------------------------------------------------------------------------
# skip this one for perl 5.6.*; it does not truncate the long strings in the
# same place as 5.8.* and 5.9.*, although they still work fine

($running_perl56) and ok(1);
($running_perl56) and ok(1);
($running_perl56) and ok(1);
($running_perl56) and ok(1);
(!$running_perl56) and try_extraction ('

  body VIRUS_WARNING345                /(This message contained attachments that have been blocked by Guinevere|This is an automatic message from the Guinevere Internet Antivirus Scanner)\./

', {
    base_extract => 1,
    bases_must_be_casei => 1,
    bases_can_use_alternations => 0,
    bases_can_use_quantifiers => 0,
    bases_can_use_char_classes => 0,
    bases_split_out_alternations => 1
}, [

  'this is an automatic message from the guinevere internet ant:VIRUS_WARNING345',
  'this message contained attachments that have been blocked by:VIRUS_WARNING345'

], [ ]);

# ---------------------------------------------------------------------------

try_extraction ('
    body FOO /(?:Viagra|Valium|Xanax|Soma|Cialis){2}/i

', {
    base_extract => 1,
    bases_must_be_casei => 1,
    bases_can_use_alternations => 0,
    bases_can_use_quantifiers => 0,
    bases_can_use_char_classes => 0,
    bases_split_out_alternations => 1
}, [

  'cialis:FOO',
  'soma:FOO',
  'valium:FOO',
  'viagra:FOO',
  'xanax:FOO'

], [ ]);

# ---------------------------------------------------------------------------

try_extraction ('
    body FOO /\brecords (?:[a-z_,-]+ )+?(?:feature|(?:a|re)ward)/i

', {
    base_extract => 1,
    bases_must_be_casei => 1,
    bases_can_use_alternations => 0,
    bases_can_use_quantifiers => 0,
    bases_can_use_char_classes => 0,
    bases_split_out_alternations => 1
}, [

    'records :FOO'

], [ ]);

# ---------------------------------------------------------------------------

try_extraction ('
    body EXCUSE_REMOVE /to .{0,20}(?:mailings|offers)/i
    body TEST2 /foody* bar/
    body TEST1A /fo(?:oish|o) bar/


', {
    base_extract => 1,
    bases_must_be_casei => 1,
    bases_can_use_alternations => 0,
    bases_can_use_quantifiers => 0,
    bases_can_use_char_classes => 0,
    bases_split_out_alternations => 1
}, [


    'foo bar:TEST1A',
    'food:TEST2',
    'fooish bar:TEST1A',
    'mailings:EXCUSE_REMOVE',
    'offers:EXCUSE_REMOVE',

], [ ]);

# ---------------------------------------------------------------------------

try_extraction ('
    body EXCUSE_REMOVE /to .{0,20}(?:mail(ings|food)|o(ffer|blarg)s)/i
    body TEST2 /foody* bar/


', {
    base_extract => 1,
    bases_must_be_casei => 1,
    bases_can_use_alternations => 0,
    bases_can_use_quantifiers => 0,
    bases_can_use_char_classes => 0,
    bases_split_out_alternations => 1
}, [

    'food:TEST2',
    'mailfood:EXCUSE_REMOVE TEST2',
    'mailings:EXCUSE_REMOVE',
    'oblargs:EXCUSE_REMOVE',
    'offers:EXCUSE_REMOVE',

], [ ]);

# ---------------------------------------------------------------------------

try_extraction ('
    body FOO /foo bar/
    body EXCUSE_REMOVE /to be removed from.{0,20}(?:mailings|offers)/i
    body KAM_STOCKTIP15 /(?:Nano Superlattice Technology|NSLT)/is
    body TEST1 /foo(?:ish)? bar/
    body TEST1A /fo(?:oish|o) bar/
    body TEST1B /fo(?:oish|o)? bar/
    body TEST2 /foody* bar/
    body TEST3 /foody? bar/
    body TEST4 /A(?i:ct) N(?i:ow)/
    body TEST5 /time to refinance|refinanc\w{1,3}\b.{0,16}\bnow\b/i
    body TEST6 /(?:Current|Target)(?: Price)?:\s+\$(?:O\.|\d\.O)/
    body TEST7 /(?!credit)[ck\xc7\xe7@]\W?r\W?[e3\xc8\xc9\xca\xcb\xe8\xe9\xea\xeb\xa4]\W?[d\xd0]\W?[il|!1y?\xcc\xcd\xce\xcf\xec\xed\xee\xef]\W?t/i


', {
    base_extract => 1,
    bases_must_be_casei => 1,
    bases_can_use_alternations => 0,
    bases_can_use_quantifiers => 0,
    bases_can_use_char_classes => 0,
    bases_split_out_alternations => 1
}, [

    'fo bar:TEST1B',
    'foo bar:FOO TEST1 TEST1A TEST1B',
    'to be removed from:EXCUSE_REMOVE',
    'nslt:KAM_STOCKTIP15',
    'nano superlattice technology:KAM_STOCKTIP15',
    'fooish bar:TEST1 TEST1A TEST1B',
    'act now:TEST4',
    'food:TEST2',
    'food bar:TEST2 TEST3',
    'foody bar:TEST2 TEST3',
    'refinanc:TEST5',
    'target::TEST6',
    'target price::TEST6',
    'current::TEST6',
    'current price::TEST6',

], [

    # we do not want to see these
    '!credit:TEST7'

]);

# ---------------------------------------------------------------------------

try_extraction ('
    body FOO /foo bar/
    body EXCUSE_REMOVE /to be removed from.{0,20}(?:mailings|offers)/i
    body KAM_STOCKTIP15 /(?:Nano Superlattice Technology|NSLT)/is

    # this should not result in a match on "foo bar" since we are not
    # splitting alts in this test
    body TEST1 /fo(?:oish|o)? b(a|b)r/
    body TEST2 /fo(?:oish|o) b(a|b)r/

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
    'foo bar:FOO TEST2',
    'nano superlattice technology:KAM_STOCKTIP15',
    'fooish bar:TEST1',
    'fooish bar:TEST2'

]);

#############################################################################

use Mail::SpamAssassin;

sub try_extraction {
  my ($rules, $params, $output, $notoutput) = @_;

  my $sa = Mail::SpamAssassin->new({
    rules_filename => "log/test_rules_copy",
    site_rules_filename => "log/test_default.cf",
    userprefs_filename  => "log/userprefs.cf",
    local_tests_only    => 1,
    debug             => $debug,
    dont_copy_prefs   => 1,
  });
  ok($sa);

  # remove all rules and plugins; we want just our stuff
  unlink(<log/test_rules_copy/*.pre>);
  unlink(<log/test_rules_copy/*.pm>);
  unlink(<log/test_rules_copy/*.cf>);

  open (OUT, ">log/test_rules_copy/00_test.cf") or die "failed to write rule";
  print OUT "
    use_bayes 0     # disable bayes loading
    loadplugin Mail::SpamAssassin::Plugin::Check
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


