#!/usr/bin/perl -T

use strict;
use warnings;
use re 'taint';
use lib '.'; use lib 't';
use version 0.77;

use SATest; sa_t_init("dkim");

use vars qw(%patterns %anti_patterns);

my $tests = 258;
my $version;

use constant HAS_DKIM_VERIFIER => eval {
  require Mail::DKIM::Verifier;
  $version = version->parse(Mail::DKIM::Verifier->VERSION);
  $version >= version->parse(0.31);
};

use Test::More;
plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');
plan skip_all => "Needs Mail::DKIM::Verifier >= 0.31" unless HAS_DKIM_VERIFIER ;

$tests -= 8 if $version < version->parse(0.37);
$tests -= 16 if $version < version->parse(0.34);
plan tests => $tests;

use IO::File;
use Mail::SpamAssassin;


# ---------------------------------------------------------------------------
my $spamassassin_obj;

sub process_sample_file($) {
  my($fn) = @_;  # file name
  my($mail_obj, $per_msg_status, $spam_report);
  $spamassassin_obj->timer_reset;
  my $fh = IO::File->new;
  $fh->open($fn,'<') or die "cannot open file $fn: $!";
  $mail_obj = $spamassassin_obj->parse($fh,0);
  if ($mail_obj) {
    local($1,$2,$3,$4,$5,$6);  # avoid Perl 5.8.x bug, $1 can get tainted
    $per_msg_status = $spamassassin_obj->check($mail_obj);
  }
  if ($per_msg_status) {
    $spam_report = $per_msg_status->get_tag('REPORT');
    $per_msg_status->finish;
  }
  if ($mail_obj) {
    $mail_obj->finish;
  }
  $fh->close or die "error closing file $fn: $!";
  $spam_report =~ s/\A(\s*\n)+//s;
# print "\t$spam_report\n";
  return $spam_report;
}

sub test_samples($$) {
  my($test_filenames, $patt_antipatt_list) = @_;
  for my $fn (sort { $a cmp $b } @$test_filenames) {
    my $el = $patt_antipatt_list->[0];
    shift @$patt_antipatt_list if @$patt_antipatt_list > 1; # last autorepeats
    my($patt,$anti) = split(m{\s* / \s*}x, $el, 2);
    %patterns      = map { (" $_ ", " $_ $fn ") } split(' ',$patt);
    %anti_patterns = map { (" $_ ", " $_ $fn ") } split(' ',$anti);
    print "Testing sample $fn\n";
    my $spam_report = process_sample_file($fn);
    clear_pattern_counters();
    patterns_run_cb($spam_report);
    my $status = ok_all_patterns();
    printf("\nTest on file %s failed:\n%s\n", $fn,$spam_report)  if !$status;
  }
}

# ensure rules will fire, and disable some expensive ones
tstlocalrules("
  full   DKIM_SIGNED           eval:check_dkim_signed()
  full   DKIM_VALID            eval:check_dkim_valid()
  full   DKIM_VALID_AU         eval:check_dkim_valid_author_sig()
  meta   DKIM_INVALID          DKIM_SIGNED && !DKIM_VALID
  header DKIM_ADSP_NXDOMAIN    eval:check_dkim_adsp('N')
  header DKIM_ADSP_DISCARD     eval:check_dkim_adsp('D')
  header DKIM_ADSP_ALL         eval:check_dkim_adsp('A')
  header DKIM_ADSP_CUSTOM_LOW  eval:check_dkim_adsp('1')
  header DKIM_ADSP_CUSTOM_MED  eval:check_dkim_adsp('2')
  header DKIM_ADSP_CUSTOM_HIGH eval:check_dkim_adsp('3')
  adsp_override sa-test-nxd.spamassassin.org  nxdomain
  adsp_override sa-test-unk.spamassassin.org  unknown
  adsp_override sa-test-all.spamassassin.org  all
  adsp_override sa-test-dis.spamassassin.org  discardable
  adsp_override sa-test-di2.spamassassin.org

  dkim_minimum_key_bits 512
  score DKIM_SIGNED          -0.1
  score DKIM_VALID           -0.1
  score DKIM_INVALID	      0.1
  score DKIM_VALID_AU        -0.1
  score DKIM_ADSP_NXDOMAIN    0.1
  score DKIM_ADSP_DISCARD     0.1
  score DKIM_ADSP_ALL         0.1
  score DKIM_ADSP_CUSTOM_LOW  0.1
  score DKIM_ADSP_CUSTOM_MED  0.1
  score DKIM_ADSP_CUSTOM_HIGH 0.1
  header DKIM_ADSP_SEL_TEST   eval:check_dkim_adsp('*', .spamassassin.org)
  priority DKIM_ADSP_SEL_TEST -100
  score  DKIM_ADSP_SEL_TEST   0.1
");

my $dirname = "data/dkim";

$spamassassin_obj = Mail::SpamAssassin->new({
  rules_filename      => $localrules,
  site_rules_filename => $siterules,
  userprefs_filename  => $userrules,
  dont_copy_prefs     => 1,
  require_rules       => 1,
# debug               => 'dkim',
  post_config_text => q{
    dns_available yes
    use_auto_whitelist 0
    use_bayes 0
    use_razor2 0
    use_pyzor 0
    use_dcc 0
  },
});
ok($spamassassin_obj);
$spamassassin_obj->compile_now;  # try to preloaded most modules

print "Using Mail::DKIM version $version\n";

# mail samples test-pass* should all pass DKIM validation
my($fn, @test_filenames, @patt_antipatt_list);
local *DIR;
opendir(DIR, $dirname) or die "Cannot open directory $dirname: $!";
while (defined($fn = readdir(DIR))) {
  next  if $fn eq '.' || $fn eq '..';
  # skip test cases that fail in older versions of Mail::DKIM
  next  if $fn !~ /^test-pass-\d*\.msg$/;
  next if $version < version->parse(0.34) && $fn =~ /^test-pass-1[34]\.msg$/;
  next if $version < version->parse(0.37) && $fn =~ /^test-pass-15\.msg$/;
  push(@test_filenames, "$dirname/$fn");
}
closedir(DIR) or die "Error closing directory $dirname: $!";
@patt_antipatt_list = (
  'DKIM_SIGNED DKIM_VALID DKIM_VALID_AU / DKIM_INVALID DKIM_ADSP_NXDOMAIN DKIM_ADSP_DISCARD DKIM_ADSP_ALL DKIM_ADSP_SEL_TEST'
);
test_samples(\@test_filenames, \@patt_antipatt_list);

# this mail sample is special, doesn't have any signature
@patt_antipatt_list = ( '/ DKIM_SIGNED DKIM_VALID' );
test_samples(["$dirname/test-fail-01.msg"], \@patt_antipatt_list);

# mail samples test-fail* should all fail DKIM validation
@test_filenames = ();
opendir(DIR, $dirname) or die "Cannot open directory $dirname: $!";
while (defined($fn = readdir(DIR))) {
  next  if $fn eq '.' || $fn eq '..';
  next  if $fn !~ /^test-fail-\d*\.msg$/;
  next  if $fn eq "test-fail-01.msg";  # no signature
  push(@test_filenames, "$dirname/$fn");
}
closedir(DIR) or die "Error closing directory $dirname: $!";
@patt_antipatt_list = ( 'DKIM_SIGNED DKIM_INVALID / DKIM_VALID' );
test_samples(\@test_filenames, \@patt_antipatt_list);

# mail samples test-adsp* should all fail DKIM validation, testing ADSP
@test_filenames = ();
opendir(DIR, $dirname) or die "Cannot open directory $dirname: $!";
while (defined($fn = readdir(DIR))) {
  next  if $fn eq '.' || $fn eq '..';
  next  if $fn !~ /^test-adsp-\d*\.msg$/;
  push(@test_filenames, "$dirname/$fn");
}
closedir(DIR) or die "Error closing directory $dirname: $!";
@patt_antipatt_list = (
  ' / DKIM_VALID DKIM_ADSP_NXDOMAIN DKIM_ADSP_DISCARD DKIM_ADSP_ALL', # 11
  'DKIM_ADSP_NXDOMAIN / DKIM_VALID DKIM_ADSP_DISCARD  DKIM_ADSP_ALL', # 12
  'DKIM_ADSP_ALL  / DKIM_VALID DKIM_ADSP_NXDOMAIN DKIM_ADSP_DISCARD', # 13
  'DKIM_ADSP_DISCARD  / DKIM_VALID DKIM_ADSP_NXDOMAIN DKIM_ADSP_ALL', # 14
  'DKIM_ADSP_DISCARD  / DKIM_VALID DKIM_ADSP_NXDOMAIN DKIM_ADSP_ALL', # 15
  ' / DKIM_VALID DKIM_ADSP_NXDOMAIN DKIM_ADSP_DISCARD DKIM_ADSP_ALL', # 16 foo
  ' / DKIM_VALID DKIM_ADSP_NXDOMAIN DKIM_ADSP_DISCARD DKIM_ADSP_ALL', # 17 unk
  'DKIM_ADSP_ALL  / DKIM_VALID DKIM_ADSP_NXDOMAIN DKIM_ADSP_DISCARD', # 18 all
  'DKIM_ADSP_DISCARD  / DKIM_VALID DKIM_ADSP_NXDOMAIN DKIM_ADSP_ALL', # 19 dis
  'DKIM_ADSP_DISCARD  / DKIM_VALID DKIM_ADSP_NXDOMAIN DKIM_ADSP_ALL', # 20 di2
  'DKIM_ADSP_DISCARD  / DKIM_VALID DKIM_ADSP_ALL',                    # 21 nxd
  'DKIM_ADSP_NXDOMAIN / DKIM_VALID DKIM_ADSP_DISCARD  DKIM_ADSP_ALL', # 22 xxx
);
test_samples(\@test_filenames, \@patt_antipatt_list);

STDOUT->autoflush(1);

END {
  $spamassassin_obj->finish  if $spamassassin_obj;
}
