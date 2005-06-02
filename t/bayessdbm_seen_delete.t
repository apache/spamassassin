#!/usr/bin/perl

use Data::Dumper;
use lib '.'; use lib 't';
use SATest; sa_t_init("bayessdbm_seen_delete");
use Test;

use constant HAS_SDBM_FILE => eval { require SDBM_File; };

BEGIN { 
  if (-e 't/test_dir') {
    chdir 't';
  }

  if (-e 'test_dir') {
    unshift(@INC, '../blib/lib');
  }

  plan tests => (HAS_SDBM_FILE ? 54 : 0);
};

exit unless HAS_SDBM_FILE;

tstlocalrules ("
        bayes_store_module Mail::SpamAssassin::BayesStore::SDBM
        bayes_learn_to_journal 0
");

use Mail::SpamAssassin;

my $sa = create_saobj();

$sa->init();

ok($sa);

ok($sa->{bayes_scanner});

ok(!$sa->{bayes_scanner}->is_scan_available());

open(MAIL,"< data/spam/001");

my $raw_message = do {
  local $/;
  <MAIL>;
};

close(MAIL);
ok($raw_message);

my $mail = $sa->parse( $raw_message );

ok($mail);

my $body = $sa->{bayes_scanner}->get_body_from_msg($mail);

ok($body);

my $toks = $sa->{bayes_scanner}->tokenize($mail, $body);

ok(scalar(keys %{$toks}) > 0);

my($msgid,$msgid_hdr) = $sa->{bayes_scanner}->get_msgid($mail);

# $msgid is the generated hash messageid
# $msgid_hdr is the Message-Id header
ok($msgid eq 'ce33e4a8bc5798c65428d6018380bae346c7c126@sa_generated');
ok($msgid_hdr eq '9PS291LhupY');

ok($sa->{bayes_scanner}->{store}->tie_db_writable());

ok(!$sa->{bayes_scanner}->{store}->seen_get($msgid));

$sa->{bayes_scanner}->{store}->untie_db();

ok($sa->{bayes_scanner}->learn(1, $mail));

ok(!$sa->{bayes_scanner}->learn(1, $mail));

ok($sa->{bayes_scanner}->{store}->tie_db_writable());

ok($sa->{bayes_scanner}->{store}->seen_get($msgid) eq 's');

$sa->{bayes_scanner}->{store}->untie_db();

ok($sa->{bayes_scanner}->{store}->tie_db_writable());

my $tokerror = 0;
foreach my $tok (keys %{$toks}) {
  my ($spam, $ham, $atime) = $sa->{bayes_scanner}->{store}->tok_get($tok);
  if ($spam == 0 || $ham > 0) {
    $tokerror = 1;
  }
}
ok(!$tokerror);

my $tokens = $sa->{bayes_scanner}->{store}->tok_get_all(keys %{$toks});

ok($tokens);

$tokerror = 0;
foreach my $tok (@{$tokens}) {
  my ($token, $tok_spam, $tok_ham, $atime) = @{$tok};
  if ($tok_spam == 0 || $tok_ham > 0) {
    $tokerror = 1;
  }
}
ok(!$tokerror);

$sa->{bayes_scanner}->{store}->untie_db();

ok($sa->{bayes_scanner}->learn(0, $mail));

ok($sa->{bayes_scanner}->{store}->tie_db_writable());

ok($sa->{bayes_scanner}->{store}->seen_get($msgid) eq 'h');

$sa->{bayes_scanner}->{store}->untie_db();

ok($sa->{bayes_scanner}->{store}->tie_db_writable());

$tokerror = 0;
foreach my $tok (keys %{$toks}) {
  my ($spam, $ham, $atime) = $sa->{bayes_scanner}->{store}->tok_get($tok);
  if ($spam  > 0 || $ham == 0) {
    $tokerror = 1;
  }
}
ok(!$tokerror);

$sa->{bayes_scanner}->{store}->untie_db();

ok($sa->{bayes_scanner}->forget($mail));

ok($sa->{bayes_scanner}->{store}->tie_db_writable());

ok(!$sa->{bayes_scanner}->{store}->seen_get($msgid));

$sa->{bayes_scanner}->{store}->untie_db();

undef $sa;

sa_t_init('bayes'); # this wipes out what is there and begins anew

# make sure we learn to a journal
tstlocalrules ("
        bayes_store_module Mail::SpamAssassin::BayesStore::SDBM
        bayes_learn_to_journal 1
");

$sa = create_saobj();

$sa->init();

ok(!-e 'log/user_state/bayes_journal');

ok($sa->{bayes_scanner}->learn(1, $mail));

ok(-e 'log/user_state/bayes_journal');

$sa->{bayes_scanner}->sync(1); # always returns 0, so no need to check return

ok(!-e 'log/user_state/bayes_journal');

ok(-e 'log/user_state/bayes_seen.pag');
ok(-e 'log/user_state/bayes_seen.dir');

ok(-e 'log/user_state/bayes_toks.pag');
ok(-e 'log/user_state/bayes_toks.dir');

undef $sa;

sa_t_init('bayes'); # this wipes out what is there and begins anew

# make sure we learn to a journal
tstlocalrules ("
        bayes_store_module Mail::SpamAssassin::BayesStore::SDBM
bayes_learn_to_journal 0
bayes_min_spam_num 10
bayes_min_ham_num 10
");

# we get to bastardize the existing pattern matching code here.  It lets us provide
# our own checking callback and keep using the existing ok_all_patterns call
%patterns = ( 1 => 'Acted on message' );

ok(salearnrun("--spam data/spam", \&check_examined));
ok_all_patterns();

ok(salearnrun("--ham data/nice", \&check_examined));
ok_all_patterns();

ok(salearnrun("--ham data/whitelists", \&check_examined));
ok_all_patterns();

%patterns = ( 'non-token data: bayes db version' => 'db version' );
ok(salearnrun("--dump magic", \&patterns_run_cb));
ok_all_patterns();

# now delete the journal and bayes_seen -- should still be possible
# for Bayes to continue...
unlink 'log/user_state/bayes_journal';
ok(unlink 'log/user_state/bayes_seen.pag');
ok(unlink 'log/user_state/bayes_seen.dir');

use constant SCAN_USING_PERL_CODE_TEST => 1;

if (SCAN_USING_PERL_CODE_TEST) {
$sa = create_saobj();

$sa->init();

open(MAIL,"< ../sample-nonspam.txt");

$raw_message = do {
  local $/;
  <MAIL>;
};

close(MAIL);

$mail = $sa->parse( $raw_message );

$body = $sa->{bayes_scanner}->get_body_from_msg($mail);

my $msgstatus = Mail::SpamAssassin::PerMsgStatus->new($sa, $mail);

ok($msgstatus);

my $score = $sa->{bayes_scanner}->scan($msgstatus, $mail, $body);

# Pretty much we can't count on the data returned with such little training
# so just make sure that the score wasn't equal to .5 which is the default
# return value.
print "\treturned score: $score\n";
ok($score =~ /\d/ && $score <= 1.0 && $score != .5);

open(MAIL,"< ../sample-spam.txt");

$raw_message = do {
  local $/;
  <MAIL>;
};

close(MAIL);

$mail = $sa->parse( $raw_message );

$body = $sa->{bayes_scanner}->get_body_from_msg($mail);

$msgstatus = Mail::SpamAssassin::PerMsgStatus->new($sa, $mail);

$score = $sa->{bayes_scanner}->scan($msgstatus, $mail, $body);

# Pretty much we can't count on the data returned with such little training
# so just make sure that the score wasn't equal to .5 which is the default
# return value.
print "\treturned score: $score\n";
ok($score =~ /\d/ && $score <= 1.0 && $score != .5);

}

ok($sa->{bayes_scanner}->{store}->clear_database());

ok(!-e 'log/user_state/bayes_journal');
ok(!-e 'log/user_state/bayes_seen.pag');
ok(!-e 'log/user_state/bayes_seen.dir');
ok(!-e 'log/user_state/bayes_toks.pag');
ok(!-e 'log/user_state/bayes_toks.dir');

sub check_examined {
  local ($_);
  my $string = shift;

  if (defined $string) {
    $_ = $string;
  } else {
    $_ = join ('', <IN>);
  }

  if ($_ =~ /(?:Forgot|Learned) tokens from \d+ message\(s\) \(\d+ message\(s\) examined\)/) {
    $found{'Acted on message'}++;
  }
}


