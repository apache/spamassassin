#!/usr/bin/perl -T

use File::Find qw(find);
use lib '.'; use lib 't';
use SATest; sa_t_init("bayesdbm");

use constant HAS_DB_FILE => eval { require DB_File };
 
use Test::More;

plan skip_all => "Long running tests disabled" unless conf_bool('run_long_tests');
plan skip_all => "DB_File is unavailable" unless HAS_DB_FILE;
plan tests => 54;

tstprefs ("
  bayes_learn_to_journal 0
");

use Mail::SpamAssassin;

my $sa = create_saobj();

$sa->init();

sub getimpl {
  return $sa->call_plugins("learner_get_implementation");
}
ok($sa);

ok ($sa->{bayes_scanner} && getimpl);

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

my $body = getimpl->get_body_from_msg($mail);

ok($body);

my $toks = getimpl->tokenize($mail, $body);

ok(scalar(keys %{$toks}) > 0);

my $msgid = $mail->generate_msgid();
my $msgid_hdr = $mail->get_msgid();

# $msgid is the generated hash messageid
# $msgid_hdr is the Message-Id header
ok($msgid eq '71f849915d7e469ddc1890cd8175f6876843f99e@sa_generated')
    or warn "got: [$msgid]";
ok($msgid_hdr eq '9PS291LhupY');

ok(getimpl->{store}->tie_db_writable());

ok(!getimpl->{store}->seen_get($msgid));

getimpl->{store}->untie_db();

ok($sa->{bayes_scanner}->learn(1, $mail));

ok(!$sa->{bayes_scanner}->learn(1, $mail));

ok(getimpl->{store}->tie_db_writable());

ok(getimpl->{store}->seen_get($msgid) eq 's');

getimpl->{store}->untie_db();

ok(getimpl->{store}->tie_db_writable());

my $tokerror = 0;
foreach my $tok (keys %{$toks}) {
  my ($spam, $ham, $atime) = getimpl->{store}->tok_get($tok);
  if ($spam == 0 || $ham > 0) {
    $tokerror = 1;
  }
}
ok(!$tokerror);

my $tokens = getimpl->{store}->tok_get_all(keys %{$toks});

ok($tokens);

$tokerror = 0;
foreach my $tok (@{$tokens}) {
  my ($token, $tok_spam, $tok_ham, $atime) = @{$tok};
  if ($tok_spam == 0 || $tok_ham > 0) {
    $tokerror = 1;
  }
}
ok(!$tokerror);

getimpl->{store}->untie_db();

ok($sa->{bayes_scanner}->learn(0, $mail));

ok(getimpl->{store}->tie_db_writable());

ok(getimpl->{store}->seen_get($msgid) eq 'h');

getimpl->{store}->untie_db();

ok(getimpl->{store}->tie_db_writable());

$tokerror = 0;
foreach my $tok (keys %{$toks}) {
  my ($spam, $ham, $atime) = getimpl->{store}->tok_get($tok);
  if ($spam  > 0 || $ham == 0) {
    $tokerror = 1;
  }
}
ok(!$tokerror);

getimpl->{store}->untie_db();

ok($sa->{bayes_scanner}->forget($mail));

ok(getimpl->{store}->tie_db_writable());

ok(!getimpl->{store}->seen_get($msgid));

getimpl->{store}->untie_db();

undef $sa;

sa_t_init('bayesdbm'); # this wipes out what is there and begins anew

# make sure we learn to a journal
tstprefs ("
  bayes_learn_to_journal 1
");

$sa = create_saobj();

$sa->init();

ok(!-e "$userstate/bayes_journal");

ok($sa->{bayes_scanner}->learn(1, $mail));

ok(-e "$userstate/bayes_journal");

$sa->{bayes_scanner}->sync(1); # always returns 0, so no need to check return

ok(!-e "$userstate/bayes_journal");

ok(-e "$userstate/bayes_seen");

ok(-e "$userstate/bayes_toks");

undef $sa;

sa_t_init('bayesdbm'); # this wipes out what is there and begins anew

# make sure we learn to a journal
tstprefs ("
  bayes_learn_to_journal 0
  bayes_min_spam_num 10
  bayes_min_ham_num 10
");

# we get to bastardize the existing pattern matching code here.  It lets us provide
# our own checking callback and keep using the existing ok_all_patterns call
%patterns = ( 1 => 'Acted on message' );

$wanted_examined = count_files("data/spam");
ok(salearnrun("--spam data/spam", \&check_examined));
ok_all_patterns();

$wanted_examined = count_files("data/nice");
ok(salearnrun("--ham data/nice", \&check_examined));
ok_all_patterns();

$wanted_examined = count_files("data/welcomelists");
ok(salearnrun("--ham data/welcomelists", \&check_examined));
ok_all_patterns();

$wanted_examined = 3;
ok(salearnrun("--ham --mbox data/nice.mbox", \&check_examined));
ok_all_patterns();

$wanted_examined = 3;
ok(salearnrun("--ham --mbox < data/nice.mbox", \&check_examined));
ok_all_patterns();

$wanted_examined = 3;
ok(salearnrun("--forget --mbox data/nice.mbox", \&check_examined));
ok_all_patterns();

%patterns = ( 'non-token data: bayes db version' => 'db version' );
ok(salearnrun("--dump magic", \&patterns_run_cb));
ok_all_patterns();

use constant SCAN_USING_PERL_CODE_TEST => 1;
# jm: off! not working for some reason.   Mind you, this is
# not a supported way to call these APIs!  so no biggie

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

$body = getimpl->get_body_from_msg($mail);

my $msgstatus = Mail::SpamAssassin::PerMsgStatus->new($sa, $mail);

ok($msgstatus);

my $score = getimpl->scan($msgstatus, $mail, $body);

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

$body = getimpl->get_body_from_msg($mail);

$msgstatus = Mail::SpamAssassin::PerMsgStatus->new($sa, $mail);

$score = getimpl->scan($msgstatus, $mail, $body);

# Pretty much we can't count on the data returned with such little training
# so just make sure that the score wasn't equal to .5 which is the default
# return value.
print "\treturned score: $score\n";
ok($score =~ /\d/ && $score <= 1.0 && $score != .5);

}

ok(getimpl->{store}->clear_database());

ok(!-e "$userstate/bayes_journal");
ok(!-e "$userstate/bayes_seen");
ok(!-e "$userstate/bayes_toks");

sub check_examined {
  local ($_);
  my $string = shift;

  if (defined $string) {
    $_ = $string;
  } else {
    $_ = join ('', <IN>);
  }

  if ($_ =~ /(?:Forgot|Learned) tokens from \d+ message\(s\) \((\d+) message\(s\) examined\)/) {
    #print STDERR "examined $1 messages\n";
    if (defined $wanted_examined && $wanted_examined == $1) {
      $found{'Acted on message'}++;
    }
  }
}

sub count_files {
  my $cnt = 0;
  find({wanted => sub { $cnt++ if -f $_; }, no_chdir => 1}, $_[0]);
  return $cnt;
}

