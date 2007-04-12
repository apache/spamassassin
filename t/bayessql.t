#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest;
use Test;

use constant TEST_ENABLED => conf_bool('run_bayes_sql_tests');
use constant HAS_DBI => eval { require DBI; }; # for our cleanup stuff

BEGIN { 
  if (-e 't/test_dir') {
    chdir 't';
  }

  if (-e 'test_dir') {
    unshift(@INC, '../blib/lib');
  }

  plan tests => ((TEST_ENABLED && HAS_DBI) ? 53 : 0);

  onfail => sub {
    warn "\n\nNote: Failure may be due to an incorrect config.";
  }
};

exit unless TEST_ENABLED;

my $dbdsn = conf('bayes_sql_dsn');
my $dbusername = conf('bayes_sql_username');
my $dbpassword = conf('bayes_sql_password');

my $dbconfig = '';
foreach my $setting (qw(
                  bayes_store_module
                  bayes_sql_dsn
                  bayes_sql_username
                  bayes_sql_password
                ))
{
  $val = conf($setting);
  $dbconfig .= "$setting $val\n" if $val;
}

my $testuser = 'tstusr.'.$$.'.'.time();

sa_t_init("bayes");

tstlocalrules ("
$dbconfig
bayes_sql_override_username $testuser
loadplugin validuserplugin ../../data/validuserplugin.pm
bayes_sql_username_authorized 1
");

use Mail::SpamAssassin;

my $sa = create_saobj();

$sa->init();

ok($sa);

ok($sa->{bayes_scanner});

ok($sa->{bayes_scanner}->{store}->tie_db_writable());

# This bit breaks abstraction a bit, the userid is an implementation detail,
# but is necessary to perform some of the tests.  Perhaps in the future we
# can add some sort of official API for this sort of thing.
my $testuserid = $sa->{bayes_scanner}->{store}->{_userid};
ok(defined($testuserid));

ok($sa->{bayes_scanner}->{store}->clear_database());

ok(database_clear_p($testuser, $testuserid));

$sa->finish_learner();

undef $sa;

sa_t_init("bayes");

tstlocalrules ("
$dbconfig
bayes_sql_override_username iwillfail
loadplugin validuserplugin ../../data/validuserplugin.pm
bayes_sql_username_authorized 1
");

$sa = create_saobj();

$sa->init();

ok($sa);

ok($sa->{bayes_scanner});

ok(!$sa->{bayes_scanner}->{store}->tie_db_writable());

$sa->finish_learner();

undef $sa;

sa_t_init("bayes");

tstlocalrules ("
$dbconfig
bayes_sql_override_username $testuser
");

$sa = create_saobj();

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

my @msg;
foreach my $line (split(/^/m,$raw_message)) {
  $line =~ s/\r$//;
  push(@msg, $line);
}

my $mail = $sa->parse( \@msg );

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

# This bit breaks abstraction a bit, the userid is an implementation detail,
# but is necessary to perform some of the tests.  Perhaps in the future we
# can add some sort of official API for this sort of thing.
$testuserid = $sa->{bayes_scanner}->{store}->{_userid};
ok(defined($testuserid));

ok($sa->{bayes_scanner}->{store}->clear_database());

ok(database_clear_p($testuser, $testuserid));

$sa->finish_learner();

undef $sa;

sa_t_init('bayes'); # this wipes out what is there and begins anew

# make sure we learn to a journal
tstlocalrules ("
$dbconfig
bayes_min_spam_num 10
bayes_min_ham_num 10
bayes_sql_override_username $testuser
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

@msg = ();
foreach my $line (split(/^/m,$raw_message)) {
  $line =~ s/\r$//;
  push(@msg, $line);
}

$mail = $sa->parse( \@msg );

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

@msg = ();
foreach my $line (split(/^/m,$raw_message)) {
  $line =~ s/\r$//;
  push(@msg, $line);
}

$mail = $sa->parse( \@msg );

$body = $sa->{bayes_scanner}->get_body_from_msg($mail);

$msgstatus = Mail::SpamAssassin::PerMsgStatus->new($sa, $mail);

$score = $sa->{bayes_scanner}->scan($msgstatus, $mail, $body);

# Pretty much we can't count on the data returned with such little training
# so just make sure that the score wasn't equal to .5 which is the default
# return value.
print "\treturned score: $score\n";
ok($score =~ /\d/ && $score <= 1.0 && $score != .5);
}

# This bit breaks abstraction a bit, the userid is an implementation detail,
# but is necessary to perform some of the tests.  Perhaps in the future we
# can add some sort of official API for this sort of thing.
$testuserid = $sa->{bayes_scanner}->{store}->{_userid};
ok(defined($testuserid));

ok($sa->{bayes_scanner}->{store}->clear_database());

ok(database_clear_p($testuser, $testuserid));

$sa->finish_learner();

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

# WARNING! Do not use this as an example, this breaks abstraction and here strictly
# to help the regression tests.
sub database_clear_p {
  my ($username, $userid) = @_;

  my $dbh = DBI->connect($dbdsn,$dbusername,$dbpassword);

  if (!defined($dbh)) {
    return 0;
  }

  my @row_ary;

  my $sql = "SELECT count(*) from bayes_vars where username = ?";
  @row_ary = $dbh->selectrow_array($sql, undef, $username);
  return 0 if ($row_ary[0] != 0);

  $sql = "SELECT count(*) from bayes_token where id = ?";
  @row_ary = $dbh->selectrow_array($sql, undef, $userid);
  return 0 if ($row_ary[0] != 0);

  $sql = "SELECT count(*) from bayes_seen where id = ?";
  @row_ary = $dbh->selectrow_array($sql, undef, $userid);
  return 0 if ($row_ary[0] != 0);

  $sql = "SELECT count(*) from bayes_expire where id = ?";
  @row_ary = $dbh->selectrow_array($sql, undef, $userid);
  return 0 if ($row_ary[0] != 0);

  $dbh->disconnect();

  return 1;
}

  
