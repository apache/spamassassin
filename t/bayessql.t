#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest;
use Test;

use constant TEST_ENABLED => (-e 'bayessql.cf' || -e 't/bayessql.cf');
use constant HAS_DBI => eval { require DBI; }; # for our cleanup stuff

BEGIN { 
  if (-e 't/test_dir') {
    chdir 't';
  }

  if (-e 'test_dir') {
    unshift(@INC, '../blib/lib');
  }

  plan tests => ((TEST_ENABLED && HAS_DBI) ? 38 : 0);

  onfail => sub {
    warn "\n\nNote: Failure may be due to an incorrect config.";
  }
};

exit unless TEST_ENABLED;

my $dbconfig;
my $dbdsn;
my $dbusername;
my $dbpassword;

open(CONFIG,"<bayessql.cf");
while (my $line = <CONFIG>) {
  $dbconfig .= $line;
  if ($line =~ /^bayes_sql_dsn (.*)/) {
    $dbdsn = $1;
    chomp($dbdsn);
  }
  elsif ($line =~ /^bayes_sql_username (.*)/) {
    $dbusername = $1;
    chomp($dbusername);
  }
  elsif ($line =~ /^bayes_sql_password (.*)/) {
    $dbpassword = $1;
    chomp($dbpassword);
  }
}
close(CONFIG);

my $testuser = 'tstusr.'.$$.'.'.time();

sa_t_init("bayes");

tstlocalrules ("
bayes_store_module Mail::SpamAssassin::BayesStore::SQL
$dbconfig
bayes_sql_override_username $testuser
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

my @msg;
foreach my $line (split(/^/m,$raw_message)) {
  $line =~ s/\r$//;
  push(@msg, $line);
}

my $mail = $sa->parse( \@msg );

ok($mail);

my $body = $sa->{bayes_scanner}->get_body_from_msg($mail);

ok($body);

my @toks = $sa->{bayes_scanner}->tokenize($mail, $body);

ok(scalar(@toks) > 0);

my($msgid,$msgid_hdr) = $sa->{bayes_scanner}->get_msgid($mail);

# $msgid is the generated hash messageid, $msgid_hdr is the Message-Id header ...
ok($msgid eq '502e12b89b9c74074744ffc18a95d80cff2effcd@sa_generated');
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
foreach my $tok (@toks) {
  my ($spam, $ham, $atime) = $sa->{bayes_scanner}->{store}->tok_get($tok);
  if ($spam == 0 || $ham > 0) {
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
foreach my $tok (@toks) {
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

ok(cleanupdb());

sa_t_init('bayes'); # this wipes out what is there and begins anew

# make sure we learn to a journal
tstlocalrules ("
bayes_store_module Mail::SpamAssassin::BayesStore::SQL
$dbconfig
bayes_min_spam_num 10
bayes_min_ham_num 10
bayes_sql_override_username $testuser
");

# we get to bastardize the existing pattern matching code here.  It lets us provide
# our own checking callback and keep using the existing ok_all_patterns call
%patterns = ( 1 => 'Learned from message' );

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
ok($score != .5);

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
ok($score != .5);
}


ok(cleanupdb());

sub check_examined {
  local ($_);
  my $string = shift;

  if (defined $string) {
    $_ = $string;
  } else {
    $_ = join ('', <IN>);
  }

  if ($_ =~ /Learned from \d+ message\(s\) \(\d+ message\(s\) examined\)/) {
    $found{'Learned from message'}++;
  }
}


sub cleanupdb {
  my $rv;
  my $error = 0;

  my $dbh = DBI->connect($dbdsn,$dbusername,$dbpassword);

  if (!defined($dbh)) {
    return 0;
  }

  $rv = $dbh->do("DELETE FROM bayes_vars WHERE username = ?", undef, $testuser);
  if (!defined($rv)) {
    $error = 1;
  }
  $rv = $dbh->do("DELETE FROM bayes_seen WHERE username = ?", undef, $testuser);
  if (!defined($rv)) {
    $error = 1;
  }
  $rv = $dbh->do("DELETE FROM bayes_token WHERE username = ?", undef, $testuser);
  if (!defined($rv)) {
    $error = 1;
  }
  $rv = $dbh->do("DELETE FROM bayes_expire WHERE username = ?", undef, $testuser);
  return !$error;
}
