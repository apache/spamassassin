#!/usr/bin/perl -T

use File::Find qw(find);
use lib '.'; use lib 't';
use SATest; sa_t_init("bayessql");

use Test::More;
use Mail::SpamAssassin;

use constant HAS_DBI => eval { require DBI; }; # for our cleanup stuff
use constant SQLITE => eval { require DBD::SQLite; };
use constant SQL => conf_bool('run_bayes_sql_tests');

plan skip_all => "DBI is unavailable on this system" unless (HAS_DBI);
plan skip_all => "Bayes SQL tests are disabled or DBD::SQLite not found" unless (SQLITE || SQL);

my $tests = 0;
$tests += 59 if (SQLITE);
$tests += 59 if (SQL);
plan tests => $tests;

diag "Note: If there is a failure it may be due to an incorrect SQL configuration.";

my ($dbconfig, $dbdsn, $dbusername, $dbpassword);

if (SQLITE) {
  # Try /dev/shm as it's likely memdisk, otherwise SQLite is sloow..
  my $dbdir = tempdir("bayessql.XXXXXX", DIR => -w "/dev/shm" ? "/dev/shm" : "log");
  die "FATAL: failed to create dbdir: $!" unless -d $dbdir;
  $dbdsn = "dbi:SQLite:dbname=$dbdir/bayes.db";
  $dbusername = "";
  $dbpassword = "";
  my $dbh = DBI->connect($dbdsn,$dbusername,$dbpassword);
  $dbh->do("PRAGMA synchronous = OFF");
  $dbh->do("PRAGMA cache_size = 10000");
  $dbh->do("
  CREATE TABLE bayes_expire (
    id int(11) NOT NULL default '0',
    runtime int(11) NOT NULL default '0',
    PRIMARY KEY (id)
  );
  ") or die "Failed to create $dbfile";
  $dbh->do("
  CREATE TABLE bayes_global_vars (
    variable varchar(30) NOT NULL default '',
    value varchar(200) NOT NULL default '',
    PRIMARY KEY (variable)
  );
  ") or die "Failed to create $dbfile";
  $dbh->do("
  INSERT INTO bayes_global_vars VALUES ('VERSION','3');
  ") or die "Failed to create $dbfile";
  $dbh->do("
  CREATE TABLE bayes_seen (
    id int(11) NOT NULL default '0',
    msgid varchar(200) NOT NULL default '' COLLATE binary,
    flag char(1) NOT NULL default '',
    PRIMARY KEY (id,msgid)
  );
  ") or die "Failed to create $dbfile";
  $dbh->do("
  CREATE TABLE bayes_token (
    id int(11) NOT NULL default '0',
    token char(5) NOT NULL default '' COLLATE binary,
    spam_count int(11) NOT NULL default '0',
    ham_count int(11) NOT NULL default '0',
    atime int(11) NOT NULL default '0',
    PRIMARY KEY (id, token)
  );
  ") or die "Failed to create $dbfile";
  $dbh->do("
  CREATE INDEX idx_id_atime ON bayes_token (id, atime);
  ") or die "Failed to create $dbfile";
  $dbh->do("
  CREATE TABLE bayes_vars (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username varchar(200) NOT NULL default '',
    spam_count int(11) NOT NULL default '0',
    ham_count int(11) NOT NULL default '0',
    token_count int(11) NOT NULL default '0',
    last_expire int(11) NOT NULL default '0',
    last_atime_delta int(11) NOT NULL default '0',
    last_expire_reduce int(11) NOT NULL default '0',
    oldest_token_age int(11) NOT NULL default '2147483647',
    newest_token_age int(11) NOT NULL default '0'
  );
  ") or die "Failed to create $dbfile";
  $dbh->do("
  CREATE UNIQUE INDEX idx_username ON bayes_vars (username);
  ") or die "Failed to create $dbfile";

  $dbh->disconnect;
  undef $dbh;

  $dbconfig = "
    bayes_store_module Mail::SpamAssassin::BayesStore::SQL
    bayes_sql_dsn $dbdsn
  ";

  run_bayes();
  rmtree($dbdir);
}

if (SQL) {
  $dbdsn = conf('bayes_sql_dsn');
  $dbusername = conf('bayes_sql_username');
  $dbpassword = conf('bayes_sql_password');

  $dbconfig = '';
  foreach my $setting (qw(
    bayes_store_module
    bayes_sql_dsn
    bayes_sql_username
    bayes_sql_password
    ))
  {
    my $val = conf($setting);
    $dbconfig .= "$setting $val\n" if $val;
  }

  run_bayes();
}


#---------------------------------------------------------------------------
sub run_bayes {

my $testuser = 'tstusr.'.$$.'.'.time();

tstprefs ("
  $dbconfig
  bayes_sql_override_username $testuser
  loadplugin validuserplugin ../../../data/validuserplugin.pm
  bayes_sql_username_authorized 1
");

my $sa = create_saobj();

$sa->init();

ok($sa);

my $learner = $sa->call_plugins("learner_get_implementation");

ok($sa->{bayes_scanner} && $learner);

ok($learner->{store}->tie_db_writable());

# This bit breaks abstraction a bit, the userid is an implementation detail,
# but is necessary to perform some of the tests.  Perhaps in the future we
# can add some sort of official API for this sort of thing.
my $testuserid = $learner->{store}->{_userid};
ok(defined($testuserid));

ok($learner->{store}->clear_database());

ok(database_clear_p($testuser, $testuserid));

$sa->finish_learner();

undef $sa;

sa_t_init("bayessql");

tstprefs ("
  $dbconfig
  bayes_sql_override_username iwillfail
  loadplugin validuserplugin ../../../data/validuserplugin.pm
  bayes_sql_username_authorized 1
");

$sa = create_saobj();

$sa->init();

ok($sa);

$learner = $sa->call_plugins("learner_get_implementation");

ok($sa->{bayes_scanner});

ok(!$learner->{store}->tie_db_writable());

$sa->finish_learner();

undef $sa;

sa_t_init("bayessql");

tstprefs ("
  $dbconfig
  bayes_sql_override_username $testuser
");

$sa = create_saobj();

$sa->init();

ok($sa);

$learner = $sa->call_plugins("learner_get_implementation");

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

my $body = $learner->get_body_from_msg($mail);

ok($body);

my $toks = $learner->tokenize($mail, $body);

ok(scalar(keys %{$toks}) > 0);

my $msgid = $mail->generate_msgid();
my $msgid_hdr = $mail->get_msgid();

# $msgid is the generated hash messageid
# $msgid_hdr is the Message-Id header
ok($msgid eq '71f849915d7e469ddc1890cd8175f6876843f99e@sa_generated');
ok($msgid_hdr eq '9PS291LhupY');

ok($learner->{store}->tie_db_writable());

ok(!$learner->{store}->seen_get($msgid));

$learner->{store}->untie_db();

ok($sa->{bayes_scanner}->learn(1, $mail));

ok(!$sa->{bayes_scanner}->learn(1, $mail));

ok($learner->{store}->tie_db_writable());

ok($learner->{store}->seen_get($msgid) eq 's');

$learner->{store}->untie_db();

ok($learner->{store}->tie_db_writable());

my $tokerror = 0;
foreach my $tok (keys %{$toks}) {
  my ($spam, $ham, $atime) = $learner->{store}->tok_get($tok);
  if ($spam == 0 || $ham > 0) {
    $tokerror = 1;
  }
}
ok(!$tokerror);

my $tokens = $learner->{store}->tok_get_all(keys %{$toks});

ok($tokens);

$tokerror = 0;
foreach my $tok (@{$tokens}) {
  my ($token, $tok_spam, $tok_ham, $atime) = @{$tok};
  if ($tok_spam == 0 || $tok_ham > 0) {
    $tokerror = 1;
  }
}

ok(!$tokerror);

$learner->{store}->untie_db();

ok($sa->{bayes_scanner}->learn(0, $mail));

ok($learner->{store}->tie_db_writable());

ok($learner->{store}->seen_get($msgid) eq 'h');

$learner->{store}->untie_db();

ok($learner->{store}->tie_db_writable());

$tokerror = 0;
foreach my $tok (keys %{$toks}) {
  my ($spam, $ham, $atime) = $learner->{store}->tok_get($tok);
  if ($spam  > 0 || $ham == 0) {
    $tokerror = 1;
  }
}
ok(!$tokerror);

$learner->{store}->untie_db();

ok($sa->{bayes_scanner}->forget($mail));

ok($learner->{store}->tie_db_writable());

ok(!$learner->{store}->seen_get($msgid));

$learner->{store}->untie_db();

# This bit breaks abstraction a bit, the userid is an implementation detail,
# but is necessary to perform some of the tests.  Perhaps in the future we
# can add some sort of official API for this sort of thing.
$testuserid = $learner->{store}->{_userid};
ok(defined($testuserid));

ok($learner->{store}->clear_database());

ok(database_clear_p($testuser, $testuserid));

$sa->finish_learner();

undef $sa;

sa_t_init("bayessql"); # this wipes out what is there and begins anew

# make sure we learn to a journal
tstprefs ("
  $dbconfig
  bayes_min_spam_num 10
  bayes_min_ham_num 10
  bayes_sql_override_username $testuser
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

$learner = $sa->call_plugins("learner_get_implementation");

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

$body = $learner->get_body_from_msg($mail);

my $msgstatus = Mail::SpamAssassin::PerMsgStatus->new($sa, $mail);

ok($msgstatus);

my $score = $learner->scan($msgstatus, $mail, $body);

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

$body = $learner->get_body_from_msg($mail);

$msgstatus = Mail::SpamAssassin::PerMsgStatus->new($sa, $mail);

$score = $learner->scan($msgstatus, $mail, $body);

# Pretty much we can't count on the data returned with such little training
# so just make sure that the score wasn't equal to .5 which is the default
# return value.
print "\treturned score: $score\n";
ok($score =~ /\d/ && $score <= 1.0 && $score != .5);
}

# This bit breaks abstraction a bit, the userid is an implementation detail,
# but is necessary to perform some of the tests.  Perhaps in the future we
# can add some sort of official API for this sort of thing.
$testuserid = $learner->{store}->{_userid};
ok(defined($testuserid));

ok($learner->{store}->clear_database());

ok(database_clear_p($testuser, $testuserid));

$sa->finish_learner();

}
#---------------------------------------------------------------------------

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

# WARNING! Do not use this as an example, this breaks abstraction
# and is here strictly to help the regression tests.
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

