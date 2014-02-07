#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("whitelist_addrs");
use IO::File;

use constant HAS_MODULES => eval {
  require DB_File;
};

use constant TEST_ENABLED => conf_bool('run_long_tests');

use constant DO_RUN => TEST_ENABLED && HAS_MODULES;

use Test;
BEGIN { 
  if (-e 't/test_dir') {
    chdir 't';
  }

  if (-e 'test_dir') {
    unshift(@INC, '../blib/lib');
  }

  plan tests => (DO_RUN ? 35 : 0);
 };

exit unless DO_RUN;

# ---------------------------------------------------------------------------

%added_address_whitelist_patterns = (
q{SpamAssassin auto-whitelist: adding address to whitelist:}, 'added address to whitelist',
);
%added_address_blacklist_patterns = (
q{SpamAssassin auto-whitelist: adding address to blacklist:}, 'added address to blacklist',
);
%removed_address_patterns = (
q{SpamAssassin auto-whitelist: removing address:}, 'removed address',
);
%is_nonspam_patterns = (
q{X-Spam-Status: No}, 'spamno',
);
%is_spam_patterns = (
q{X-Spam-Status: Yes}, 'spamyes',
);


%patterns = %added_address_whitelist_patterns;
ok(sarun ("--add-addr-to-whitelist whitelist_test\@whitelist.spamassassin.taint.org", \&patterns_run_cb));
ok_all_patterns();
%patterns = %is_nonspam_patterns;
ok (sarun ("-L < data/nice/002", \&patterns_run_cb));
ok_all_patterns();
%patterns = %is_nonspam_patterns;
sarun ("-L < data/spam/004", \&patterns_run_cb);
ok_all_patterns();

%patterns = %removed_address_patterns;
ok(sarun ("--remove-addr-from-whitelist whitelist_test\@whitelist.spamassassin.taint.org", \&patterns_run_cb));
ok_all_patterns();
%patterns = %is_spam_patterns;
sarun ("-L < data/spam/004", \&patterns_run_cb);
ok_all_patterns();

%patterns = %added_address_blacklist_patterns;
ok(sarun ("--add-addr-to-blacklist whitelist_test\@whitelist.spamassassin.taint.org", \&patterns_run_cb));
ok_all_patterns();
%patterns = %is_spam_patterns;
sarun ("-L < data/nice/002", \&patterns_run_cb);
ok_all_patterns();

ok(sarun ("--remove-addr-from-whitelist whitelist_test\@whitelist.spamassassin.taint.org", \&patterns_run_cb));


# The following section tests the object oriented interface to adding/removing whitelist
# and blacklist entries.  Primarily this is testing basic functionality and that the
# "print" commands that are present in the command line interface are not being printed
# when you call the methods directly.  This is why we are manipulating STDOUT.

open my $oldout, ">&STDOUT" || die "Cannnot dup STDOUT";

my $fh = IO::File->new_tmpfile();
ok($fh);
open(STDOUT, ">&=".fileno($fh)) || die "Cannot reopen STDOUT";
select STDOUT; $| = 1;

my $sa = create_saobj();

$sa->init();

$sa->add_address_to_whitelist("whitelist_test\@whitelist.spamassassin.taint.org");

seek($fh, 0, 0);

my $error = do {
  local $/;
  <$fh>;
};
$fh->close();
open STDOUT, ">&".fileno($oldout) || die "Cannot dupe \$oldout: $!";
select STDOUT; $| = 1;

#warn "# $error\n";
ok($error !~ /SpamAssassin auto-whitelist: /);

%patterns = %is_nonspam_patterns;
ok (sarun ("-L < data/nice/002", \&patterns_run_cb));
ok_all_patterns();
%patterns = %is_nonspam_patterns;
sarun ("-L < data/spam/004", \&patterns_run_cb);
ok_all_patterns();

$fh = IO::File->new_tmpfile();
ok($fh);
open(STDOUT, ">&=".fileno($fh)) || die "Cannot reopen STDOUT";
select STDOUT; $| = 1;

$sa->remove_address_from_whitelist("whitelist_test\@whitelist.spamassassin.taint.org");

seek($fh, 0, 0);

$error = do {
  local $/;
  <$fh>;
};
$fh->close();
open STDOUT, ">&".fileno($oldout) || die "Cannot dupe \$oldout: $!";
select STDOUT; $| = 1;

#warn "# $error\n";
ok($error !~ /SpamAssassin auto-whitelist: /);

%patterns = %is_spam_patterns;
sarun ("-L < data/spam/004", \&patterns_run_cb);
ok_all_patterns();

$fh = IO::File->new_tmpfile();
ok($fh);
open(STDOUT, ">&=".fileno($fh)) || die "Cannot reopen STDOUT";
select STDOUT; $| = 1;

$sa->add_address_to_blacklist("whitelist_test\@whitelist.spamassassin.taint.org");

seek($fh, 0, 0);

$error = do {
  local $/;
  <$fh>;
};
$fh->close();
open STDOUT, ">&".fileno($oldout) || die "Cannot dupe \$oldout: $!";
select STDOUT; $| = 1;

#warn "# $error\n";
ok($error !~ /SpamAssassin auto-whitelist: /);

%patterns = %is_spam_patterns;
sarun ("-L < data/nice/002", \&patterns_run_cb);
ok_all_patterns();

$sa->remove_address_from_whitelist("whitelist_test\@whitelist.spamassassin.taint.org");

# Now we can test the "all" methods

open(MAIL,"< data/nice/002");

my $raw_message = do {
  local $/;
  <MAIL>;
};

close(MAIL);
ok($raw_message);

my $mail = $sa->parse( $raw_message );

$fh = IO::File->new_tmpfile();
ok($fh);
open(STDOUT, ">&=".fileno($fh)) || die "Cannot reopen STDOUT";
select STDOUT; $| = 1;

$sa->add_all_addresses_to_whitelist($mail);

seek($fh, 0, 0);

$error = do {
  local $/;
  <$fh>;
};
$fh->close();
open STDOUT, ">&".fileno($oldout) || die "Cannot dupe \$oldout: $!";
select STDOUT; $| = 1;

#warn "# $error\n";
ok($error !~ /SpamAssassin auto-whitelist: /);

%patterns = %is_nonspam_patterns;
ok (sarun ("-L < data/nice/002", \&patterns_run_cb));
ok_all_patterns();
%patterns = %is_nonspam_patterns;
sarun ("-L < data/spam/004", \&patterns_run_cb);
ok_all_patterns();

$fh = IO::File->new_tmpfile();
ok($fh);
open(STDOUT, ">&=".fileno($fh)) || die "Cannot reopen STDOUT";
select STDOUT; $| = 1;

$sa->remove_all_addresses_from_whitelist($mail);

seek($fh, 0, 0);

$error = do {
  local $/;
  <$fh>;
};
$fh->close();
open STDOUT, ">&".fileno($oldout) || die "Cannot dupe \$oldout: $!";
select STDOUT; $| = 1;

#warn "# $error\n";
ok($error !~ /SpamAssassin auto-whitelist: /);

%patterns = %is_spam_patterns;
sarun ("-L < data/spam/004", \&patterns_run_cb);
ok_all_patterns();

$fh = IO::File->new_tmpfile();
ok($fh);
open(STDOUT, ">&=".fileno($fh)) || die "Cannot reopen STDOUT";
select STDOUT; $| = 1;

$sa->add_all_addresses_to_blacklist($mail);

seek($fh, 0, 0);

$error = do {
  local $/;
  <$fh>;
};
$fh->close();
open STDOUT, ">&".fileno($oldout) || die "Cannot dupe \$oldout: $!";
select STDOUT; $| = 1;

#warn "# $error\n";
ok($error !~ /SpamAssassin auto-whitelist: /);

%patterns = %is_spam_patterns;
sarun ("-L < data/nice/002", \&patterns_run_cb);
ok_all_patterns();

$sa->remove_all_addresses_from_whitelist($mail);
