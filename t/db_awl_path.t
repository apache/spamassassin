#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("db_awl_path");
use Test::More tests => 4;
use IO::File;

# ---------------------------------------------------------------------------
diag "Note: This test when successful displays lockfile warning messages";

%is_spam_patterns = (
q{ X-Spam-Status: Yes}, 'isspam',
);

# We can't easily test to see if a given AWL was used.  so what we do
# is tell SpamAssassin to use an inaccessible one, then verify that
# the address in question was *not* whitelisted successfully.   '

open (OUT, ">$workdir/awl");
print OUT "file created to block AWL from working; AWL expects a dir";
close OUT;

tstprefs ("
  auto_whitelist_path ./$workdir/awl/this_lock_warning_is_ok
  auto_whitelist_file_mode 0755
");

my $fh = IO::File->new_tmpfile();
ok($fh);
open(STDERR, ">&=".fileno($fh)) || die "Cannot reopen STDERR";
sarun("--add-addr-to-whitelist whitelist_test\@whitelist.spamassassin.taint.org",
      \&patterns_run_cb);
seek($fh, 0, 0);
my $error = do {
  local $/;
  <$fh>;
};

diag $error;
like($error, qr/(cannot create tmp lockfile)|(unlink of lock file.*failed)/, "Check we get the right error back");

# and this mail should *not* be whitelisted as a result.
%patterns = %is_spam_patterns;
sarun ("-L -t < data/spam/004", \&patterns_run_cb);
ok_all_patterns();

ok(unlink "$workdir/awl"); # need a little cleanup
