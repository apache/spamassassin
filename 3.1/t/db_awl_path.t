#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("db_awl_path");
use Test; BEGIN { plan tests => 4 };
use IO::File;

# ---------------------------------------------------------------------------

%is_spam_patterns = (
q{ X-Spam-Status: Yes}, 'isspam',
);

# We can't easily test to see if a given AWL was used.  so what we do
# is tell SpamAssassin to use an inaccessible one, then verify that
# the address in question was *not* whitelisted successfully.   '

open (OUT, ">log/awl");
print OUT "file created to block AWL from working; AWL expects a dir";
close OUT;

tstprefs ("
        $default_cf_lines
        auto_whitelist_path ./log/awl/shouldbeinaccessible
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

print "# $error\n";
ok($error, qr/(cannot create tmp lockfile)|(unlink of lock file.*failed)/, "Check we get the right error back");

# and this mail should *not* be whitelisted as a result.
%patterns = %is_spam_patterns;
sarun ("-L -t < data/spam/004", \&patterns_run_cb);
ok_all_patterns();

ok(unlink 'log/awl'); # need a little cleanup
