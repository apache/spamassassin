#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("strip2");
use Test; BEGIN { plan tests => 12 };

warn "
	If tests 8, 10, and 12 fail, it's because you did not apply
	the patch to Mail::Audit in 'MailAudit.patch'.
\n";

# ---------------------------------------------------------------------------

%patterns = (
 	'www.supersitescentral.com' => 'msg-text'
);

use File::Copy;

sub diff {
  my ($f1, $f2) = @_;
  system ("diff $f1 $f2");
  return ($? >> 8);
}

my $INPUT = 'data/spam/002';

# create the -t output
ok (sarun ("-t < $INPUT", \&patterns_run_cb));
ok_all_patterns();
clear_pattern_counters();
copy ("log/strip2.out", "log/strip2_with-t.out");

# create the -p output
ok (sarun ("-P < $INPUT", \&patterns_run_cb));
ok_all_patterns();
clear_pattern_counters();
copy ("log/strip2.out", "log/strip2_with-P.out");

# create fake output, as if it was not spam
copy ("data/spam/002", "log/strip2_without_markup.out");

# now run -d for each of them and fail if it doesn't match up exactly
ok (sarun ("-d < log/strip2_with-t.out", \&patterns_run_cb));
ok (diff ($INPUT, "log/strip2.out") == 0);

ok (sarun ("-d < log/strip2_with-P.out", \&patterns_run_cb));
ok (diff ($INPUT, "log/strip2.out") == 0);

ok (sarun ("-d < log/strip2_without_markup.out", \&patterns_run_cb));
ok (diff ($INPUT, "log/strip2.out") == 0);

