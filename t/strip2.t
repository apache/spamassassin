#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("strip2");
use Test; BEGIN { plan tests => 12 };

# this should be taken care of now by local overriding of Mail::Audit
# warn "
# 	If tests 8, 10, and 12 fail, it's because you did not apply
# 	the patch to Mail::Audit in 'MailAudit.patch'.
# \n";

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
ok (sarun ("-L -t < $INPUT", \&patterns_run_cb));
ok_all_patterns();
clear_pattern_counters();
copy ("log/strip2.1", "log/strip2_with-t.out");

# create the -p output
ok (sarun ("-L -P < $INPUT", \&patterns_run_cb));
ok_all_patterns();
clear_pattern_counters();
copy ("log/strip2.4", "log/strip2_with-P.out");

# create fake output, as if it was not spam
copy ("data/spam/002", "log/strip2_without_markup.out");

# now run -d for each of them and fail if it does not match up exactly
ok (sarun ("-d < log/strip2_with-t.out", \&patterns_run_cb));
ok (diff ($INPUT, "log/strip2.7") == 0);

ok (sarun ("-d < log/strip2_with-P.out", \&patterns_run_cb));
ok (diff ($INPUT, "log/strip2.9") == 0);

ok (sarun ("-d < log/strip2_without_markup.out", \&patterns_run_cb));
ok (diff ($INPUT, "log/strip2.11") == 0);

