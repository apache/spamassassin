#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("reportheader");

use Test::More tests => 3;

$ENV{'LANGUAGE'} = $ENV{'LC_ALL'} = 'C';             # a cheat, but we need the patterns to work

# ---------------------------------------------------------------------------

%patterns = (
  qr/^X-Spam-Report:\s*$/m, 'qp-encoded-hdr',
  qr/^\t\*\s+[0-9.-]+ INVALID_DATE\s+Invalid Date: header =\?UTF-8\?B\?wq4gwq8gwrA=\?= foo$/m, 'qp-encoded-desc',
  qr/^ [0-9.-]+ INVALID_DATE\s+Invalid Date: header ® ¯ ° foo$/m, 'report-desc',
);

tstprefs ("
  report_safe 0
  describe INVALID_DATE Invalid Date: header ® ¯ ° foo
");

sarun ("-L -t < data/spam/001", \&patterns_run_cb);
ok_all_patterns();

