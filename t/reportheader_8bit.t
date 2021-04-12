#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("reportheader");

use Test::More tests => 3;

$ENV{'LANGUAGE'} = $ENV{'LC_ALL'} = 'C';             # a cheat, but we need the patterns to work

# ---------------------------------------------------------------------------

%patterns = (
  q{/(?m)^X-Spam-Report:\s*$/}, 'qp-encoded-hdr',
  q{/(?m)^\t\*\s+[0-9.-]+ INVALID_DATE\s+Invalid Date: header =\?UTF-8\?B\?wq4gwq8gwrA=\?= foo$/}, 'qp-encoded-desc',
  q{/(?m)^ [0-9.-]+ INVALID_DATE\s+Invalid Date: header ® ¯ ° foo$/}, 'report-desc',
);

tstprefs ("
  report_safe 0
  describe INVALID_DATE Invalid Date: header ® ¯ ° foo
");

sarun ("-L -t < data/spam/001", \&patterns_run_cb);
ok_all_patterns();

