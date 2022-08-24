#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("sa_awl");

use Test::More tests => 1;

# ---------------------------------------------------------------------------

%patterns = (
  q{ X-Spam-Status: Yes}, 'isspam',
);

tstprefs ("
  auto_welcomelist_path ./$userstate/awltest
  auto_welcomelist_file_mode 0755
");

sarun("--add-addr-to-welcomelist whitelist_test\@whitelist.spamassassin.taint.org",
      \&patterns_run_cb);

print cwd() . "\n";
saawlrun("--clean --min 9999 ./$userstate/awltest");

sarun ("-L -t < data/spam/004", \&patterns_run_cb);
ok_all_patterns();

