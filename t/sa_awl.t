#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("sa_awl");

use Test::More tests => 1;

# ---------------------------------------------------------------------------

%patterns = (
  q{ X-Spam-Status: Yes}, 'isspam',
);

tstprefs ("
        $default_cf_lines
        auto_whitelist_path ./log/awltest
        auto_whitelist_file_mode 0755
");

sarun("--add-addr-to-whitelist whitelist_test\@whitelist.spamassassin.taint.org",
      \&patterns_run_cb);

untaint_system("pwd");
saawlrun("--clean --min 9999 ./log/awltest");

sarun ("-L -t < data/spam/004", \&patterns_run_cb);
ok_all_patterns();

