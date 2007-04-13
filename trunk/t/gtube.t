#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spam");
use Test; BEGIN { plan tests => 4 };

# ---------------------------------------------------------------------------

%patterns = (

q{ BODY: Generic Test for Unsolicited Bulk Email }, 'gtube',

);

tstprefs ("
        $default_cf_lines

        ifplugin Mail::SpamAssassin::Plugin::AWL
         use_auto_whitelist 1
         auto_whitelist_path ./log/awl
         auto_whitelist_file_mode 0755
        endif
");

$ENV{'LANGUAGE'} = $ENV{'LC_ALL'} = 'C';             # a cheat, but we match the description

ok (sarun ("-L -t < data/spam/gtube.eml", \&patterns_run_cb));
ok_all_patterns();

%patterns = (

q{ X-Spam-Status: No }, 'not_marked_as_spam_from_awl_bonus',

);

ok (sarun ("-L -t < data/nice/not_gtube.eml", \&patterns_run_cb));
ok_all_patterns();

