#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("if_can");
use Test; BEGIN { plan tests => 5 };

# ---------------------------------------------------------------------------

%patterns = (

        q{ GTUBE }, 'gtube',
        q{ SHOULD_BE_CALLED }, 'should_be_called',

);
%anti_patterns = (

        q{ SHOULD_NOT_BE_CALLED1 }, 'should_not_be_called1',
        q{ SHOULD_NOT_BE_CALLED2 }, 'should_not_be_called2',

);
tstlocalrules (q{

        loadplugin Mail::SpamAssassin::Plugin::Test
        if !can(Mail::SpamAssassin::Plugin::Test::check_test_plugin)
          body SHOULD_NOT_BE_CALLED1 /./
        endif
        if (can(Mail::SpamAssassin::Plugin::Test::non_existent_method))
          body SHOULD_NOT_BE_CALLED2 /./
        endif
        if (can(Mail::SpamAssassin::Plugin::Test::check_test_plugin))
          body SHOULD_BE_CALLED /./
        endif

});

ok (sarun ("-L -t < data/spam/gtube.eml", \&patterns_run_cb));
ok_all_patterns();

