#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("if_can");
use Test::More tests => 19;

# ---------------------------------------------------------------------------

%patterns = (

  q{ GTUBE }, 'gtube',
  q{ SHOULD_BE_CALLED01 }, 'should_be_called01',
  q{ SHOULD_BE_CALLED02 }, 'should_be_called02',
  q{ SHOULD_BE_CALLED03 }, 'should_be_called03',
  q{ SHOULD_BE_CALLED04 }, 'should_be_called04',
  q{ SHOULD_BE_CALLED05 }, 'should_be_called05',
  q{ SHOULD_BE_CALLED06 }, 'should_be_called06',
  q{ SHOULD_BE_CALLED07 }, 'should_be_called07',
  q{ SHOULD_BE_CALLED08 }, 'should_be_called08',
  q{ SHOULD_BE_CALLED09 }, 'should_be_called09',
  q{ SHOULD_BE_CALLED10 }, 'should_be_called10',
  q{ SHOULD_BE_CALLED11 }, 'should_be_called11',
  q{ SHOULD_BE_CALLED12 }, 'should_be_called12',

);
%anti_patterns = (

  q{ SHOULD_NOT_BE_CALLED01 }, 'should_not_be_called01',
  q{ SHOULD_NOT_BE_CALLED02 }, 'should_not_be_called02',
  q{ SHOULD_NOT_BE_CALLED03 }, 'should_not_be_called03',
  q{ SHOULD_NOT_BE_CALLED04 }, 'should_not_be_called04',
  q{ SHOULD_NOT_BE_CALLED05 }, 'should_not_be_called05',

);
tstlocalrules (q{

  loadplugin Mail::SpamAssassin::Plugin::Test

  if (has(Mail::SpamAssassin::Plugin::Test::check_test_plugin))
    body SHOULD_BE_CALLED01 /./
  endif
  if (has(Mail::SpamAssassin::Plugin::Test::test_feature_xxxx_true))
    body SHOULD_BE_CALLED02 /./
  endif
  if (has(Mail::SpamAssassin::Plugin::Test::test_feature_xxxx_false))
    body SHOULD_BE_CALLED03 /./
  endif
  if (can(Mail::SpamAssassin::Plugin::Test::test_feature_xxxx_true))
    body SHOULD_BE_CALLED04 /./
  endif
  if (!can(Mail::SpamAssassin::Plugin::Test::test_feature_xxxx_false))
    body SHOULD_BE_CALLED05 /./
  endif
  if (!has(Mail::SpamAssassin::Plugin::Test::test_feature_xxxx_nosuch))
    body SHOULD_BE_CALLED06 /./
  endif
  if (!can(Mail::SpamAssassin::Plugin::Test::test_feature_xxxx_nosuch))
    body SHOULD_BE_CALLED07 /./
  endif
  if can(Mail::SpamAssassin::Plugin::Test::test_feature_xxxx_true) && version > 0.00000
    body SHOULD_BE_CALLED08 /./
  endif
  if !can(Mail::SpamAssassin::Plugin::Test::test_feature_xxxx_false  ) && !(! version > 0.00000)
    body SHOULD_BE_CALLED09 /./
  endif
  if has(Mail::SpamAssassin::Plugin::Test::test_feature_xxxx_true) && (!can(Mail::SpamAssassin::Plugin::Test::test_feature_xxxx_nosuch))
    body SHOULD_BE_CALLED10 /./
  endif

  if !has(Mail::SpamAssassin::Plugin::Test::check_test_plugin)
    body SHOULD_NOT_BE_CALLED01 /./
  endif
  if (has(Mail::SpamAssassin::Plugin::Test::non_existent_method))
    body SHOULD_NOT_BE_CALLED02 /./
  endif
  if (can(Mail::SpamAssassin::Plugin::Test::non_existent_method))
    body SHOULD_NOT_BE_CALLED03 /./
  endif
  if can(Mail::SpamAssassin::Plugin::Test::test_feature_xxxx_true)
  if (can(Mail::SpamAssassin::Plugin::Test::test_feature_xxxx_false))
    body SHOULD_NOT_BE_CALLED04 /./
  else
    body SHOULD_BE_CALLED11 /./
  endif
  endif

  if can(Mail::SpamAssassin::Conf::feature_local_tests_only) && local_tests_only
    body SHOULD_BE_CALLED12 /./
  endif
  if can(Mail::SpamAssassin::Conf::feature_local_tests_only) && !local_tests_only
    body SHOULD_NOT_BE_CALLED05 /./
  endif

});

ok (sarun ("-L -t < data/spam/gtube.eml", \&patterns_run_cb));
ok_all_patterns();

