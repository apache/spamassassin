#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("if_can");
use Test::More tests => 19;

# ---------------------------------------------------------------------------

%patterns = (

  q{ 1000 GTUBE }, '',
  q{ 1.0 SHOULD_BE_CALLED01 }, '',
  q{ 1.0 SHOULD_BE_CALLED02 }, '',
  q{ 1.0 SHOULD_BE_CALLED03 }, '',
  q{ 1.0 SHOULD_BE_CALLED04 }, '',
  q{ 1.0 SHOULD_BE_CALLED05 }, '',
  q{ 1.0 SHOULD_BE_CALLED06 }, '',
  q{ 1.0 SHOULD_BE_CALLED07 }, '',
  q{ 1.0 SHOULD_BE_CALLED08 }, '',
  q{ 1.0 SHOULD_BE_CALLED09 }, '',
  q{ 1.0 SHOULD_BE_CALLED10 }, '',
  q{ 1.0 SHOULD_BE_CALLED11 }, '',
  q{ 1.0 SHOULD_BE_CALLED12 }, '',

);
%anti_patterns = (

  q{ SHOULD_NOT_BE_CALLED01 }, '',
  q{ SHOULD_NOT_BE_CALLED02 }, '',
  q{ SHOULD_NOT_BE_CALLED03 }, '',
  q{ SHOULD_NOT_BE_CALLED04 }, '',
  q{ SHOULD_NOT_BE_CALLED05 }, '',

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

