#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("welcomelist_spf");

use Test::More;
plan skip_all => 'Long running tests disabled' unless conf_bool('run_long_tests');
plan tests => 15;

tstlocalrules(q{
  header USER_IN_SPF_WELCOMELIST  eval:check_for_spf_welcomelist_from()
  tflags USER_IN_SPF_WELCOMELIST  userconf nice noautolearn net
  score  USER_IN_SPF_WELCOMELIST  -100

  header USER_IN_DEF_SPF_WL       eval:check_for_def_spf_welcomelist_from()
  tflags USER_IN_DEF_SPF_WL       userconf nice noautolearn net
  score  USER_IN_DEF_SPF_WL       -10

  meta   USER_IN_SPF_WHITELIST    (USER_IN_SPF_WELCOMELIST)
  tflags USER_IN_SPF_WHITELIST    userconf nice noautolearn net
  score  USER_IN_SPF_WHITELIST    -100

  def_welcomelist_from_spf        *@example.com
});

my $net_cfg = q{
  clear_trusted_networks
  clear_internal_networks
  trusted_networks 65.214.43.158 64.142.3.173
  internal_networks 65.214.43.158 64.142.3.173
  always_trust_envelope_sender 1
};

tstprefs($net_cfg);
%patterns = (
  q{ -10 USER_IN_DEF_SPF_WL }, '',
);
%anti_patterns = (
  q{ USER_IN_SPF_WELCOMELIST }, '',
  q{ USER_IN_SPF_WHITELIST }, '',
);
sarun("-t < data/nice/welcomelist_spf1", \&patterns_run_cb);
ok_all_patterns();

tstprefs($net_cfg . q{
  welcomelist_from_spf *@example.com
});
%patterns = (
  q{ -100 USER_IN_SPF_WELCOMELIST }, '',
  q{ -10 USER_IN_DEF_SPF_WL }, '',
  q{ -100 USER_IN_SPF_WHITELIST }, '',
);
%anti_patterns = ();
sarun("-t < data/nice/welcomelist_spf1", \&patterns_run_cb);
ok_all_patterns();

tstprefs($net_cfg);
%patterns = ();
%anti_patterns = (
  q{ USER_IN_DEF_SPF_WL }, '',
  q{ USER_IN_SPF_WELCOMELIST }, '',
  q{ USER_IN_SPF_WHITELIST }, '',
);
sarun("-t < data/nice/welcomelist_spf2", \&patterns_run_cb);
ok_all_patterns();

disable_compat("welcomelist_blocklist");

tstprefs($net_cfg);
%patterns = (
  q{ -10 USER_IN_DEF_SPF_WL }, '',
);
%anti_patterns = (
  q{ USER_IN_SPF_WELCOMELIST }, '',
  q{ USER_IN_SPF_WHITELIST }, '',
);
sarun("-t < data/nice/welcomelist_spf1", \&patterns_run_cb);
ok_all_patterns();

tstprefs($net_cfg . q{
  welcomelist_from_spf *@example.com
});
%patterns = (
  q{ USER_IN_SPF_WELCOMELIST }, '',
  q{ -10 USER_IN_DEF_SPF_WL }, '',
  q{ -100 USER_IN_SPF_WHITELIST }, '',
);
%anti_patterns = ();
sarun("-t < data/nice/welcomelist_spf1", \&patterns_run_cb);
ok_all_patterns();
