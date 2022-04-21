#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("wlbl_uri");
use Test::More tests => 12;

%patterns = (
  q{ 0.0 URI_HOST_IN_BLOCKLIST }, 'hit-blo',
  q{ 100 URI_HOST_IN_BLACKLIST }, 'hit-bla',
  q{ -0.0 URI_HOST_IN_WELCOMELIST }, 'hit-wel',
  q{ -100 URI_HOST_IN_WHITELIST }, 'hit-whi',
);

###

tstprefs("
  blocklist_uri_host ximian.com
  welcomelist_uri_host helixcode.com
");

sarun ("-L -t < data/nice/001", \&patterns_run_cb);
ok_all_patterns();

###

tstprefs("
  blacklist_uri_host ximian.com
  whitelist_uri_host helixcode.com
");

sarun ("-L -t < data/nice/001", \&patterns_run_cb);
ok_all_patterns();

###

%patterns = (
  q{ 100 URI_HOST_IN_BLOCKLIST }, 'hit-blo',
  q{ -100 URI_HOST_IN_WELCOMELIST }, 'hit-wel',
);
%anti_patterns = (
  q{ URI_HOST_IN_BLACKLIST }, 'hit-bla',
  q{ URI_HOST_IN_WHITELIST }, 'hit-whi',
);

tstpre("
  enable_compat welcomelist_blocklist
");
tstprefs("
  blocklist_uri_host ximian.com
  welcomelist_uri_host helixcode.com
");

sarun ("-L -t < data/nice/001", \&patterns_run_cb);
ok_all_patterns();

