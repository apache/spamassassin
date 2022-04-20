#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("wlbl_uri");
use Test::More tests => 4;

%patterns = (
  q{ URI_HOST_IN_BLOCKLIST }, 'hit-blo',
  q{ URI_HOST_IN_BLACKLIST }, 'hit-bla',
  q{ URI_HOST_IN_WELCOMELIST }, 'hit-wel',
  q{ URI_HOST_IN_WHITELIST }, 'hit-whi',
);

tstprefs ("
	$default_cf_lines
	blocklist_uri_host ximian.com
	blacklist_uri_host ximian.com
	welcomelist_uri_host helixcode.com
	whitelist_uri_host helixcode.com
	");

sarun ("-L -t < data/nice/001", \&patterns_run_cb);
ok_all_patterns();
