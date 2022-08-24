#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("wlbl_uri");
use Test::More tests => 12;

# copied from 60_welcome.cf
# should do the right thing with the different disable/enable compat settings
my $myrules = <<'END';
  if can(Mail::SpamAssassin::Conf::feature_welcomelist_blocklist)
    body URI_HOST_IN_BLOCKLIST		eval:check_uri_host_in_blocklist()
    tflags URI_HOST_IN_BLOCKLIST		userconf noautolearn
    score URI_HOST_IN_BLOCKLIST		100

    if !can(Mail::SpamAssassin::Conf::compat_welcomelist_blocklist)
      meta URI_HOST_IN_BLACKLIST		(URI_HOST_IN_BLOCKLIST)
      tflags URI_HOST_IN_BLACKLIST	userconf noautolearn
      score URI_HOST_IN_BLACKLIST		100
      score URI_HOST_IN_BLOCKLIST		0.01
    endif
  endif
  if !can(Mail::SpamAssassin::Conf::feature_welcomelist_blocklist)
    if (version >= 3.004000)
      body URI_HOST_IN_BLOCKLIST		eval:check_uri_host_in_blacklist()
      tflags URI_HOST_IN_BLOCKLIST	userconf noautolearn
      score URI_HOST_IN_BLOCKLIST		0.01

      meta URI_HOST_IN_BLACKLIST		(URI_HOST_IN_BLOCKLIST)
      tflags URI_HOST_IN_BLACKLIST	userconf noautolearn
      score URI_HOST_IN_BLACKLIST		100
    endif
  endif

  if can(Mail::SpamAssassin::Conf::feature_welcomelist_blocklist)
    body URI_HOST_IN_WELCOMELIST	eval:check_uri_host_in_welcomelist()
    tflags URI_HOST_IN_WELCOMELIST	userconf nice noautolearn
    score URI_HOST_IN_WELCOMELIST		-100

    if !can(Mail::SpamAssassin::Conf::compat_welcomelist_blocklist)
      meta URI_HOST_IN_WHITELIST		(URI_HOST_IN_WELCOMELIST)
      tflags URI_HOST_IN_WHITELIST	userconf nice noautolearn
      score URI_HOST_IN_WHITELIST		-100
      score URI_HOST_IN_WELCOMELIST	-0.01
    endif
  endif
  if !can(Mail::SpamAssassin::Conf::feature_welcomelist_blocklist)
    if (version >= 3.004000)
      body URI_HOST_IN_WELCOMELIST	eval:check_uri_host_in_whitelist()
      tflags URI_HOST_IN_WELCOMELIST	userconf nice noautolearn
      score URI_HOST_IN_WELCOMELIST	-0.01

      meta URI_HOST_IN_WHITELIST		(URI_HOST_IN_WELCOMELIST)
      tflags URI_HOST_IN_WHITELIST	userconf nice noautolearn
      score URI_HOST_IN_WHITELIST		-100
    endif
  endif
END
    
disable_compat "welcomelist_blocklist";

%patterns = (
  q{ 0.0 URI_HOST_IN_BLOCKLIST }, '',
  q{ 100 URI_HOST_IN_BLACKLIST }, '',
  q{ -0.0 URI_HOST_IN_WELCOMELIST }, '',
  q{ -100 URI_HOST_IN_WHITELIST }, '',
);

###

tstprefs($myrules . "
  blocklist_uri_host ximian.com
  welcomelist_uri_host helixcode.com
");

sarun ("-L -t < data/nice/001", \&patterns_run_cb);
ok_all_patterns();

###

tstprefs($myrules . "
  blacklist_uri_host ximian.com
  whitelist_uri_host helixcode.com
");

sarun ("-L -t < data/nice/001", \&patterns_run_cb);
ok_all_patterns();

###

%patterns = (
  q{ 100 URI_HOST_IN_BLOCKLIST }, '',
  q{ -100 URI_HOST_IN_WELCOMELIST }, '',
);
%anti_patterns = (
  q{ URI_HOST_IN_BLACKLIST }, '',
  q{ URI_HOST_IN_WHITELIST }, '',
);

tstpre("
  enable_compat welcomelist_blocklist
");
tstprefs($myrules . "
  blocklist_uri_host ximian.com
  welcomelist_uri_host helixcode.com
");

sarun ("-L -t < data/nice/001", \&patterns_run_cb);
ok_all_patterns();

