#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("rule_types");
use Test; BEGIN { plan tests => 9 };

# ---------------------------------------------------------------------------

%patterns = (

q{ TEST_INVALID_DATE }, 'invdate',
q{ TEST_EXCUSE_4 }, 'bodyspotted',
q{ LAST_RCVD_LINE }, 'LAST_RCVD_LINE',
q{ MESSAGEID_MATCH }, 'MESSAGEID_MATCH',
q{ ENV_FROM }, 'ENV_FROM',
q{ SUBJ_IN_BODY }, 'SUBJ_IN_BODY',
q{ URI_RULE }, 'URI_RULE',
q{ BODY_LINE_WRAP }, 'BODY_LINE_WRAP',
q{ RELAYS }, 'RELAYS',

);

# define a few rules in the user prefs file (this is OK
# for the commandline scanner).   Try to exercise some of the
# different rule types we support, header-name macros etc. (TODO: all ;)
#
tstprefs ('

header LAST_RCVD_LINE	Received =~ /www.fasttrec.com/
header MESSAGEID_MATCH	MESSAGEID =~ /fasttrec.com/
header ENV_FROM		EnvelopeFrom =~ /jm.netnoteinc.com/
body SUBJ_IN_BODY	/YOUR BRAND NEW HOUSE/
uri URI_RULE		/WWW.SUPERSITESCENTRAL.COM/i
body BODY_LINE_WRAP	/making obscene amounts of money from the/
header RELAYS		X-Spam-Relays-Untrusted =~ / helo=www.fasttrec.com /

    ');

sarun ("-L -t < data/spam/002", \&patterns_run_cb);
ok_all_patterns();
