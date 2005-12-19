#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spf");
use Test;

use constant TEST_ENABLED => conf_bool('run_net_tests');
use constant HAS_SPFQUERY => eval { require Mail::SPF::Query; };
# Do not run this test on non-Linux unices as root, due to a bug
# in Sys::Hostname::Long (which Mail::Query::SPF uses.)
# See <http://bugzilla.spamassassin.org/show_bug.cgi?id=3806>
use constant IS_LINUX   => $^O eq 'linux';
use constant IS_WINDOWS => ($^O =~ /^(mswin|dos|os2)/oi);
use constant AM_ROOT    => $< == 0;

use constant DO_RUN     => TEST_ENABLED && HAS_SPFQUERY &&
                                        !(AM_ROOT &&
                                          !(IS_LINUX || IS_WINDOWS));

BEGIN {
  
  plan tests => (DO_RUN ? 28 : 0);

};

exit unless (DO_RUN);

# ---------------------------------------------------------------------------

# ensure all rules will fire
tstlocalrules ("
  score SPF_FAIL 0.001
  score SPF_HELO_FAIL 0.001
  score SPF_HELO_NEUTRAL 0.001
  score SPF_HELO_SOFTFAIL 0.001
  score SPF_NEUTRAL 0.001
  score SPF_SOFTFAIL 0.001
  score SPF_PASS -0.001
  score SPF_HELO_PASS -0.001
");

%patterns = (
    q{ SPF_HELO_PASS }, 'helo_pass',
    q{ SPF_PASS }, 'pass',
);

sarun ("-t < data/nice/spf1", \&patterns_run_cb);
ok_all_patterns();

%patterns = (
    q{ SPF_NEUTRAL }, 'neutral',
    q{ SPF_HELO_NEUTRAL }, 'helo_neutral',
);

sarun ("-t < data/spam/spf1", \&patterns_run_cb);
ok_all_patterns();

%patterns = (
    q{ SPF_SOFTFAIL }, 'softfail',
    q{ SPF_HELO_SOFTFAIL }, 'helo_softfail',
);

sarun ("-t < data/spam/spf2", \&patterns_run_cb);
ok_all_patterns();
%patterns = (
    q{ SPF_FAIL }, 'fail',
    q{ SPF_HELO_FAIL }, 'helo_fail',
);

sarun ("-t < data/spam/spf3", \&patterns_run_cb);
ok_all_patterns();


# Test using an assortment of trusted and internal network definitions

# 9-10: Trusted networks contain first header.

tstprefs("
clear_trusted_networks
clear_internal_networks
trusted_networks 65.214.43.157
always_trust_envelope_sender 1
");

%patterns = (
    q{ SPF_HELO_PASS }, 'helo_pass',
    q{ SPF_PASS }, 'pass',
);

sarun ("-t < data/nice/spf2", \&patterns_run_cb);
ok_all_patterns();


# 11-12: Internal networks contain first header.
#	 Trusted networks not defined.

tstprefs("
clear_trusted_networks
clear_internal_networks
internal_networks 65.214.43.157
always_trust_envelope_sender 1
");

%patterns = (
    q{ SPF_HELO_PASS }, 'helo_pass',
    q{ SPF_PASS }, 'pass',
);

sarun ("-t < data/nice/spf2", \&patterns_run_cb);
ok_all_patterns();


# 13-14: Internal networks contain first header.
#	 Trusted networks contain some other IP.

tstprefs("
clear_trusted_networks
clear_internal_networks
trusted_networks 1.2.3.4
internal_networks 65.214.43.157
always_trust_envelope_sender 1
");

%patterns = (
    q{ SPF_HELO_NEUTRAL }, 'helo_neutral',
    q{ SPF_NEUTRAL }, 'neutral',
);

sarun ("-t < data/nice/spf2", \&patterns_run_cb);
ok_all_patterns();


# 15-16: Trusted+Internal networks contain first header.

tstprefs("
clear_trusted_networks
clear_internal_networks
trusted_networks 65.214.43.157
internal_networks 65.214.43.157
always_trust_envelope_sender 1
");

%patterns = (
    q{ SPF_HELO_PASS }, 'helo_pass',
    q{ SPF_PASS }, 'pass',
);

sarun ("-t < data/nice/spf2", \&patterns_run_cb);
ok_all_patterns();


# 17-18: Trusted networks contain first and second header.
#	 Internal networks contain first header.

tstprefs("
clear_trusted_networks
clear_internal_networks
trusted_networks 65.214.43.157 64.142.3.173
internal_networks 65.214.43.157
always_trust_envelope_sender 1
");

%patterns = (
    q{ SPF_HELO_PASS }, 'helo_pass',
    q{ SPF_PASS }, 'pass',
);

sarun ("-t < data/nice/spf2", \&patterns_run_cb);
ok_all_patterns();


# 19-26: Trusted networks contain first and second header.
#	 Internal networks contain first and second header.

tstprefs("
clear_trusted_networks
clear_internal_networks
trusted_networks 65.214.43.157 64.142.3.173
internal_networks 65.214.43.157 64.142.3.173
always_trust_envelope_sender 1
");

%anti_patterns = (
    q{ SPF_HELO_PASS }, 'helo_pass',
    q{ SPF_HELO_FAIL }, 'helo_fail',
    q{ SPF_HELO_SOFTFAIL }, 'helo_softfail',
    q{ SPF_HELO_NEUTRAL }, 'helo_neutral',
    q{ SPF_PASS }, 'pass',
    q{ SPF_FAIL }, 'fail',
    q{ SPF_SOFTFAIL }, 'softfail',
    q{ SPF_NEUTRAL }, 'neutral',
);
%patterns = ();

sarun ("-t < data/nice/spf2", \&patterns_run_cb);
ok_all_patterns();


# 27-28: Trusted networks contain first header.
#	 Internal networks contain first and second header.

tstprefs("
clear_trusted_networks
clear_internal_networks
trusted_networks 65.214.43.157
internal_networks 65.214.43.157 64.142.3.173
always_trust_envelope_sender 1
");

%anti_patterns = ();
%patterns = (
    q{ SPF_HELO_PASS }, 'helo_pass',
    q{ SPF_PASS }, 'pass',
);

sarun ("-t < data/nice/spf2", \&patterns_run_cb);
ok_all_patterns();

