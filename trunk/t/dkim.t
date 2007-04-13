#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("dkim");
use Test;

use constant num_tests => 21;

use constant TEST_ENABLED => conf_bool('run_net_tests');
use constant HAS_MODULES => eval { require Mail::DKIM; require Mail::DKIM::Verifier; };
# use constant IS_LINUX   => $^O eq 'linux';
# use constant IS_WINDOWS => ($^O =~ /^(mswin|dos|os2)/oi);
# use constant AM_ROOT    => $< == 0;

# Since the plugin is disabled by default, so are the tests
use constant DO_RUN     => TEST_ENABLED && HAS_MODULES && 0;

BEGIN {
  
  plan tests => (DO_RUN ? num_tests : 0);

};

exit unless (DO_RUN);

# ---------------------------------------------------------------------------

# ensure all rules will fire
tstlocalrules ("
  score DKIM_SIGNED              -0.001
  score DKIM_VERIFIED            -0.001
  score DKIM_POLICY_SIGNSOME     0.001
  score DKIM_POLICY_SIGNALL      0.001
  score DKIM_POLICY_TESTING      0.001

");

# see DKIM corpus documentation at http://testing.dkim.org/documentation.html
# for details of the test messages....
#
# TODO: we should use a test-config setting to control whether the
# testing.dkim.org message corpus is used, defaulting to off; and add a small
# set of test messages for general make test use; since otherwise "make test"
# in the field will wind up relying on the third-party DNS records at dkim.org.

%patterns = (
q{ DKIM_SIGNED }, 'DKIM_SIGNED', q{ DKIM_VERIFIED }, 'DKIM_VERIFIED',
);
sarun ("-t < data/nice/dkim/BasicTest_01", \&patterns_run_cb);
ok ok_all_patterns();

# skip this test; it fails under current releases of Mail::DKIM.
if (0) {
  %patterns = (
  q{ DKIM_SIGNED }, 'DKIM_SIGNED', q{ DKIM_VERIFIED }, 'DKIM_VERIFIED',
  );
  sarun ("-t < data/nice/dkim/Simple_02", \&patterns_run_cb);
  ok ok_all_patterns();
}

%patterns = (
q{ DKIM_SIGNED }, 'DKIM_SIGNED', q{ DKIM_VERIFIED }, 'DKIM_VERIFIED',
);
sarun ("-t < data/nice/dkim/Nowsp_03", \&patterns_run_cb);
ok ok_all_patterns();

%patterns = (
q{ DKIM_SIGNED }, 'DKIM_SIGNED', q{ DKIM_VERIFIED }, 'DKIM_VERIFIED',
);
sarun ("-t < data/nice/dkim/MIMEsimple_04", \&patterns_run_cb);
ok ok_all_patterns();

%patterns = (
q{ DKIM_SIGNED }, 'DKIM_SIGNED', q{ DKIM_VERIFIED }, 'DKIM_VERIFIED',
);
sarun ("-t < data/nice/dkim/MIMEnowsp_05", \&patterns_run_cb);
ok ok_all_patterns();

%patterns = (
q{ DKIM_SIGNED }, 'DKIM_SIGNED', q{ DKIM_VERIFIED }, 'DKIM_VERIFIED',
);
sarun ("-t < data/nice/dkim/MultipleSig_06", \&patterns_run_cb);
ok ok_all_patterns();


# Message with the presence of the "v=" tag (Message: AddedVtag_07)

# '7. The draft states the following about the v= tag in the Signature: v=
# Verifiers MUST ignore DKIM-Signature header fields with a 'v=' tag. Existence
# of such a tag indicates a new, incompatible version of the DKIM-Signature
# header field. * The message present in the file "AddedVtag_07" is signed with
# the presence of the "v=" tag value set at "DKIM1". * The expected result is
# Authentication-Results: <your_verifying_machine>;
# header.From=mickey@dkim.org; dkim=neutral or fail; based on the Signing
# Policy'
#
# not yet tested -- Mail::DKIM fails this test, by calling this "invalid"
# instead of "neutral" or "fail"

if (0) {
  %patterns = (
  q{ DKIM_SIGNED }, 'DKIM_SIGNED', q{ DKIM_VERIFIED }, 'DKIM_VERIFIED',
  );
  sarun ("-t < data/nice/dkim/AddedVtag_07", \&patterns_run_cb);
  ok ok_all_patterns();
}

%patterns = (
q{ DKIM_SIGNED }, 'DKIM_SIGNED', q{ DKIM_VERIFIED }, 'DKIM_VERIFIED',
);
sarun ("-t < data/nice/dkim/MultipleReceived_08", \&patterns_run_cb);
ok ok_all_patterns();

%patterns = (
q{ DKIM_SIGNED }, 'DKIM_SIGNED', q{ DKIM_VERIFIED }, 'DKIM_VERIFIED',
);
sarun ("-t < data/nice/dkim/NonExistingHeader_09", \&patterns_run_cb);
ok ok_all_patterns();

# '10. Presence of Multiple Authentication-Results headers (Message:
# MultipleAuthRes_10) The message file "MutlipleAuthRes_10" does NOT contain
# any DKIM Signature but carries two pre-existing invalid
# "Authentication-Results" headers. * There is no particular requirement on how
# multiple Authentication-Results headers should be handled. * Determine the
# behavior of your verifier with the presence of these multiple headers. '
#
# no need to worry about this -- this is really an exceptional case
# and its up to Mail::DKIM how it handles it.

if (0) {
  %patterns = (
  q{ DKIM_SIGNED }, 'DKIM_SIGNED', q{ DKIM_VERIFIED }, 'DKIM_VERIFIED',
  );
  sarun ("-t < data/nice/dkim/MultipleAuthRes_10", \&patterns_run_cb);
  ok ok_all_patterns();
}

