#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("reportheader");

use Test::More tests => 11;

$ENV{'LANGUAGE'} = $ENV{'LC_ALL'} = 'C';             # a cheat, but we need the patterns to work

# ---------------------------------------------------------------------------

%patterns = (
  q{ Spam detection software, running on the system "}, 'spam-report-body',
  q{ Subject: There yours for FREE!}, 'subj',
  q{ X-Spam-Status: Yes, score=}, 'status',
  q{ X-Spam-Flag: YES}, 'flag',
  q{ From: ends in many numbers}, 'endsinnums',
  q{ From: does not include a real name}, 'noreal',
  q{ BODY: Nobody's perfect }, 'remove',
  q{ Message-Id is not valid, }, 'msgidnotvalid',
  q{ 'From' yahoo.com does not match }, 'fromyahoo',
  q{ Invalid Date: header (not RFC 2822) }, 'invdate',
  q{ Uses a dotted-decimal IP address in URL }, 'dotteddec',
);

# This test checks that the report template feature works.
# Define a representative example default template here to test out
tstprefs ('
  clear_report_template
  report Spam detection software, running on the system "_HOSTNAME_",
  report has_YESNO(, NOT)_ identified this incoming email as_YESNO( possible,)_ spam.  The original
  report message has been attached to this so you can view it or label
  report similar future email.  If you have any questions, see
  report _CONTACTADDRESS_ for details.
  report
  report Content preview:  _PREVIEW_
  report
  report Content analysis details:   (_SCORE_ points, _REQD_ required)
  report
  report " pts rule name              description"
  report  ---- ---------------------- --------------------------------------------------
  report _SUMMARY_

  report_contact  @@CONTACT_ADDRESS@@

  clear_headers

  add_header all Checker-Version SpamAssassin _VERSION_ (_SUBVERSION_) on _HOSTNAME_
  add_header spam Flag _YESNOCAPS_
  add_header all Level _STARS(*)_
  add_header all Status "_YESNO_, score=_SCORE_ required=_REQD_ tests=_TESTS_ autolearn=_AUTOLEARN_ version=_VERSION_"
  report_safe 0
');

sarun ("-L -t < data/spam/001", \&patterns_run_cb);
ok_all_patterns();

