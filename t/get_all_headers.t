#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("get_all_headers");
use Test; BEGIN { plan tests => 5 };

# ---------------------------------------------------------------------------

%patterns = (

q{ MIME-Version: 1.0 } => 'no-extra-space',

q{/text-all-raw: Received: from yahoo\.com\[\\\\n\]    \(PPPa33-ResaleLosAngelesMetroB2-2R7452\.dialinx\.net \[4\.48\.136\.190\]\) by\[\\\\n\]    www\.goabroad\.com\.cn \(8\.9\.3/8\.9\.3\) with SMTP id TAA96146; Thu,\[\\\\n\]    30 Aug 2001 19:06:45 \+0800 \(CST\) \(envelope-from\[\\\\n\]    pertand\@email\.mondolink\.com\)\[\\\\n\]From  :<tst1\@example\.com>\[\\\\n\]X-Mailer: Mozilla 4\.04 \[en\]C-bls40  \(Win95; U\)\[\\\\n\]To: jenny33436\@netscape\.net\[\\\\n\]Subject: via\.gra\[\\\\n\]From:\[\\\\t\]  <tst2\@example\.com>\[\\\\n\]DATE: Fri, 7 Dec 2001 07:01:03\[\\\\n\]MIME-Version: 1\.0\[\\\\n\]Message-Id: <20011206235802\.4FD6F1143D6\@mail\.netnoteinc\.com>\[\\\\n\]Sender: travelincentives\@aol\.com\[\\\\n\]Content-Type: text/plain; charset="us-ascii"\[\\\\n\]/} => 'full-headers-raw',

q{/text-all-noraw: Received: from yahoo\\.com \\(PPPa33-ResaleLosAngelesMetroB2-2R7452\\.dialinx\\.net \\[4\\.48\\.136\\.190\\]\\) by www\\.goabroad\\.com\\.cn \\(8\\.9\\.3/8\\.9\\.3\\) with SMTP id TAA96146; Thu, 30 Aug 2001 19:06:45 \\+0800 \\(CST\\) \\(envelope-from pertand\\@email\\.mondolink\\.com\\)\[\\\\n\]From:<tst1\\@example\\.com>\[\\\\n\]X-Mailer: Mozilla 4\\.04 \\[en\\]C-bls40  \\(Win95; U\\)\[\\\\n\]To: jenny33436\\@netscape\\.net\[\\\\n\]Subject: via\\.gra\[\\\\n\]From:\[\\\\t\]  <tst2\\@example\\.com>\[\\\\n\]DATE: Fri, 7 Dec 2001 07:01:03\[\\\\n\]MIME-Version: 1\\.0\[\\\\n\]Message-Id: <20011206235802\\.4FD6F1143D6\\@mail\\.netnoteinc\\.com>\[\\\\n\]Sender: travelincentives\\@aol\\.com\[\\\\n\]Content-Type: text/plain; charset="us-ascii"\[\\\\n\]/} => 'full-headers-noraw',

);

%anti_patterns = (

q{/MIME-Version:  1\.0/} => 'extra-space'

);

tstlocalrules ("
  loadplugin Dumpheaders ../../data/Dumpheaders.pm
");

ok (sarun ("-L -t < data/spam/008", \&patterns_run_cb));
ok_all_patterns();

