#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("shortcircuit");

use Test::More tests => 18;

# ---------------------------------------------------------------------------

%anti_patterns = (
  q{ autolearn=ham } => 'autolearned as ham'
);

tstpre ('
  loadplugin Mail::SpamAssassin::Plugin::Shortcircuit
');

tstlocalrules ('

  header SHORTCIRCUIT             eval:check_shortcircuit()
  describe SHORTCIRCUIT           Not all rules were run, due to a shortcircuited rule
  tflags SHORTCIRCUIT             userconf noautolearn
  add_header all Status "_YESNO_, score=_SCORE_ required=_REQD_ tests=_TESTS_ shortcircuit=_SCTYPE_ autolearn=_AUTOLEARN_ version=_VERSION_"

  # hits spam/001
  body X_FOO            /Congratulations/
  header X_BAR          From =~ /sb55/
  # this should still fire, fixing the meta dependency ordering automatically
  meta SC_PRI_SPAM_001  (X_FOO && X_BAR)
  shortcircuit SC_PRI_SPAM_001  spam
  priority SC_PRI_SPAM_001 -1000

  # hits spam/002
  header SC_002        Subject =~ /ADV/
  shortcircuit SC_002  on
  priority SC_002      -100
  score SC_002         50

  # nice/001
  header SC_HAM_001    X-Mailer =~ /Evolution/
  shortcircuit SC_HAM_001       ham

');

%patterns = (
  ' 1.0 SC_PRI_SPAM_001 ', 'hit',
  'shortcircuit=spam', 'sc',
  qr/X-Spam-Status: Yes, score=103.0 required=5.0 /m, 'shortcircuit_spam_score',
  ' 100 SHORTCIRCUIT Not all rules were run', 'shortcircuit rule desc',
);
ok (sarun ("-L -t < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

%patterns = (
  ' 50 SC_002 ', 'hit',
  'shortcircuit=spam', 'sc',
  qr/^X-Spam-Status: Yes, score=50.0 required=5.0 /m, 'SC_002 score',
  ' 0.0 SHORTCIRCUIT Not all rules were run', 'shortcircuit rule desc',
);
ok (sarun ("-L -t < data/spam/002", \&patterns_run_cb));
ok_all_patterns();

%patterns = (
  ' -1.0 SC_HAM_001 ', 'SC_HAM_001',
  'shortcircuit=ham', 'sc_ham',
  qr/^X-Spam-Status: No, score=-101.0 required=5.0 /m, 'SC_HAM_001 score',
  ' -100 SHORTCIRCUIT Not all rules were run', 'shortcircuit rule desc',
);
ok (sarun ("-L -t < data/nice/001", \&patterns_run_cb));
ok_all_patterns();

