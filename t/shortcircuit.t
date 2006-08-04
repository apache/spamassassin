#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("shortcircuit");
use Test; BEGIN { plan tests => 8 };

# ---------------------------------------------------------------------------

%anti_patterns = (
q{ autolearn=ham } => 'autolearned as ham'
);

tstlocalrules ('

  loadplugin Mail::SpamAssassin::Plugin::Shortcircuit

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

');

%patterns = (
  q{ SC_PRI_SPAM_001 }, 'hit',
  q{ shortcircuit=spam }, 'sc',
);
ok (sarun ("-L -t < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

%patterns = (
  q{ SC_002 }, 'hit',
  q{ shortcircuit=spam }, 'sc',
);
ok (sarun ("-L -t < data/spam/002", \&patterns_run_cb));
ok_all_patterns();
