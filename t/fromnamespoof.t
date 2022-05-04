#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("fromnamespoof");

use Test::More;

plan tests => 3;

# ---------------------------------------------------------------------------

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::FromNameSpoof
");

tstlocalrules ("
  header FROMNAME_EQUALS_TO  eval:check_fromname_equals_to()
  score FROMNAME_EQUALS_TO 3.3

  header FROMNAME_EQUALS_REPLYTO  eval:check_fromname_equals_replyto()
  score FROMNAME_EQUALS_REPLYTO 3.3
");

%patterns = (
  q{ 3.3 FROMNAME_EQUALS_TO }, 'FROMNAME_EQUALS_TO',
  q{ 3.3 FROMNAME_EQUALS_REPLYTO }, 'FROMNAME_EQUALS_REPLYTO',
);

ok sarun ("-L -t < data/spam/fromnamespoof/spoof1", \&patterns_run_cb);
ok_all_patterns();
