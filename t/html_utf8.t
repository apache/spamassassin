#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("html_obfu");

use constant TEST_ENABLED => ($] > 5.008004);

use Test; BEGIN { plan tests => (TEST_ENABLED ? 2 : 0) };

exit unless (TEST_ENABLED);

# ---------------------------------------------------------------------------

%patterns = (
q{ QUOTE_YOUR } => 'QUOTE_YOUR',
);

%anti_patterns = (
q{ OPPORTUNITY } => 'OPPORTUNITY',
);

tstlocalrules ('
body OPPORTUNITY	/OPPORTUNITY/
# body QUOTE_YOUR /\x{201c}Your/
body QUOTE_YOUR /\xE2\x80\x9CYour/
');
sarun ("-L -t < data/spam/009", \&patterns_run_cb);
ok_all_patterns();
