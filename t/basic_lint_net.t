#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("basic_lint_net");
use Test::More;

plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');

plan tests => 2;

# ---------------------------------------------------------------------------

%patterns = (
  q{  }, 'anything',
);
%anti_patterns = (
  q{ warn: }, 'warning',
);

# override locale for this test!
$ENV{'LANGUAGE'} = $ENV{'LC_ALL'} = 'C';

sarun ("--lint --net", \&patterns_run_cb);
ok_all_patterns();

