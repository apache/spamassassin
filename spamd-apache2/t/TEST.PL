#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

use lib qw(lib);

use Apache::TestRunPerl ();

Apache::TestRunPerl->new->run(@ARGV);

{
	no warnings 'redefine';

#	sub Apache::TestRun::pre_configure {
#		Apache::TestConfig::autoconfig_skip_module_add(qr(.));
#	}
}

# vim: ts=4 sw=4 noet
