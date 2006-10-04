#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("mimeheader");
use Test; BEGIN { plan tests => 2 };

$ENV{'LANGUAGE'} = $ENV{'LC_ALL'} = 'C';             # a cheat, but we need the patterns to work

# ---------------------------------------------------------------------------

%patterns = (

  q{ MIMEHEADER_TEST1 }, q{ test1 },
  q{ MIMEHEADER_TEST2 }, q{ test2 },

);

tstprefs (q{

  # loadplugin Mail::SpamAssassin::Plugin::MIMEHeader
  mimeheader MIMEHEADER_TEST1 content-type =~ /application\/msword/
  mimeheader MIMEHEADER_TEST2 content-type =~ m!APPLICATION/MSWORD!i

	});

sarun ("-L -t < data/nice/004", \&patterns_run_cb);
ok_all_patterns();
