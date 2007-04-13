#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("mimeheader");
use Test; BEGIN { plan tests => 4 };

$ENV{'LANGUAGE'} = $ENV{'LC_ALL'} = 'C';             # a cheat, but we need the patterns to work

# ---------------------------------------------------------------------------

%patterns = (

  q{ MIMEHEADER_TEST1 }, q{ test1 },
  q{ MIMEHEADER_TEST2 }, q{ test2 },
  q{ MATCH_NL_NONRAW }, q{ match_nl_nonraw },
  q{ MATCH_NL_RAW }, q{ match_nl_raw },

);

tstprefs (q{

  # loadplugin Mail::SpamAssassin::Plugin::MIMEHeader
  mimeheader MIMEHEADER_TEST1 content-type =~ /application\/msword/
  mimeheader MIMEHEADER_TEST2 content-type =~ m!APPLICATION/MSWORD!i

  mimeheader MATCH_NL_NONRAW       Content-Type =~ /msword; name/
  mimeheader MATCH_NL_RAW   Content-Type:raw =~ /msword;\n\tname/

	});

sarun ("-L -t < data/nice/004", \&patterns_run_cb);
ok_all_patterns();
