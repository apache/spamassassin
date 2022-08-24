#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("tainted_msg");

use constant AM_TAINTED => (!defined($ENV{'TEST_PERL_TAINT'}) or $ENV{'TEST_PERL_TAINT'} ne 'no');

use Test::More;
plan skip_all => "Not Tainted" unless AM_TAINTED;
plan tests => 9;

# ---------------------------------------------------------------------------

%patterns = (
  q{ tainted get_header found } => '',
  q{ tainted get_pristine found } => '',
  q{ tainted get_pristine_body found } => '',
  q{ tainted get_pristine_header found } => '',
  q{ tainted get_body found } => '',
  q{ tainted get_visible_rendered_body_text_array found } => '',
  q{ tainted get_decoded_body_text_array found } => '',
  q{ tainted get_rendered_body_text_array found } => '',
);
%anti_patterns = ();

tstprefs ("
  loadplugin myTestPlugin ../../../data/taintcheckplugin.pm
");

use Mail::SpamAssassin::Util;
Mail::SpamAssassin::Util::untaint_var(\%ENV);

ok (sarun ("-L -t < data/spam/gtube.eml", \&patterns_run_cb));
ok_all_patterns();

