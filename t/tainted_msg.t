#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("tainted_msg");
use Test; BEGIN { plan tests => 8 };

# ---------------------------------------------------------------------------

%patterns = (

  q{ tainted get_header found } => '',
  q{ tainted get_pristine found } => '',
  q{ tainted get_pristine_body found } => '',
  q{ tainted get_body found } => '',
  q{ tainted get_visible_rendered_body_text_array found } => '',
  q{ tainted get_decoded_body_text_array found } => '',
  q{ tainted get_rendered_body_text_array found } => '',

);
%anti_patterns = ();

tstlocalrules ("
    loadplugin myTestPlugin ../../data/taintcheckplugin.pm
");

ok (sarun ("-L -t < data/spam/gtube.eml", \&patterns_run_cb));
ok_all_patterns();

