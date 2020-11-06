#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("esp");

use Test::More;
plan tests => 1;

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::Esp
");

tstprefs("

sendgrid_feed data/spam/esp/sendgrid_id.txt
header   SENDGRID_ID   eval:esp_sendgrid_check_id()
describe SENDGRID_ID   Check Sendgrid id

");

%patterns_sendgrid_id = (
        q{ SENDGRID_ID } => 'Sendgrid',
            );

%patterns = %patterns_sendgrid_id;
sarun ("-L -t < data/spam/esp/sendgrid_id.eml", \&patterns_run_cb);
ok_all_patterns();
