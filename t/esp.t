#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("esp");

use Test::More;
plan tests => 2;

tstprefs("
  loadplugin Mail::SpamAssassin::Plugin::Esp

  sendgrid_feed data/spam/esp/sendgrid_id.txt
  header   SENDGRID_ID   eval:esp_sendgrid_check_id()
  describe SENDGRID_ID   Check Sendgrid id

  mailchimp_feed data/spam/esp/mailchimp.txt
  header   MAILCHIMP_ID   eval:esp_mailchimp_check()
  describe MAILCHIMP_ID   Check Mailchimp id
");

%patterns_sendgrid_id = (
  q{ SENDGRID_ID } => 'Sendgrid',
);

%patterns = %patterns_sendgrid_id;
sarun ("-L -t < data/spam/esp/sendgrid_id.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns_mailchimp_id = (
  q{ MAILCHIMP_ID } => 'Mailchimp',
);

%patterns = %patterns_mailchimp_id;
sarun ("-L -t < data/spam/esp/mailchimp.eml", \&patterns_run_cb);
ok_all_patterns();

