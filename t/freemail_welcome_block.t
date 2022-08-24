#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("freemail");

use Test::More;

plan tests => 23;

# ---------------------------------------------------------------------------

# Global
tstprefs ("
  freemail_domains gmail.com
");

## Standard + welcomelist should not hit

tstlocalrules (q{
  freemail_import_welcomelist_auth 0
  welcomelist_auth test@gmail.com
  header FREEMAIL_FROM eval:check_freemail_from()
  score FREEMAIL_FROM 3.3
  header FREEMAIL_REPLYXX eval:check_freemail_replyto('reply')
  score FREEMAIL_REPLYXX 3.3
  header FREEMAIL_REPLYTO eval:check_freemail_replyto('replyto')
  score FREEMAIL_REPLYTO 3.3
  header FREEMAIL_REPLYXX eval:check_freemail_replyto('reply')
  score FREEMAIL_REPLYXX 3.3
  header FREEMAIL_ENVFROM_END_DIGIT  eval:check_freemail_header('EnvelopeFrom', '\d@')
  score FREEMAIL_ENVFROM_END_DIGIT 3.3
  header FREEMAIL_REPLYTO_END_DIGIT  eval:check_freemail_header('Reply-To', '\d@')
  score FREEMAIL_REPLYTO_END_DIGIT 3.3
  header FREEMAIL_HDR_REPLYTO eval:check_freemail_header('Reply-To')
  score FREEMAIL_HDR_REPLYTO 3.3
});

%patterns = (
  q{ 3.3 FREEMAIL_FROM }, '',
);
%anti_patterns = (
  # No Reply-To or body
  q{ FREEMAIL_REPLYTO }, '',
  q{ FREEMAIL_REPLYXX }, '',
  q{ FREEMAIL_ENVFROM_END_DIGIT }, '',
  q{ FREEMAIL_REPLYTO_END_DIGIT }, '',
  q{ FREEMAIL_HDR_REPLYTO }, '',
);

ok sarun ("-L -t < data/spam/relayUS.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

## Now test with freemail_import_welcomelist_auth, should not hit

%patterns = ();
%anti_patterns = (
  q{ FREEMAIL_FROM }, '',
);

tstlocalrules (q{
  freemail_import_welcomelist_auth 1
  welcomelist_auth test@gmail.com
  header FREEMAIL_FROM eval:check_freemail_from()
  score FREEMAIL_FROM 3.3
});

ok sarun ("-L -t < data/spam/relayUS.eml", \&patterns_run_cb);
ok_all_patterns();

## From and Reply-To different

%patterns = (
  q{ 3.3 FREEMAIL_FROM }, '',
  q{ 3.3 FREEMAIL_REPLYTO }, '',
  q{ 3.3 FREEMAIL_REPLYXX }, '',
  q{ 3.3 FREEMAIL_ENVFROM_END_DIGIT }, '',
  q{ 3.3 FREEMAIL_REPLYTO_END_DIGIT }, '',
  q{ 3.3 FREEMAIL_HDR_REPLYTO }, '',
);
%anti_patterns = ();

tstlocalrules (q{
  header FREEMAIL_FROM eval:check_freemail_from()
  score FREEMAIL_FROM 3.3
  header FREEMAIL_REPLYTO eval:check_freemail_replyto('replyto')
  score FREEMAIL_REPLYTO 3.3
  header FREEMAIL_REPLYXX eval:check_freemail_replyto('reply')
  score FREEMAIL_REPLYXX 3.3
  header FREEMAIL_ENVFROM_END_DIGIT  eval:check_freemail_header('EnvelopeFrom', '\d@')
  score FREEMAIL_ENVFROM_END_DIGIT 3.3
  header FREEMAIL_REPLYTO_END_DIGIT  eval:check_freemail_header('Reply-To', '\d@')
  score FREEMAIL_REPLYTO_END_DIGIT 3.3
  header FREEMAIL_HDR_REPLYTO eval:check_freemail_header('Reply-To')
  score FREEMAIL_HDR_REPLYTO 3.3
});

ok sarun ("-L -t < data/spam/freemail1", \&patterns_run_cb);
ok_all_patterns();

## Multiple Reply-To values, no email on body

%patterns = (
  q{ 3.3 FREEMAIL_REPLYTO }, '',
  q{ 3.3 FREEMAIL_REPLYXX }, '',
  q{ 3.3 FREEMAIL_REPLYTO_END_DIGIT }, '',
  q{ 3.3 FREEMAIL_HDR_REPLYTO }, '',
);
%anti_patterns = ();

tstlocalrules (q{
  header FREEMAIL_REPLYTO eval:check_freemail_replyto('replyto')
  score FREEMAIL_REPLYTO 3.3
  header FREEMAIL_REPLYXX eval:check_freemail_replyto('reply')
  score FREEMAIL_REPLYXX 3.3
  header FREEMAIL_REPLYTO_END_DIGIT  eval:check_freemail_header('Reply-To', '\d@')
  score FREEMAIL_REPLYTO_END_DIGIT 3.3
  header FREEMAIL_HDR_REPLYTO eval:check_freemail_header('Reply-To')
  score FREEMAIL_HDR_REPLYTO 3.3
});

ok sarun ("-L -t < data/spam/freemail2", \&patterns_run_cb);
ok_all_patterns();

## No Reply-To, another freemail in body

%patterns = (
  q{ 3.3 FREEMAIL_REPLYXX }, '',
);
%anti_patterns = ();

tstlocalrules (q{
  header FREEMAIL_REPLYXX eval:check_freemail_replyto('reply')
  score FREEMAIL_REPLYXX 3.3
});

ok sarun ("-L -t < data/spam/freemail3", \&patterns_run_cb);
ok_all_patterns();

