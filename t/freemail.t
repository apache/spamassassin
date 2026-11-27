#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("freemail");

use Test::More;

plan tests => 37;

# ---------------------------------------------------------------------------

# Global
tstprefs ("
  freemail_domains gmail.com
");

## Standard + whitelist should not hit

tstlocalrules (q{
  freemail_import_whitelist_auth 0
  whitelist_auth test@gmail.com
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

## Now test with freemail_import_whitelist_auth, should not hit

%patterns = ();
%anti_patterns = (
  q{ FREEMAIL_FROM }, '',
);

tstlocalrules (q{
  freemail_import_whitelist_auth 1
  whitelist_auth test@gmail.com
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

## Each rule uses its own regex (Bug 8559)

%patterns = (
  q{ 3.3 FREEMAIL_HDR_YES }, '',
  q{ 3.3 FREEMAIL_FROM_YES }, '',
  q{ 3.3 FREEMAIL_BODY_YES }, '',
);
%anti_patterns = (
  q{ FREEMAIL_HDR_NO }, '',
  q{ FREEMAIL_FROM_NO }, '',
  q{ FREEMAIL_BODY_NO }, '',
);

tstlocalrules (q{
  header FREEMAIL_HDR_YES eval:check_freemail_header('From', '^test')
  score FREEMAIL_HDR_YES 3.3
  header FREEMAIL_HDR_NO eval:check_freemail_header('From', '^another')
  score FREEMAIL_HDR_NO 3.3
  header FREEMAIL_FROM_YES eval:check_freemail_from('^test')
  score FREEMAIL_FROM_YES 3.3
  header FREEMAIL_FROM_NO eval:check_freemail_from('^another')
  score FREEMAIL_FROM_NO 3.3
  header FREEMAIL_BODY_YES eval:check_freemail_body('^another')
  score FREEMAIL_BODY_YES 3.3
  header FREEMAIL_BODY_NO eval:check_freemail_body('^test')
  score FREEMAIL_BODY_NO 3.3
});

ok sarun ("-L -t < data/spam/freemail3", \&patterns_run_cb);
ok_all_patterns();

## Every imported welcomelist_auth entry is used (Bug 8559)

%patterns = ();
%anti_patterns = (
  q{ FREEMAIL_FROM }, '',
  q{ FREEMAIL_BODY }, '',
);

tstlocalrules (q{
  freemail_import_welcomelist_auth 1
  welcomelist_auth test@gmail.com
  welcomelist_auth another1@gmail.com
  header FREEMAIL_FROM eval:check_freemail_from()
  score FREEMAIL_FROM 3.3
  header FREEMAIL_BODY eval:check_freemail_body()
  score FREEMAIL_BODY 3.3
});

ok sarun ("-L -t < data/spam/freemail3", \&patterns_run_cb);
ok_all_patterns();

## mailto: links are matched with each object's own TLD list (Bug 8559)

foreach my $tld ('aa1', 'aa2') {
  my $rule = 'FM_' . uc($tld);
  my $sa = create_saobj({
    config_text => "loadplugin Mail::SpamAssassin::Plugin::Check\n"
      . "loadplugin Mail::SpamAssassin::Plugin::FreeMail\n"
      . "loadhandler Mail::SpamAssassin::Handler::HTML\n"
      . "util_rb_tld $tld\nfreemail_domains mail.aa1 mail.aa2\n"
      . "header $rule eval:check_freemail_body('\\.$tld\$')\nscore $rule 1\n",
    dont_copy_prefs => 1,
  });
  $sa->init(0);
  my $status = $sa->check($sa->parse("Content-Type: text/html\n\n"
    . "<a href=\"mailto:joe\@mail.aa1\">1</a> <a href=\"mailto:joe\@mail.aa2\">2</a>\n"));
  ok($status->get_names_of_tests_hit() =~ /\b$rule\b/);
  $status->finish();
  $sa->finish();
}

## A From address that is also a Reply-To address

foreach my $case (['b', 0], ['d', 1]) {
  my ($local, $hit) = @$case;
  my $sa = create_saobj({
    config_text => "loadplugin Mail::SpamAssassin::Plugin::Check\n"
      . "loadplugin Mail::SpamAssassin::Plugin::FreeMail\n"
      . "freemail_domains gmail.com\n"
      . "header FM_REPLYTO eval:check_freemail_replyto('replyto')\n"
      . "score FM_REPLYTO 1\n",
    dont_copy_prefs => 1,
  });
  $sa->init(0);
  my $status = $sa->check($sa->parse("From: a\@gmail.com, b\@gmail.com\n"
    . "Reply-To: c\@example.com, $local\@gmail.com\n\nhello\n"));
  is(($status->get_names_of_tests_hit() =~ /\bFM_REPLYTO\b/) ? 1 : 0, $hit);
  $status->finish();
  $sa->finish();
}
