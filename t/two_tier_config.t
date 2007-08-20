#!/usr/bin/perl

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_tests.t", kluge around ...
    chdir 't';
  }

  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib');
    unshift(@INC, '../lib');
  }
}

my $prefix = '.';
if (-e 'test_dir') {            # running from test directory, not ..
  $prefix = '..';
}

use lib '.'; use lib 't';
use SATest; sa_t_init("two_tier_config");
use Test; BEGIN { plan tests => 33 };

use strict;
require Mail::SpamAssassin;

# ---------------------------------------------------------------------------

my $sa = create_saobj({'dont_copy_prefs' => 1, post_config_text => q{

  allow_user_rules 1
  header LAST_RCVD_LINE   Received =~ /www.fasttrec.com/
  header MESSAGEID_MATCH  MESSAGEID =~ /fasttrec.com/
  header ENV_FROM         EnvelopeFrom =~ /jm.netnoteinc.com/
  body SUBJ_IN_BODY       /YOUR BRAND NEW HOUSE/
  uri URI_RULE            /WWW.SUPERSITESCENTRAL.COM/i
  body BODY_LINE_WRAP     /making obscene amounts of money from the/
  header RELAYS           X-Spam-Relays-Untrusted =~ / helo=www.fasttrec.com /
  required_score 7
  rewrite_header Subject  FOO
  add_header spam Foo Hello
  whitelist_from jm@example.com
  blacklist_from n1@example.com
  score URI_RULE 10
  redirector_pattern    /^http:\/\/foo.com\/(.*)$/i
  clear_report_template
  report Foo

}}); $sa->init(0);

ok ($sa->{conf}->{required_score}, 7);
ok ($sa->{conf}->{rewrite_header}->{Subject}, "FOO");
ok ($sa->{conf}->{headers_spam}->{Foo}, "Hello");
ok ($sa->{conf}->{whitelist_from}->{'jm@example.com'}, '^jm\@example\.com$');
ok ($sa->{conf}->{blacklist_from}->{'n1@example.com'}, '^n1\@example\.com$');
ok grep { $_ eq '^jm\@example\.com$' } values %{$sa->{conf}->{whitelist_from}};

ok ($sa->{conf}->{scores}->{URI_RULE}, 10);
ok grep { m!http:\\/\\/foo.com\\/! } @{$sa->{conf}->{redirector_patterns}};
ok !grep { m!http:\\/\\/bar.com\\/! } @{$sa->{conf}->{redirector_patterns}};

ok ($sa->{conf}->{report_template}, "Foo\n");

# ---------------------------------------------------------------------------

$sa->{conf}->push_tier();
open OUT, ">log/localrules.tmp/tier1.cf" or die; print OUT q{

  required_score 8
  rewrite_header Subject  BAR
  clear_headers
  add_header spam Bar Hello
  unblacklist_from n1@example.com
  whitelist_from n2@example.com
  score URI_RULE 5
  redirector_pattern    /^http:\/\/bar.com\/(.*)$/i

  # should append
  report Bar

}; close OUT or die;
$sa->read_scoreonly_config("log/localrules.tmp/tier1.cf");

ok ($sa->{conf}->{required_score}, 8);
ok ($sa->{conf}->{rewrite_header}->{Subject}, "BAR");
ok ($sa->{conf}->{headers_spam}->{Foo}, undef);
ok ($sa->{conf}->{headers_spam}->{Bar}, "Hello");
ok ($sa->{conf}->{whitelist_from}->{'jm@example.com'}, '^jm\@example\.com$');
ok ($sa->{conf}->{whitelist_from}->{'n2@example.com'}, '^n2\@example\.com$');
ok ($sa->{conf}->{blacklist_from}->{'n1@example.com'}, undef);
ok ($sa->{conf}->{scores}->{URI_RULE}, 5);
ok grep { m!http:\\/\\/foo.com\\/! } @{$sa->{conf}->{redirector_patterns}};
ok grep { m!http:\\/\\/bar.com\\/! } @{$sa->{conf}->{redirector_patterns}};

ok ($sa->{conf}->{report_template}, "Foo\nBar\n");

# ---------------------------------------------------------------------------

$sa->{conf}->pop_tier();
ok ($sa->{conf}->{required_score}, 7);
ok ($sa->{conf}->{rewrite_header}->{Subject}, "FOO");
ok ($sa->{conf}->{headers_spam}->{Foo}, "Hello");
ok ($sa->{conf}->{headers_spam}->{Bar}, undef);
ok ($sa->{conf}->{whitelist_from}->{'jm@example.com'}, '^jm\@example\.com$');
ok ($sa->{conf}->{blacklist_from}->{'n1@example.com'}, '^n1\@example\.com$');
ok ($sa->{conf}->{blacklist_from}->{'n2@example.com'}, undef);
ok ($sa->{conf}->{scores}->{URI_RULE}, 10);
ok grep { m!http:\\/\\/foo.com\\/! } @{$sa->{conf}->{redirector_patterns}};
ok !grep { m!http:\\/\\/bar.com\\/! } @{$sa->{conf}->{redirector_patterns}};

ok ($sa->{conf}->{report_template}, "Foo\n");

# ---------------------------------------------------------------------------

$sa->finish(); ok 1;
