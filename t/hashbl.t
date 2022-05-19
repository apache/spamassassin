#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("hashbl");

use Test::More;
plan skip_all => "Net tests disabled"          unless conf_bool('run_net_tests');
plan skip_all => "Can't use Net::DNS Safely"   unless can_use_net_dns_safely();

# run many times to catch some random natured failures
my $iterations = 5;
plan tests => 11 * $iterations;

# ---------------------------------------------------------------------------

%patterns = (
 q{ 1.0 X_HASHBL_EMAIL } => '',
 q{ 1.0 X_HASHBL_OSENDR } => '',
 q{ 1.0 X_HASHBL_BTC } => '',
 q{ 1.0 X_HASHBL_URI } => '',
 q{ 1.0 X_HASHBL_TAG } => '',
 q{ 1.0 META_HASHBL_EMAIL } => '',
 q{ 1.0 META_HASHBL_BTC } => '',
 q{ 1.0 META_HASHBL_URI } => '',
);
%anti_patterns = (
 q{ 1.0 X_HASHBL_SHA256 } => '',
);

# Check from debug output log that nothing else than these were queried
@valid_queries = qw(
cb565607a98fbdf1be52cdb86466ab34244bd6fc.hashbltest1.spamassassin.org
bc9f1b35acd338b92b0659cc2111e6b661a8b2bc.hashbltest1.spamassassin.org
62e12fbe4b32adc2e87147d74590372b461f35f6.hashbltest1.spamassassin.org
96b802967118135ef048c2bc860e7b0deb7d2333.hashbltest1.spamassassin.org
170d83ef2dc9c2de0e65ce4461a3a375.hashbltest2.spamassassin.org
cc205dd956d568ff8524d7fc42868500e4d7d162.hashbltest3.spamassassin.org
jykf2a5v6asavfel3stymlmieh4e66jeroxuw52mc5xhdylnyb7a.hashbltest3.spamassassin.org
6a42acf4133289d595e3875a9d677f810e80b7b4.hashbltest4.spamassassin.org
5c6205960a65b1f9078f0e12dcac970aab0015eb.hashbltest4.spamassassin.org
1234567890.hashbltest5.spamassassin.org
w3hcrlct6yshq5vq6gjv2hf3pzk3jvsk6ilj5iaks4qwewudrr6q.hashbltest6.spamassassin.org
);

sub check_queries {
  my %invalid;
  my %found;
  if (!open(WL, $current_checkfile)) {
    diag("LOGFILE OPEN FAILED");
    return 0;
  }
  while (<WL>) {
    my $line = $_;
    while ($line =~ /\b(\w+\.hashbltest\d\.spamassassin\.org)\b/g) {
      my $query = $1;
      $found{$query}++;
      if (!grep { $query eq $_ } @valid_queries) {
        $invalid{$query}++;
      }
    }
  }
  close WL;
  diag("Invalid query launched: $_") foreach (keys %invalid);
  unless (keys %found == @valid_queries) {
    diag("Incorrect amount of queries launched");
    return 0;
  }
  return !%invalid;
}

tstlocalrules(q{
  rbl_timeout 30

  header   X_HASHBL_EMAIL eval:check_hashbl_emails('hashbltest1.spamassassin.org')
  tflags   X_HASHBL_EMAIL net

  hashbl_acl_freemail gmail.com
  header   X_HASHBL_OSENDR eval:check_hashbl_emails('hashbltest2.spamassassin.org/A', 'md5/max=10/shuffle', 'X-Original-Sender', '^127\.', 'freemail')
  tflags   X_HASHBL_OSENDR net

  body     X_HASHBL_BTC eval:check_hashbl_bodyre('hashbltest3.spamassassin.org', 'sha1/max=10/shuffle', '\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
  tflags   X_HASHBL_BTC net

  # Not supposed to hit, @valid_queries just checks that sha256 is calculated correctly
  body     X_HASHBL_SHA256 eval:check_hashbl_bodyre('hashbltest3.spamassassin.org', 'sha256/max=10/shuffle', '\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
  tflags   X_HASHBL_SHA256 net

  header   X_HASHBL_URI eval:check_hashbl_uris('hashbltest4.spamassassin.org', 'sha1', '127.0.0.2')
  tflags   X_HASHBL_URI net

  header   __X_SOME_ID X-Some-ID =~ /^(?<XSOMEID>\d{10,20})$/
  header   X_HASHBL_TAG eval:check_hashbl_tag('hashbltest5.spamassassin.org/A', 'raw', 'XSOMEID', '^127\.')
  tflags   X_HASHBL_TAG net

  # Not supposed to hit, @valid_queries just checks that they are launched
  hashbl_ignore text/plain
  body     X_HASHBL_ATT eval:check_hashbl_attachments('hashbltest6.spamassassin.org/A', 'sha256')
  describe X_HASHBL_ATT Message contains attachment found on attbl
  tflags   X_HASHBL_ATT net

  # Bug 7897 - test that meta rules depending on net rules hit
  meta META_HASHBL_EMAIL X_HASHBL_EMAIL
  # It also needs to hit even if priority is lower than dnsbl (-100)
  meta META_HASHBL_BTC X_HASHBL_BTC
  priority META_HASHBL_BTC -500
  # Or super high
  meta META_HASHBL_URI X_HASHBL_URI
  priority META_HASHBL_URI 2000
  priority X_HASHBL_URI 2000
});

for (1 .. $iterations) {
  ok sarun ("-t -D async,dns,HashBL < data/spam/hashbl 2>&1", \&patterns_run_cb);
  ok(check_queries());
  ok_all_patterns();
}

