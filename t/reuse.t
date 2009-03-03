#!/usr/bin/perl -w

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_tests.t", kluge around ...
    chdir 't';
  }

  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib');
  }
}

my $prefix = '.';
if (-e 'test_dir') {            # running from test directory, not ..
  $prefix = '..';
}

use strict;
use SATest; sa_t_init("reuse");
use Test;

use vars qw(%patterns %anti_patterns $perl_path &patterns_run_cb);

use Mail::SpamAssassin;

if (-e '../masses/mass-check') {
  plan tests => 37;
}
else {
  plan tests => 0;
  exit;
}

# Tests the following cases:
# - No reuse: no change
# - Reuse and no X-Spam-Status: no change
# - Reuse on: metas work
# - Reuse works with existing tests (disabled)
# - Reuse works with non-existing tests (they get scores)
# - Reuse handles multiple "old rule names"
# - Reuse works in positive and negative cases
# - Rules defined only by "reuse" can have arbitrary scores and priorities set

tstlocalrules('

# Check that order of reuse/body lines for BODY_RULE_* does not matter
reuse  BODY_RULE_1

body   BODY_RULE_1    /./
score  BODY_RULE_1    1.0

body   BODY_RULE_2    /\bfoobar\b/
score  BODY_RULE_2    1.0

header HEADER_RULE_1  Subject =~ /\bmessage\b/

meta   META_RULE_1    BODY_RULE_1 || BODY_RULE_2

reuse    BODY_RULE_2
priority BODY_RULE_2  -2
score    BODY_RULE_2  1.5

reuse    NEW_RULE     OTHER_RULE
priority NEW_RULE     -3
score    NEW_RULE     0.5

reuse    OTHER_RULE
priority OTHER_RULE   -4

reuse    RENAMED_RULE OLD_RULE_1 OLD_RULE_2 OLD_RULE_3

reuse    SCORED_RULE  OLD_RULE_2
score    SCORED_RULE  2.0
priority SCORED_RULE -1

');

# reuse on, mail has no X-Spam-Status
write_mail(0);
ok_system("$perl_path -w ../masses/mass-check -c=log/localrules.tmp --reuse --file log/mail.txt > log/noxss.out");

%patterns = (
             'BODY_RULE_1' => 'BODY_RULE_1',
             'HEADER_RULE_1' => 'HEADER_RULE_1',
             'META_RULE_1' => 'META_RULE_1'
             );
%anti_patterns = (
                  'NEW_RULE' => 'NEW_RULE',
                  'OTHER_RULE' => 'OTHER_RULE',
                  'RENAMED_RULE' => 'RENAMED_RULE',
                  'NONEXISTANT_RULE' => 'NONEXISTANT_RULE',
                  'BODY_RULE_2' => 'BODY_RULE_2',
                  'SCORED_RULE' => 'SCORED_RULE'
                  );

checkfile("noxss.out", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

# write mail with X-Spam-Status
write_mail(1);

# test without reuse
ok_system("$perl_path -w ../masses/mass-check -c=log/localrules.tmp --file log/mail.txt > log/noreuse.out");

%patterns = (
             'BODY_RULE_1' => 'BODY_RULE_1',
             'HEADER_RULE_1' => 'HEADER_RULE_1',
             'META_RULE_1' => 'META_RULE_1'
             );
%anti_patterns = (
                  'NEW_RULE' => 'NEW_RULE',
                  'OTHER_RULE' => 'OTHER_RULE',
                  'RENAMED_RULE' => 'RENAMED_RULE',
                  'NONEXISTANT_RULE' => 'NONEXISTANT_RULE',
                  'BODY_RULE_2' => 'BODY_RULE_2',
                  'SCORED_RULE' => 'SCORED_RULE'
                  );
checkfile("noreuse.out", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

# test with reuse
ok_system("$perl_path -w ../masses/mass-check -c=log/localrules.tmp --reuse --file log/mail.txt > log/reuse.out");


%patterns = (
             'HEADER_RULE_1' => 'HEADER_RULE_1',
             'BODY_RULE_2' => 'BODY_RULE_2',
             'META_RULE_1' => 'META_RULE_1',
             'NEW_RULE' => 'NEW_RULE',
             'OTHER_RULE' => 'OTHER_RULE',
             'RENAMED_RULE' => 'RENAMED_RULE',
             'SCORED_RULE' => 'SCORED_RULE',
             'Y 8' => 'score'
             );
%anti_patterns = (
                  'BODY_RULE_1' => 'BODY_RULE_1',
                  'NONEXISTANT_RULE' => 'NONEXISTANT_RULE'
                  );

checkfile("reuse.out", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

tstlocalrules('

meta META_RULE_1 RULE_A && !RULE_B

body  RULE_A /./
reuse RULE_B OTHER_RULE

body  RULE_C / does not hit /

meta META_RULE_2 (RULE_A && RULE_B) || RULE_C

');

write_mail(1);

# test with reuse
ok_system("$perl_path -w ../masses/mass-check -c=log/localrules.tmp --reuse --file log/mail.txt > log/metareuse.out");

%patterns = (
	     'META_RULE_2' => 'META_RULE_2',
	     'RULE_A' => 'RULE_A',
	     'RULE_B' => 'RULE_B',
             );
%anti_patterns = (
	     'META_RULE_1' => 'META_RULE_1',
	     'RULE_C' => 'RULE_C',
		 );
checkfile("metareuse.out", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();


sub write_mail {
    my ($x_spam_status) = @_;

    my $msg = <<EOF;
Received: from internal.example.com [127.0.0.1] by localhost
    for recipient\@example.com; Fri, 07 Oct 2002 09:02:00 +0000
Received: from external.spammer.com (external.spammer.com
    [150.51.53.1]) by internal.example.com for recipient\@example.com;
    Fri, 07 Oct 2002 09:01:00 +0000
Message-ID: <clean.1010101\@example.com>
Date: Mon, 07 Oct 2002 09:00:00 +0000
From: Sender <sender\@this-spammer.com>
MIME-Version: 1.0
To: Recipient <recipient\@example.com>
Subject: trivial message
Content-Type: text/plain; charset=us-ascii; format=flowed
Content-Transfer-Encoding: 7bit
EOF

    if ($x_spam_status) {
        $msg .= <<END;
X-Spam-Status: Yes, score=15.3 required=5.0 tests=BODY_RULE_2,
	NONEXISTANT_RULE,OTHER_RULE,OLD_RULE_2,OLD_RULE_3
END
    }

    $msg .= <<END;


This is a test message.

END

    tstfile($msg);
}

sub ok_system {
    my $cmd = shift;

    print "\t$cmd\n";
    system($cmd);
    my $exit_code = ($?>>8);
    ok ($exit_code == 0)

}

