#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("report_safe");
use Test; BEGIN { plan tests => 8 };

# ---------------------------------------------------------------------------

# Use a slightly modified gtube ...
my $origtest = 'data/spam/gtube.eml';
my $test = 'log/report_safe.eml';
my $original = '';
if (open(OTEST, $origtest) && open(TEST, ">$test")) {
  local $/=undef;
  $original .= "X-Spam-Prev-Subject: this is a test\n";
  $original .= "X-Spam-Status: No, this should fail horribly!\n";
  $original .= <OTEST>;
  print TEST $original;
  close(TEST);
  close(OTEST);
}
else {
  die "can't open input files: $!";
}

# unfortunately, we can't use a regexp since quotemeta is used on patterns
sub safe {
    my ($boundary, $report_charset, $type, $description, $disposition) = @_;

    return <<"EOM";
Content-Type: $type; x-spam-type=original
Content-Description: $description
Content-Disposition: $disposition
Content-Transfer-Encoding: 8bit

$original
EOM
}

my $description = 'original message before SpamAssassin';
my $disposition = 'inline';
my $message;

%patterns = ('X-Spam-Status: Yes' => 'XSS_Yes', 'X-Spam-Prev-Subject: this is a test' => 'XSS_Prev_Subject');
%anti_patterns = ($original => P_1, 'X-Spam-Status: No' => 'XSS_No');
tstprefs ("report_safe 0\n");
sarun ("-L < $test", \&patterns_run_cb);
ok_all_patterns();

$message = safe($boundary, '', 'message/rfc822', $description, 'inline');
%patterns = ($message => P_2, 'X-Spam-Status: Yes' => 'XSS_Yes');
%anti_patterns = ();
tstprefs ("report_safe 1\n");
sarun ("-L < $test", \&patterns_run_cb);
ok_all_patterns();

$message = safe($boundary, '', 'text/plain', $description, 'inline');
%patterns = ($message => P_3, 'X-Spam-Status: Yes' => 'XSS_Yes');
%anti_patterns = ();
tstprefs ("report_safe 2\n");
sarun ("-L < $test", \&patterns_run_cb);
ok_all_patterns();
