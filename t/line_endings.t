#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("line_endings");

use constant TEST_ENABLED => conf_bool('run_long_tests');

use Test; BEGIN {
  plan tests => (TEST_ENABLED ? 26 : 0);
};
exit unless TEST_ENABLED;

# ---------------------------------------------------------------------------

# Use a slightly modified gtube ...
my $origtest = 'data/spam/gtube.eml';
my $test = 'log/report_safe.eml';
my $test2 = 'log/report_safe2.eml';
my $original = '';
if (open(OTEST, $origtest) && open(TEST, ">$test") && open(TEST2, ">$test2")) {
  binmode OTEST;
  binmode TEST;
  binmode TEST2;

  local $/=undef;
  $original .= "X-Spam-Prev-Subject: this is a test\n";
  $original .= "X-Spam-Status: No, this should fail horribly!\n";
  $original .= <OTEST>;
  $original =~ s/\r*\n/\r\n/gs; print TEST $original;
  $original =~ s/\r*\n/\n/gs; print TEST2 $original;

  close(TEST);
  close(TEST2);
  close(OTEST);
}
else {
  die "can't open input files: $!";
}

my $description = 'original message before SpamAssassin';
my $disposition = 'inline';
my $message;

my $resulttext;
my $count_crnl;
my $count_nl;

%patterns = ('X-Spam-Status: Yes' => 'XSS_Yes');
%anti_patterns = ($original => P_1, 'X-Spam-Status: No' => 'XSS_No', q{ MISSING_HB_SEP }, 'hb_sep');
tstprefs ("report_safe 0\n");
sarun ("-L < $test", \&my_patterns_run);
ok_all_patterns();

# support one *or* the other, depending on platform
count_line_endings($resulttext);
if ($count_crnl) {
  ok ($count_crnl!=0 && $count_nl==0);
} else {
  ok ($count_crnl==0 && $count_nl!=0);
}

$message = safe($boundary, '', 'message/rfc822', $description, 'inline');
%patterns = ($message => P_2, 'X-Spam-Status: Yes' => 'XSS_Yes');
%anti_patterns = ( q{ MISSING_HB_SEP }, 'hb_sep');
tstprefs ("report_safe 1\n");
sarun ("-L < $test", \&my_patterns_run);
ok_all_patterns();
count_line_endings($resulttext);
if ($count_crnl) {
  ok ($count_crnl!=0 && $count_nl==0);
} else {
  ok ($count_crnl==0 && $count_nl!=0);
}

$message = safe($boundary, '', 'text/plain', $description, 'inline');
%patterns = ($message => P_3, 'X-Spam-Status: Yes' => 'XSS_Yes');
%anti_patterns = ( q{ MISSING_HB_SEP }, 'hb_sep');
tstprefs ("report_safe 2\n");
sarun ("-L < $test", \&my_patterns_run);
ok_all_patterns();
count_line_endings($resulttext);
if ($count_crnl) {
  ok ($count_crnl!=0 && $count_nl==0);
} else {
  ok ($count_crnl==0 && $count_nl!=0);
}

# now with the other line-ending style...

%patterns = ('X-Spam-Status: Yes' => 'XSS_Yes');
%anti_patterns = ($original => P_1, 'X-Spam-Status: No' => 'XSS_No', q{ MISSING_HB_SEP }, 'hb_sep');
tstprefs ("report_safe 0\n");
sarun ("-L < $test2", \&my_patterns_run);
ok_all_patterns();

# support one *or* the other, depending on platform
count_line_endings($resulttext);
if ($count_crnl) {
  ok ($count_crnl!=0 && $count_nl==0);
} else {
  ok ($count_crnl==0 && $count_nl!=0);
}

$message = safe($boundary, '', 'message/rfc822', $description, 'inline');
%patterns = ($message => P_2, 'X-Spam-Status: Yes' => 'XSS_Yes');
%anti_patterns = ( q{ MISSING_HB_SEP }, 'hb_sep');
tstprefs ("report_safe 1\n");
sarun ("-L < $test2", \&my_patterns_run);
ok_all_patterns();
count_line_endings($resulttext);
if ($count_crnl) {
  ok ($count_crnl!=0 && $count_nl==0);
} else {
  ok ($count_crnl==0 && $count_nl!=0);
}

$message = safe($boundary, '', 'text/plain', $description, 'inline');
%patterns = ($message => P_3, 'X-Spam-Status: Yes' => 'XSS_Yes');
%anti_patterns = ( q{ MISSING_HB_SEP }, 'hb_sep');
tstprefs ("report_safe 2\n");
sarun ("-L < $test2", \&my_patterns_run);
ok_all_patterns();
count_line_endings($resulttext);
if ($count_crnl) {
  ok ($count_crnl!=0 && $count_nl==0);
} else {
  ok ($count_crnl==0 && $count_nl!=0);
}
exit;

# ---------------------------------------------------------------------------

# unfortunately, we cannot use a regexp since quotemeta is used on patterns
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

sub my_patterns_run {
  $resulttext = join ('', <IN>);
  return patterns_run_cb($resulttext);
}

sub count_line_endings {
  $count_crnl = 0;
  $count_nl = 0;
  foreach my $line (split(/\n/s, shift)) {
    if ($line =~ /\r$/) {
      $count_crnl++;
    } else {
      $count_nl++;
    }
  }
  print "line endings found: NL=$count_nl CRNL=$count_crnl\n";
}
