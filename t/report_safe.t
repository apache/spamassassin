#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("report_safe");
use Test; BEGIN { plan tests => 3 };

# ---------------------------------------------------------------------------

my $test = 'data/spam/gtube.eml';
open(TEST, $test);
my $original;
while (<TEST>) {
    $original .= $_;
}
close(TEST);

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

%patterns = ();
%anti_patterns = ($original => P_1);
tstprefs ("report_safe 0\n");
sarun ("-L -t < $test", \&patterns_run_cb);
ok_all_patterns();

$message = safe($boundary, '', 'message/rfc822', $description, 'inline');
%patterns = ($message => P_2);
%anti_patterns = ();
tstprefs ("report_safe 1\n");
sarun ("-L -t < $test", \&patterns_run_cb);
ok_all_patterns();

$message = safe($boundary, '', 'text/plain', $description, 'inline');
%patterns = ($message => P_3);
%anti_patterns = ();
tstprefs ("report_safe 2\n");
sarun ("-L -t < $test", \&patterns_run_cb);
ok_all_patterns();
