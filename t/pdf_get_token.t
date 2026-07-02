#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use lib 'blib/lib'; use lib '../blib/lib';
use Test::More;
use Mail::SpamAssassin::PDF::Core;
use Data::Dumper;

my $data = <<'EOF';
%PDF-1.4
34 0 obj<</Name /Page /Parent 1 0 R /MediaBox [0 0 612 792] /XObject <</Resources 2 0 R /Contents 4 0 R /Type /Page /Rotate 0>>>>
[[1 0 0 1 0 0] 0]
44 (q) -273.2 .5 1.5 rg
EOF

my @tokens = qw(
    34 0 obj << / Name / Page / Parent 1 0 R / MediaBox [ 0 0 612 792 ] / XObject << / Resources 2 0 R / Contents 4 0 R / Type / Page / Rotate 0 >> >>
    [ [ 1 0 0 1 0 0 ] 0 ]
    44 ( q ) -273.2 .5 1.5 rg
);

plan tests => scalar @tokens;

my $core = Mail::SpamAssassin::PDF::Core->new(\$data);
$core->pos(9);
my $i=0;
foreach my $token (@tokens) {
    my $result = $core->get_token();
    is($result, $token, "token #$i");
    $i++;
}
