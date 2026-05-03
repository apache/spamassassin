#!/usr/bin/perl -T
use strict;
use warnings;
use lib 'lib';
use Mail::SpamAssassin::HTML;
use Test::More;

my @tests;
do {
    local $/ = "__DATA__\n";
    while (<DATA>) {
        chomp;                                  # remove trailing __DATA__
        s/^#.*\n//mg;                           # remove comments
        s/\n+$//;                               # remove trailing newline
        s/\\x([0-9a-f]{2})/chr(hex($1))/gei;    # convert \xHH to character
        push @tests, $_
    }
};

plan tests => scalar @tests;

while (my $html = shift @tests) {
    my $expected = shift @tests;

    for my $character_semantics (0,1) {
        my $html_obj = Mail::SpamAssassin::HTML->new($character_semantics,1);
        $html_obj->parse($html);

        my $text = $html_obj->get_rendered_text();
        is($text, $expected, "character_semantics=$character_semantics");
    }



}


__DATA__
# Consecutive paragraphs should be separated by a single blank line
<p>A</p><p>B</p><p>

C

</p>
__DATA__
A

B

C
__DATA__
# Empty tags should collapse down to a single blank line (i.e. a paragraph separator)
# Whitespace is considered "empty"
C
<p> </p>
<p>


</p>
<p><span></span></p>
<div> <p> </p> </div>
D
__DATA__
C

D
__DATA__
# Breaks should be converted to newlines
# multiple breaks = multiple newlines
G<br>H <br/>
I<br><br><br>
J
__DATA__
G
H
I


J
__DATA__
# Consecutive table cells should be separated by a single space
# Consecutive table rows should be separated by a blank line
# Empty rows should be removed
K<table><tr><td>L</td><td>M</td></tr>
<tr> <td> </td> <td> </td> </tr>
<tr><td>N</td><td>O</td></tr></table>P
__DATA__
K

L M

N O

P
__DATA__
# Comments should have no effect
<p>
Q<!-- comment -->
R<!-- comment -->S <!-- comment --> T
</p>
__DATA__
Q RS T
__DATA__
# Non-breaking spaces are converted to spaces but without collapsing
U&nbsp;&nbsp;&nbsp;V
<p>&nbsp;</p>
<p>&nbsp;</p>
<p>&nbsp;</p>
W
__DATA__
U   V







W
__DATA__
# Breaks that precede a closing tag are removed
<p>X<br></p>
<table>
<tr>
    <td>
        Y<br>
    </td>
    <td>
        Z<br>
    </td>
</tr>
</table>
__DATA__
X

Y  Z
