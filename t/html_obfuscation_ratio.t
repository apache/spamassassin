#!/usr/bin/perl -T
use strict;
use warnings;
use lib '.'; use lib 't';
use lib 'lib';
use Mail::SpamAssassin::HTML;
use Test::More;

# Bug 8404: the obfuscation counter (HTML.pm html_text) increments when the
# tail of one text node and the head of the next are both "word" characters,
# meaning a word looks split across a tag (V<b></b>iagra).  The synthetic
# marker bytes the parser inserts for whitespace/breaks -- \x00 (block break)
# and \xa0 (NBSP, incl. the <br>-before-closing-block rewrite) -- are not \s,
# so they used to read as word chars and made ordinary block breaks and NBSP
# separated runs look obfuscated (HTML_OBFUSCATE_* false positives).

# triples of (label, HTML, expected obfuscation count)
my @tests = (

    '<br> counts as whitespace -- no obfuscation',
    'Foo<br>bar',
    0,

    'Block elements count as whitespace -- no obfuscation',
    '<div dir="auto">Bonjour Salomon</div><div dir="auto">Je reviens vers vous</div><div dir="auto">La vente</div>',
    0,

    '<br> immediately before a closing block -- no obfuscation',
    '<div>alpha<br></div><div>bravo<br></div><div>charlie</div>',
    0,

    'Bare NBSP (\xa0) at the end of a text block -- no obfuscation',
    "foo\xa0<b>bar</b>",
    0,

    'Bare NBSP (\xa0) at the beginning of a text block -- no obfuscation',
    "foo<b>\xa0bar</b>",
    0,

    'A run starting with UTF-8 NBSP (\xc2\xa0) -- no obfuscation',
    "word<b>\xc2\xa0next</b>",
    0,

    'A run ending with UTF-8 NBSP (\xc2\xa0) -- no obfuscation',
    "word\xc2\xa0<b>next</b>",
    0,

    'Genuine mid-word split -- obfuscation',
    "Vi<b>a</b>gra",
    2,

    # \xa0 is also the trailing byte of many UTF-8 letters; a genuine split
    # right after one must still count, i.e. the NBSP exclusion must not swallow
    # these letter tails.  Two shapes: a 2-byte char whose lead byte precedes
    # the \xa0 (à=\xc3\xa0), and a 3-byte char whose continuation byte does
    # (CJK U+4E20=\xe4\xb8\xa0).
    'Split after 2-byte UTF-8 letter ending in \xa0 (à) -- obfuscation',
    "voil\xc3\xa0<b>x</b>",
    1,

    'Split after 3-byte CJK char ending in \xa0 -- obfuscation',
    "\xe4\xb8\xa0<b>x</b>",
    1,

);

plan tests => scalar(@tests) / 3 * 2;   # (@tests/3) cases x 2 semantics modes

while (@tests) {
    my $label = shift @tests;
    my $html     = shift @tests;
    my $expected = shift @tests;

    for my $character_semantics (0,1) {
        my $obj = Mail::SpamAssassin::HTML->new($character_semantics, 1);
        $obj->parse($html);
        is($obj->{obfuscation} || 0, $expected,
           "[char_semantics=$character_semantics] $label");
    }
}
