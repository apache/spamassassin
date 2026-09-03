#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("uri_class");

use strict;
use warnings;
use Test::More;

use Mail::SpamAssassin::URI;

# ---------------------------------------------------------------------------
# Component splitting.  undef in an expectation means the component is absent;
# note that is not the same as '' (an empty path, or a "?" with nothing after).
my @split_tests = (
  { uri => 'https://example.com/a/b?x=1#frag',
    scheme => 'https', authority => 'example.com', host => 'example.com',
    path => '/a/b', query => 'x=1', fragment => 'frag' },
  { uri => 'http://example.com',
    scheme => 'http', authority => 'example.com', host => 'example.com',
    path => '', query => undef, fragment => undef },
  { uri => 'https://example.com/',
    scheme => 'https', authority => 'example.com', host => 'example.com',
    path => '/', query => undef, fragment => undef },
  { uri => 'https://user:pass@example.com:8080/p',
    scheme => 'https', authority => 'user:pass@example.com:8080',
    host => 'example.com', userinfo => 'user:pass', port => '8080',
    path => '/p' },
  # Scheme-relative and relative references still parse; they simply have no
  # scheme (and, for the relative one, no authority).
  { uri => '//example.com/a',
    scheme => undef, authority => 'example.com', host => 'example.com',
    path => '/a' },
  { uri => '/just/a/path',
    scheme => undef, authority => undef, host => undef, path => '/just/a/path' },
  { uri => '', scheme => undef, authority => undef, host => undef, path => '' },
  { uri => 'not a uri at all',
    scheme => undef, authority => undef, host => undef,
    path => 'not a uri at all' },
  # Scheme is case-insensitive and normalised; path case is preserved.
  { uri => 'HTTPS://Host.Example/FOO',
    scheme => 'https', host => 'host.example', path => '/FOO' },
  # An empty query is present-but-empty, distinct from having no query.
  { uri => 'https://example.com/a?',
    path => '/a', query => '' },
);

# Percent-decoding of the authority, and the boundary rule that goes with it.
my @decode_tests = (
  # %2E hides a dot inside the hostname; decoding reveals a real, resolvable
  # host, so this must be seen through.
  { uri => 'https://bar%2Eexample/tr/op', host => 'bar.example', path => '/tr/op' },
  # %2F does NOT re-split the authority into host + path.  The decoded host is
  # not resolvable, and this is what the CPAN URI module reports.
  { uri => 'https://foo.example%2Ftr%2Fop%2Fabc',
    host => 'foo.example/tr/op/abc', path => '' },
  # An encoded ? belongs to the path; it never starts a query string.
  { uri => 'https://h.com/a%3Fx=1', host => 'h.com',
    path => '/a?x=1', raw_path => '/a%3Fx=1', query => undef },
  # url_decode resolves double encoding in a single pass.
  { uri => 'https://h.com/?u=https%253A%252F%252Fevil.com%252Fp',
    host => 'h.com' },
  # An encoded separator is not distinguished from a real one by path(); a
  # caller that needs to tell them apart uses raw_path().
  { uri => 'https://h.com/tr%2Fop', path => '/tr/op', raw_path => '/tr%2Fop' },
  # A hostname has one identity however it is spelled, so an
  # internationalised name is folded to its ASCII form.
  { uri => 'https://xn--bcher-kva.de/x', host => 'xn--bcher-kva.de' },
  # Something that is not a hostname is left alone for the caller to judge.
  { uri => 'https://foo.example%2Fa%2Fb', host => 'foo.example/a/b' },
);

my @scheme_tests = (
  { uri => 'https://example.com/', is_http => 1 },
  { uri => 'http://example.com/',  is_http => 1 },
  { uri => 'HTTP://example.com/',  is_http => 1 },
  { uri => 'mailto:foo@bar.com',   is_http => 0 },
  { uri => 'tel:+15551234',        is_http => 0 },
  { uri => 'data:text/html;base64,AAAA', is_http => 0 },
  { uri => 'javascript:alert(1)',  is_http => 0 },
  { uri => '/relative',            is_http => 0 },
);

plan tests => 98;

for my $t (@split_tests, @decode_tests) {
  my $u = Mail::SpamAssassin::URI->new($t->{uri});
  for my $f (qw(scheme authority host userinfo port path raw_path query fragment)) {
    next unless exists $t->{$f};
    is($u->$f, $t->{$f}, "$t->{uri}: $f");
  }
}

for my $t (@scheme_tests) {
  my $u = Mail::SpamAssassin::URI->new($t->{uri});
  is($u->is_http ? 1 : 0, $t->{is_http}, "$t->{uri}: is_http");
}

# ---------------------------------------------------------------------------
# Query parameters.  The query is split while still encoded and each name and
# value decoded afterwards, so an encoded separator inside a value stays where
# it belongs.
{
  my $u = Mail::SpamAssassin::URI->new(
    'https://safe.example/?url=evil.com%2Fp%3Fx%3D1%26tid%3Dgood.com');
  is(scalar($u->params), 1, 'encoded %26 does not split the value');
  is($u->param('url'), 'evil.com/p?x=1&tid=good.com',
     'encoded separators stay inside the value');
}

{
  # Entity-encoded &amp; is a separator too; a bare-& split would leave "amp;b".
  my @p = Mail::SpamAssassin::URI->new('https://h.com/?a=1&amp;b=2')->params;
  is(scalar(@p), 2, '&amp; splits into two parameters');
  is($p[1]->{name}, 'b', '&amp; does not leave "amp;" on the next name');
}

{
  # A parameter with no "=" has no value at all, which is not the same as one
  # with an empty value; only the latter could ever hold a URI.
  my @p = Mail::SpamAssassin::URI->new('https://h.com/?flag&empty=&x=1')->params;
  is(scalar(@p), 3, 'three parameters');
  is($p[0]->{name}, 'flag', 'valueless parameter keeps its name');
  ok(!defined $p[0]->{value}, 'valueless parameter has an undef value');
  is($p[1]->{value}, '', 'empty value is empty, not undef');
}

{
  my @p = Mail::SpamAssassin::URI->new('https://h.com/?a=1&&b=2&')->params;
  is(scalar(@p), 2, 'empty pairs are skipped');
}

{
  # A repeated name is kept in full by params(); the hashref is lossy and
  # keeps the first, matching param() in scalar context.
  my $u = Mail::SpamAssassin::URI->new('https://h.com/?a=1&a=2&a=3');
  is(scalar($u->params), 3, 'repeated names are all kept');
  is(join(',', $u->param('a')), '1,2,3', 'param() in list context');
  is(scalar $u->param('a'), '1', 'param() in scalar context takes the first');
  is($u->param_hash->{a}, '1', 'param_hash keeps the first occurrence');
  ok(!defined $u->param('nosuch'), 'param() for a missing name is undef');
}

{
  my $u = Mail::SpamAssassin::URI->new('https://h.com/?v=a%2Bb+c&d=x;y');
  is($u->param('v'), 'a+b+c', '+ is not converted to a space');
  is($u->param('d'), 'x;y', '; does not separate parameters');
}

{
  my $u = Mail::SpamAssassin::URI->new('https://h.com/');
  is(scalar($u->params), 0, 'no query yields no parameters');
  is_deeply($u->param_hash, {}, 'no query yields an empty hash');
}

# ---------------------------------------------------------------------------
# The fragment is client-side only, so it is dropped from the form used to
# fetch, to key a cache, or to compare against a Location header.
{
  is(Mail::SpamAssassin::URI->new('https://h.com/a#frag')->without_fragment,
     'https://h.com/a', 'without_fragment drops the fragment');
  is(Mail::SpamAssassin::URI->new('https://h.com/a?x=1#f')->without_fragment,
     'https://h.com/a?x=1', 'without_fragment keeps the query');
  is(Mail::SpamAssassin::URI->new('https://h.com/a')->without_fragment,
     'https://h.com/a', 'without_fragment is a no-op without one');
  is(Mail::SpamAssassin::URI->new('https://h.com/a#')->without_fragment,
     'https://h.com/a', 'without_fragment drops an empty fragment');
}

# ---------------------------------------------------------------------------
# An object stands in for the string it was built from, so it can be passed to
# anything expecting one without the caller knowing which it holds.
{
  my $s = 'https://example.com/a?x=1';
  my $u = Mail::SpamAssassin::URI->new($s);
  is("$u", $s, 'interpolates as the original string');
  is($u . '', $s, 'concatenates as the original string');
  ok($u eq $s, 'compares equal to the original string');
  is((keys %{{ "$u" => 1 }})[0], $s, 'usable as a hash key');
  is(ref($u), 'Mail::SpamAssassin::URI', 'still an object');
  # With only '""' overloaded, bool would follow the string and an object
  # built from an empty URI would read as false.
  ok(Mail::SpamAssassin::URI->new(''), 'an object is true even when empty');
}

# ---------------------------------------------------------------------------
# The parser never rejects anything: every string yields an object, so callers
# ask a question they care about instead of testing for undef.
{
  ok(defined Mail::SpamAssassin::URI->new(''), 'empty string returns an object');
  ok(defined Mail::SpamAssassin::URI->new(undef), 'undef returns an object');
  my $big = 'https://h.com/' . ('a' x 20000) . '?x=' . ('b' x 20000);
  my $u = eval { Mail::SpamAssassin::URI->new($big) };
  ok(defined $u, 'a very long uri returns an object');
  is($u->host, 'h.com', 'a very long uri still parses its host');
}
