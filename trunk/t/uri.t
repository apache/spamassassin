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
use Test;
use SATest; sa_t_init("uri");

use Mail::SpamAssassin;
use Mail::SpamAssassin::HTML;
use Mail::SpamAssassin::Util;

plan tests => 89;

##############################################

# initialize SpamAssassin
my $sa = create_saobj({'dont_copy_prefs' => 1});

$sa->init(0); # parse rules

open (IN, "<data/spam/009");
my $mail = $sa->parse(\*IN);
close IN;
my $msg = Mail::SpamAssassin::PerMsgStatus->new($sa, $mail);

my @uris = $msg->get_uri_list();
print "got URIs: ".join (", ", @uris)."\n";
ok (@uris >= 5);
my %urimap = map { $_ => 1 } @uris;
ok ($urimap{'http://62.16.101.59/livesex.htm'});
ok ($urimap{'http://66.92.69.221/'});
ok ($urimap{'http://66.92.69.222/'});
ok ($urimap{'http://66.92.69.223/'});
ok ($urimap{'http://66.92.69.224/'});
ok ($urimap{'spamassassin.org'});
ok (!$urimap{'CUMSLUTS.'});
ok (!$urimap{'CUMSLUTS..VIRGIN'});

##############################################

sub try_domains {
  my($try, $expect) = @_;
  my $result = Mail::SpamAssassin::Util::uri_to_domain($try);

  # undef is valid in some situations, so deal with it...
  if (!defined $expect) {
    return !defined $result;
  }
  elsif (!defined $result) {
    return 0;
  }

  if ($expect eq $result) {
    return 1;
  } else {
    warn "try_domains: failed! expect: '$expect' got: '$result'\n";
    return 0;
  }
}

ok(try_domains('javascript:{some crap}', undef));
ok(try_domains('mailto:nobody@example.com', 'example.com'));
ok(try_domains('http://66.92.69.221/', '66.92.69.221'));
ok(try_domains('http://www.spamassassin.org:8080/lists.html', 'spamassassin.org'));
ok(try_domains('http://www.spamassassin.org/lists.html#some_tag', 'spamassassin.org'));
ok(try_domains('http://username@www.spamassassin.org/lists.html', 'spamassassin.org'));
ok(try_domains('http://username:password@www.spamassassin.org/lists.html', 'spamassassin.org'));
ok(try_domains('http:/%77%77%77.spamassassin.org/lists.html', undef));
ok(try_domains('http:/www.spamassassin.org/lists.html', 'spamassassin.org'));
ok(try_domains('http:www.spamassassin.org/lists.html', 'spamassassin.org'));
ok(try_domains('http://kung.pao.com.cn', 'pao.com.cn'));
ok(try_domains('kung.pao.com.cn', 'pao.com.cn'));
ok(try_domains('kung-pao.com.cn', 'kung-pao.com.cn'));
ok(try_domains('username:password@www.spamassassin.org/lists.html', 'spamassassin.org'));
ok(try_domains('spamassassin.org', 'spamassassin.org'));
ok(try_domains('SPAMASSASSIN.ORG', 'spamassassin.org'));
ok(try_domains('WWW.SPAMASSASSIN.ORG', 'spamassassin.org'));
ok(try_domains('spamassassin.txt', undef));
ok(try_domains('longer.url.but.not.spamassassin.txt', undef));
ok(try_domains('http://ebg&vosxfov.com.munged-rxspecials.net/b/Tr3f0amG','munged-rxspecials.net'));
ok(try_domains('http://blah.blah.com:/', 'blah.com'));
ok(try_domains('http://example.com.%20.host.example.info/', 'example.info'));

##############################################

sub array_cmp {
  my($a, $b) = @_;
  return 0 if (@{$a} != @{$b});
  for(my $i = 0; $i<@{$a}; $i++) {
    return 0 if ($a->[$i] ne $b->[$i]);
  }
  return 1;
}

sub try_canon {
  my($input, $expect) = @_;
  my $redirs = $sa->{conf}->{redirector_patterns};
  my @input = sort { $a cmp $b } Mail::SpamAssassin::Util::uri_list_canonify($redirs, @{$input});
  my @expect = sort { $a cmp $b } @{$expect};

  # output what we want/get for debugging
  my $res = array_cmp(\@input, \@expect);
  if (!$res) {
    warn ">> expect: [ @expect ]\n>> got: [ @input ]\n";
  }
  return $res;
}

# We should get the raw versions and a single "correct" version
ok(try_canon([
   'http:www.spamassassin.org',
   'http:/www.spamassassin.org',
   "ht\rtp:/\r/www.exa\rmple.com",
   ], [
   'http://www.spamassassin.org',
   'http:www.spamassassin.org',
   'http:/www.spamassassin.org',
   'http://www.example.com',
   ]));

# Try a simple redirector.  Should return the redirector and the URI
# that is pointed to.
ok(try_canon(['http://rd.yahoo.com/?http:/www.spamassassin.org'],
   [
   'http://rd.yahoo.com/?http:/www.spamassassin.org',
   'http://www.spamassassin.org',
   'http:/www.spamassassin.org',
   ]));

ok(try_canon(['http://images.google.ca/imgres?imgurl=gmib.free.fr/viagra.jpg&imgrefurl=http://www.google.com/url?q=http://www.google.com/url?q=%68%74%74%70%3A%2F%2F%77%77%77%2E%65%78%70%61%67%65%2E%63%6F%6D%2F%6D%61%6E%67%65%72%33%32'],

   [
   'http://images.google.ca/imgres?imgurl=gmib.free.fr/viagra.jpg&imgrefurl=http://www.google.com/url?q=http://www.google.com/url?q=%68%74%74%70%3A%2F%2F%77%77%77%2E%65%78%70%61%67%65%2E%63%6F%6D%2F%6D%61%6E%67%65%72%33%32',
   'http://images.google.ca/imgres?imgurl=gmib.free.fr/viagra.jpg&imgrefurl=http://www.google.com/url?q=http://www.google.com/url?q=http://www.expage.com/manger32',
   'http://www.expage.com/manger32',
   'http://www.google.com/url?q=http://www.expage.com/manger32',
   'http://www.google.com/url?q=http://www.google.com/url?q=http://www.expage.com/manger32',
   ]));

# redirector_pattern test
ok(try_canon(['http://chkpt.zdnet.com/chkpt/baz/jmason.org'],
   [
   'http://chkpt.zdnet.com/chkpt/baz/jmason.org',
   'http://jmason.org',
   'jmason.org',
   ]));

ok(try_canon(['http://emf0.com/r.cfm?foo=bar&r=jmason.org'],
   [
   'http://emf0.com/r.cfm?foo=bar&r=jmason.org',
   'http://jmason.org',
   'jmason.org',
   ]));

ok(try_canon(["ht\rtp\r://www.kl\nuge.n\net/"],
  ['http://www.kluge.net/']
  ));

ok(try_canon(['http:\\\\people.apache.org\\~felicity\\'],
  ['http:\\\\people.apache.org\\~felicity\\',
  'http://people.apache.org/~felicity/']
  ));

ok(try_canon([
   'http%3A//ebg&vosxfov.com%2Emunged-%72xspecials%2Enet/b/Tr3f0amG'
   ], [
   'http%3A//ebg&vosxfov.com%2Emunged-%72xspecials%2Enet/b/Tr3f0amG',
   'http://ebg&vosxfov.com.munged-rxspecials.net/b/Tr3f0amG'
   ]));

ok(try_canon([
   'http://www.nate.com/r/DM03/n%65verp4%79re%74%61%69%6c%2eco%6d/%62%61m/?m%61%6e=%6Di%634%39'
   ], [
   'http://www.nate.com/r/DM03/n%65verp4%79re%74%61%69%6c%2eco%6d/%62%61m/?m%61%6e=%6Di%634%39',
   'http://www.nate.com/r/DM03/neverp4yretail.com/bam/?man=mic49',
   'http://neverp4yretail.com/bam/?man=mic49',
   'neverp4yretail.com/bam/?man=mic49',
   ]));

ok(try_canon([
   'http://www.google.com/pagead/iclk?sa=l&ai=Br3ycNQz5Q-fXBJGSiQLU0eDSAueHkArnhtWZAu-FmQWgjlkQAxgFKAg4AEDKEUiFOVD-4r2f-P____8BoAGyqor_A8gBAZUCCapCCqkCxU7NLQH0sz4&num=5&adurl=http://1092229727:9999/https-www.paypal.com/webscrr/index.php'
   ], [
   'http://1092229727:9999/https-www.paypal.com/webscrr/index.php',
   'http://65.26.26.95:9999/https-www.paypal.com/webscrr/index.php',
   'http://www.google.com/pagead/iclk?sa=l&ai=Br3ycNQz5Q-fXBJGSiQLU0eDSAueHkArnhtWZAu-FmQWgjlkQAxgFKAg4AEDKEUiFOVD-4r2f-P____8BoAGyqor_A8gBAZUCCapCCqkCxU7NLQH0sz4&num=5&adurl=http://1092229727:9999/https-www.paypal.com/webscrr/index.php',
   ]));

ok(try_canon([
   'http://www.google.com/pagead/iclk?sa=l&ai=Br3ycNQz5Q-fXBJGSiQLU0eDSAueHkArnhtWZAu-FmQWgjlkQAxgFKAg4AEDKEUiFOVD-4r2f-P____8BoAGyqor_A8gBAZUCCapCCqkCxU7NLQH0sz4&num=5&adurl=http://1092229727:/https-www.paypal.com/webscrr/index.php'
   ], [
   'http://1092229727:/https-www.paypal.com/webscrr/index.php',
   'http://65.26.26.95:/https-www.paypal.com/webscrr/index.php',
   'http://www.google.com/pagead/iclk?sa=l&ai=Br3ycNQz5Q-fXBJGSiQLU0eDSAueHkArnhtWZAu-FmQWgjlkQAxgFKAg4AEDKEUiFOVD-4r2f-P____8BoAGyqor_A8gBAZUCCapCCqkCxU7NLQH0sz4&num=5&adurl=http://1092229727:/https-www.paypal.com/webscrr/index.php',
   ]));

ok(try_canon([
   'http://89.0x00000000000000000000068.0000000000000000000000160.0x00000000000011'
   ], [
   'http://89.0x00000000000000000000068.0000000000000000000000160.0x00000000000011',
   'http://89.104.112.17',
   ]));

ok(try_canon([
   'http://0x000000059.104.00000000000160.0x00011'
   ], [
   'http://0x000000059.104.00000000000160.0x00011',
   'http://89.104.112.17',
   ]));

ok(try_canon([
   'http://0xdd.0x6.0xf.0x8a/ws/eBayISAPI.dll',
   ], [
   'http://0xdd.0x6.0xf.0x8a/ws/eBayISAPI.dll',
   'http://221.6.15.138/ws/eBayISAPI.dll',
   ]));

ok(try_canon([
   'http://089.104.0160.0x11',
   ], [
   'http://089.104.0160.0x11',
   'http://89.104.112.17',
   ]));

ok(try_canon([
   'http://0x7f000001',
   ], [
   'http://0x7f000001',
   'http://127.0.0.1',
   ]));


##############################################

sub try {
  my ($base, $uri, $want) = @_;

  my $target = Mail::SpamAssassin::HTML::target_uri($base, $uri);

  if ($target ne $want) {
    print "URI mismatch: $base and $uri -> $target but wanted $want\n";
    return 0;
  }
  return 1;
}

my $base = 'http://a/b/c/d;p?q';

# tests from RFC 2396 draft
# http://www.gbiv.com/protocols/uri/rev-2002/rfc2396bis.html
ok(try($base, "g:h", "g:h"));
ok(try($base, "g", "http://a/b/c/g"));
ok(try($base, "./g", "http://a/b/c/g"));
ok(try($base, "g/", "http://a/b/c/g/"));
ok(try($base, "/g", "http://a/g"));
ok(try($base, "//g", "http://g"));
ok(try($base, "?y", "http://a/b/c/d;p?y"));
ok(try($base, "g?y", "http://a/b/c/g?y"));
ok(try($base, "#s", "http://a/b/c/d;p?q#s"));
ok(try($base, "g#s", "http://a/b/c/g#s"));
ok(try($base, "g?y#s", "http://a/b/c/g?y#s"));
ok(try($base, ";x", "http://a/b/c/;x"));
ok(try($base, "g;x", "http://a/b/c/g;x"));
ok(try($base, "g;x?y#s", "http://a/b/c/g;x?y#s"));
ok(try($base, ".", "http://a/b/c/"));
ok(try($base, "./", "http://a/b/c/"));
ok(try($base, "..", "http://a/b/"));
ok(try($base, "../", "http://a/b/"));
ok(try($base, "../g", "http://a/b/g"));
ok(try($base, "../..", "http://a/"));
ok(try($base, "../../", "http://a/"));
ok(try($base, "../../g", "http://a/g"));

ok(try($base, "", "http://a/b/c/d;p?q"));
ok(try($base, "../../../g", "http://a/g"));
ok(try($base, "../../../../g", "http://a/g"));
ok(try($base, "/./g", "http://a/g"));
ok(try($base, "/../g", "http://a/g"));
ok(try($base, "g.", "http://a/b/c/g."));
ok(try($base, ".g", "http://a/b/c/.g"));
ok(try($base, "g..", "http://a/b/c/g.."));
ok(try($base, "..g", "http://a/b/c/..g"));
ok(try($base, "./../g", "http://a/b/g"));
ok(try($base, "./g/.", "http://a/b/c/g/"));
ok(try($base, "g/./h", "http://a/b/c/g/h"));
ok(try($base, "g/../h", "http://a/b/c/h"));
ok(try($base, "g;x=1/./y", "http://a/b/c/g;x=1/y"));
ok(try($base, "g;x=1/../y", "http://a/b/c/y"));
ok(try($base, "g?y/./x", "http://a/b/c/g?y/./x"));
ok(try($base, "g?y/../x", "http://a/b/c/g?y/../x"));
ok(try($base, "g#s/./x", "http://a/b/c/g#s/./x"));
ok(try($base, "g#s/../x", "http://a/b/c/g#s/../x"));
ok(try($base, "http:g", "http://a/b/c/g"));

