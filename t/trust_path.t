#!/usr/bin/perl

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_tests.t", kluge around ...
    chdir 't';
  }

  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib');
    unshift(@INC, '../lib');
  }
}

my $prefix = '.';
if (-e 'test_dir') {            # running from test directory, not ..
  $prefix = '..';
}

use lib '.'; use lib 't';
use SATest; sa_t_init("trust_path");


# TODO: 3.1.x does not support redefining the ruleset, which this
# test requires; therefore disable it.
#
#use Test; BEGIN { plan tests => 24 };
use Test; BEGIN { plan tests => 0 }; exit;


use strict;

my @data = (

# ---------------------------------------------------------------------------

q{

  trusted_networks 1.1/16
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= ]
Untrusted:

},

# ---------------------------------------------------------------------------

q{

  trusted_networks 1.1/16
  internal_networks 1.1/16
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= ]
Untrusted:

},

# ---------------------------------------------------------------------------

# with an unset trusted_networks, internal_networks is documented to
# be used instead
q{

  internal_networks 1.1/16
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= ]
Untrusted:

},

# ---------------------------------------------------------------------------

q{

  trusted_networks 1.1/16 1.2/16
  internal_networks 1.2/16
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= ]
Untrusted:

},

# ---------------------------------------------------------------------------

# this should be a lint error; internal_networks is not a subset of trusted.
# note: "intl=1" in expected, because the error means that the internal_networks
# line is ignored and the default setting is intl==trusted.
q{

  trusted_networks 1.1/16
  internal_networks 1.2.8/24
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Lint-Error
Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= ]
Untrusted:

},

# ---------------------------------------------------------------------------

# this should be a lint error; internal_networks is not a subset of trusted.
q{

  trusted_networks 1.1.1/24
  internal_networks 1.1/16
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Lint-Error
Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= ]
Untrusted:

},

# ---------------------------------------------------------------------------

# this should be a lint error; internal_networks is not a subset of trusted.
# note: "intl=1" in expected, because the error means that the internal_networks
# line is ignored and the default setting is intl==trusted.
q{

  trusted_networks !1.1.1.1 1.1/16
  internal_networks 1.1.1.1
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Lint-Error
Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= ]
Untrusted:

},

# ---------------------------------------------------------------------------

# internal_networks are valid, even if the !4.3.2.1 is pointless
q{

  trusted_networks 1.1/16
  internal_networks !4.3.2.1 1.1/16
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= ]
Untrusted:

},

# ---------------------------------------------------------------------------

);


while (1) {
  my $hdrs = shift @data;
  my $expected = shift @data;
  last unless defined $expected;

  my $test_failure = 0;

  my $conf = "add_header all Untrusted _RELAYSUNTRUSTED_\n".
            "add_header all Trusted _RELAYSTRUSTED_\n".
            "clear_trusted_networks\n".
            "clear_internal_networks\n";

  $hdrs =~ s/^\s*(trusted_networks\s+[^\n]*)//gs;
  if ($1) { $conf .= $1."\n"; }
  $hdrs =~ s/^\s*(internal_networks\s+[^\n]*)//gs;
  if ($1) { $conf .= $1."\n"; }

  tstprefs ($conf);

  my $sa = create_saobj({ userprefs_filename => "log/tst.cf" });
  ok($sa);

  $sa->{lint_callback} = sub {
    my %opts = @_;
    print "lint warning: $opts{msg}\n";
  };

  if ($expected =~ s/^\s*Lint-Error\s*//) {
    print "[lint warning expected here...]\n";
    ok ($sa->lint_rules() != 0) or $test_failure=1;
  } else {
    ok ($sa->lint_rules() == 0) or $test_failure=1;
  }

  my $msg = $hdrs."\n\n[no body]\n";
  $msg =~ s/^\s+//gs;
  my $status = $sa->check_message_text ($msg);
  my $result = $status->rewrite_mail();

  # warn "JMD $result";
  $result =~ s/\n[ \t]+/ /gs;
  $result =~ /(?:\n|^)X-Spam-Trusted: ([^\n]*)\n/s;
  my $relays_t = $1;
  $result =~ /(?:\n|^)X-Spam-Untrusted: ([^\n]*)\n/s;
  my $relays_u = $1;

  my $relays = "Trusted: $relays_t Untrusted: $relays_u";
  $relays =~ s/\s+/ /gs; $expected =~ s/\s+/ /gs;
  $relays =~ s/^ //gs; $expected =~ s/^ //gs;
  $relays =~ s/ $//gs; $expected =~ s/ $//gs;

  ok ($relays eq $expected) or $test_failure = 1;

  if ($test_failure) {
    print "conf: ", ('-' x 67), "\n", $conf;
    print "hdr sample: ", ('-' x 67), $hdrs, ('-' x 78), "\n\n";
    print "expected: $expected\n";
    print "got     : $relays\n\n";

    die "dying on first test failure";
  }

  $status->finish();
  $sa->finish();
}

