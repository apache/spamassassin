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
use Test; BEGIN { plan tests => 69 };
use IO::File;

use strict;

# make a _copy_ of the STDERR file descriptor
# (so we can restore it after redirecting it)
open(OLDERR, ">&STDERR") || die "Cannot copy STDERR file handle";

# quiet "used only once" warnings
1 if *OLDERR;

my @data = (

# ---------------------------------------------------------------------------

# 127/8 implicitly trusted as default
q{

  Received: from sender.net (127.0.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Trusted: [ ip=127.0.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: 

},

# ---------------------------------------------------------------------------

# 127/8 explicitly trusted
q{

  trusted_networks 127/8
  Received: from sender.net (127.0.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Netset-Warn
Trusted: [ ip=127.0.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: 

},

# 127/8 explicitly trusted along with others
q{

  trusted_networks 127/8 1.2.2.1
  Received: from sender.net (127.0.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Netset-Warn
Trusted: [ ip=127.0.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: 

},

# ---------------------------------------------------------------------------

# 127/8 explicitly untrusted -- which is not possible to do
q{

  trusted_networks 1.2/16 !127/8
  internal_networks 1.2/16 !127/8
  Received: from sender.net (127.0.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Netset-Warn
Trusted: [ ip=127.0.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: 

},

# ---------------------------------------------------------------------------

# 127/8 implicitly trusted
q{

  trusted_networks 1.2/16
  Received: from sender.net (127.0.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Trusted: [ ip=127.0.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: 

},

# ---------------------------------------------------------------------------

# 10/8 implicitly trusted by auto-detection
# note: it should also be internal!
q{

  Received: from sender.net (10.0.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Trusted: [ ip=10.0.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: 

},

# ---------------------------------------------------------------------------

# trusted, then not (which is trusted, we do first match wins)
q{

  trusted_networks 1.2/16 !1.2/16
  Received: from sender.net (1.2.3.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Netset-Warn
Trusted: [ ip=1.2.3.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

q{

  trusted_networks 1.2/16
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Trusted:
Untrusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ]

},

# ---------------------------------------------------------------------------

q{

  trusted_networks 1.1/16
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

q{

  trusted_networks 1.1/16
  internal_networks 1.1/16
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
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

Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

q{

  trusted_networks 1.1/16 1.2/16
  internal_networks 1.2/16
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# this should be a lint error; internal_networks is not a subset of trusted.
# note: "intl=0" is expected; even though the internal_networks config is
# invalid it was still defined by the user, so we do not use trusted for internal
q{

  trusted_networks 1.1/16
  internal_networks 1.2.8/24
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Lint-Error
Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# this should be a lint error; internal_networks is not a subset of trusted.
# note: "intl=0" is expected; even though the internal_networks config is
# invalid it was still defined by the user, so we do not use trusted for internal
q{

  trusted_networks 1.1.1/24
  internal_networks 1.1/16
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Lint-Error
Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# this should be a lint error; internal_networks is not a subset of trusted.
# note: "intl=0" is expected; even though the internal_networks config is
# invalid it was still defined by the user, so we do not use trusted for internal
q{

  trusted_networks !1.1.1.1 1.1/16
  internal_networks 1.1.1.1
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Lint-Error
Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# this should be a lint error; you can't exclude a network after you've already
# included it (TODO: it is currently not a lint error, netset just warns about it)
q{

  trusted_networks 1/8 !1.1.1.2
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Netset-Warn
Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
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

Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# test msa_networks functionality, MSA trusted+internal
q{

  trusted_networks 1.1/16
  msa_networks 1.1.1.2
  Received: from sender.net (1.1.1.1) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000
  Received: from sender.net (5.5.5.5) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Trusted: [ ip=1.1.1.1 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ] [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=1 ] [ ip=5.5.5.5 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# test msa_networks functionality, MSA trusted
q{

  trusted_networks 1.1/16
  internal_networks !1.1.1.2 1.1/16
  msa_networks 1.1.1.2
  Received: from sender.net (1.1.1.1) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000
  Received: from sender.net (5.5.5.5) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Trusted: [ ip=1.1.1.1 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ] [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=1 ] [ ip=5.5.5.5 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# test msa_networks functionality, 5.5.5.5 outside of trust boundary
q{

  trusted_networks !1.1.1.2 1.1/16 5.5.5.5
  msa_networks 5.5.5.5
  Received: from sender.net (1.1.1.1) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000
  Received: from sender.net (5.5.5.5) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Trusted: [ ip=1.1.1.1 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ] [ ip=5.5.5.5 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ]

},

# ---------------------------------------------------------------------------

# test msa_networks functionality, 5.5.5.5 not trusted, so cannot be an MSA
q{

  trusted_networks 1.1/16
  msa_networks 5.5.5.5
  Received: from sender.net (1.1.1.1) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000
  Received: from sender.net (5.5.5.5) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Lint-Error
Trusted: [ ip=1.1.1.1 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ] [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: [ ip=5.5.5.5 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ]

},

# ---------------------------------------------------------------------------

# test to make sure netset is detecting overlap correctly when using short CIDR notations
q{

  trusted_networks 1/8 !1/8
  Received: from sender.net (1.1.1.1) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Netset-Warn
Trusted: [ ip=1.1.1.1 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# test to make sure netset is detecting overlap correctly when using short CIDR notations
q{

  trusted_networks !1/8 1/8
  Received: from sender.net (1.1.1.1) by receiver.net
              with SMTP; 10 Nov 2005 00:00:00 -0000

} => q{

Netset-Warn
Trusted:
Untrusted: [ ip=1.1.1.1 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ]

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
            "clear_internal_networks\n".
            "clear_msa_networks\n";

  if ($hdrs =~ s/^\s*(trusted_networks\s+[^\n]*)//gs) {
    $conf .= $1."\n";
  }
  if ($hdrs =~ s/^\s*(internal_networks\s+[^\n]*)//gs) {
    if ($1) { $conf .= $1."\n"; }
  }
  if ($hdrs =~ s/^\s*(msa_networks\s+[^\n]*)//gs) {
    if ($1) { $conf .= $1."\n"; }
  }

  tstprefs ($conf);

  my $netset_warn = 0;
  my $fh;
  if ($expected =~ s/^\s*Netset-Warn\s*//) {    
    # create a file descriptior for logging STDERR
    # (we do not want warnings for regexps we know are invalid)
    $fh = IO::File->new_tmpfile();
    open(STDERR, ">&".fileno($fh)) || die "Cannot create LOGERR temp file";
    $netset_warn = 1;
    print "[netset warning expected here...]\n";
  }

  my $sa = create_saobj({ userprefs_filename => "log/tst.cf" });
  ok($sa);

  $sa->{lint_callback} = sub {
    my %opts = @_;
    print "lint error: $opts{msg}\n";
  };

  if ($expected =~ s/^\s*Lint-Error\s*//) {
    print "[lint error expected here...]\n";
    ok ($sa->lint_rules() != 0) or $test_failure=1;
  } else {
    ok ($sa->lint_rules() == 0) or $test_failure=1;
  }

  my $msg = $hdrs."\n\n[no body]\n";
  $msg =~ s/^\s+Received: /Received: /gm;
  my $status = $sa->check_message_text ($msg);
  my $result = $status->rewrite_mail();

  # warn "JMD $result";

  if ($netset_warn) {
    open(STDERR, ">&=OLDERR") || die "Cannot reopen STDERR";

    seek($fh, 0, 0);
    my $error = do {
      local $/;
      <$fh>;
    };
    close $fh;

    $test_failure=1;
    for (split(/^/m, $error)) {
      if (/^netset: /) {
	$test_failure=0;
	print "netset warn: $_";
      } else {
	warn $_;
      }
    }
  }

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

    # die "dying on first test failure";
  }

  $status->finish();
  $sa->finish();
}

